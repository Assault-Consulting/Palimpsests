# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Subprocess lifecycle for a managed llama-server.

Level 2 owns the process. That is what makes it a *control* level rather
than another thin wrapper: we spawn ``llama-server`` ourselves with the
launch flags that ``EngineMemoryConfig`` translates to, so KV-cache
quantization, flash attention, and GPU offload are actually applied by
*our* process, not by whatever the user happened to start.

This module is deliberately scoped to llama-server, not a generic
"managed subprocess engine" base class. The reusable ``ProcessManager``
abstraction is a level-3 concern — when the native server arrives we'll
have two concrete lifecycles to compare and can extract the commonality
then (extract-on-second-use), rather than guessing the shape now against
a single case.

What it handles — the fiddly, OS-specific parts that break in the
details rather than the logic:

- spawning with a built argument vector,
- allocating a free localhost port,
- waiting for readiness by polling the health endpoint,
- surfacing an early process death as a clear error (not a hang),
- graceful shutdown (terminate, then kill) with orphan cleanup.
"""
from __future__ import annotations

import httpx
import logging
import os
import secrets
import socket
import subprocess
import tempfile
import time
from palimpsests.providers.errors import EngineUnavailable
from pathlib import Path

logger = logging.getLogger("palimpsests.providers.process")


def find_free_port() -> int:
    """Return a currently-free localhost TCP port.

    Binds to port 0 (the OS picks a free one), reads it back, and closes.
    There's an inherent race — the port could be taken between here and
    the server binding it — but for a locally-spawned child that we start
    immediately after, it's the standard pragmatic approach.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class LlamaServerProcess:
    """Owns one ``llama-server`` child process.

    Constructed with a fully-built argument vector (the adapter decides
    what those are; this class does not know about EngineMemoryConfig).
    ``start`` spawns and blocks until the server answers its health
    endpoint or the readiness deadline passes; ``stop`` shuts it down.
    """

    def __init__(
        self,
        *,
        binary: str,
        model_path: str,
        host: str = "127.0.0.1",
        port: int | None = None,
        extra_args: list[str] | None = None,
        readiness_timeout: float = 60.0,
    ) -> None:
        self._binary = binary
        self._model_path = model_path
        self._host = host
        self._port = port or find_free_port()
        self._extra_args = list(extra_args or [])
        self._readiness_timeout = readiness_timeout
        self._proc: subprocess.Popen | None = None
        self._stderr_file: object | None = None  # tempfile handle while running
        # A fresh key per launch, so the managed server answers only us.
        # Passed through the child's environment (LLAMA_API_KEY, which
        # llama-server reads for --api-key), never on its command line:
        # /proc/<pid>/cmdline is readable by every local user, and a key
        # visible to any process would defend against none of them.
        self._api_key = secrets.token_urlsafe(32)
        #: True once the server refused a request without the key; False if
        #: it answered one (a build that does not read LLAMA_API_KEY); None
        #: before start or if the check could not be made.
        self.auth_enforced: bool | None = None

    @property
    def base_url(self) -> str:
        return f"http://{self._host}:{self._port}"

    @property
    def port(self) -> int:
        return self._port

    @property
    def api_key(self) -> str:
        """The key this launch requires; send it as ``Authorization: Bearer``."""
        return self._api_key

    def build_argv(self) -> list[str]:
        """The full command line, for spawning and for tests.

        Kept pure and separate from ``start`` so the argument vector can
        be asserted on without launching anything.
        """
        argv = [
            self._binary,
            "--model",
            self._model_path,
            "--host",
            self._host,
            "--port",
            str(self._port),
        ]
        argv.extend(self._extra_args)
        return argv

    def start(self) -> None:
        """Spawn the server and block until it is ready.

        Raises ``EngineUnavailable`` if the binary is missing, the
        process dies during startup, or readiness isn't reached before
        the timeout — all of which are "the backend isn't usable"
        conditions the caller handles the same way.
        """
        if not Path(self._model_path).exists():
            raise EngineUnavailable(
                f"model file not found: {self._model_path}"
            )
        # stdout is discarded; stderr goes to an unbuffered temp file.
        # PIPE without a reader would deadlock: llama-server logs freely,
        # and once the ~64 KiB pipe buffer fills the child blocks on write
        # and the server silently hangs. A file has no such limit, and its
        # tail is exactly what we want in the error message when startup
        # fails.
        self._stderr_file = tempfile.TemporaryFile(prefix="llama-server-err-")
        try:
            self._proc = subprocess.Popen(
                self.build_argv(),
                stdout=subprocess.DEVNULL,
                stderr=self._stderr_file,
                env={**os.environ, "LLAMA_API_KEY": self._api_key},
            )
        except FileNotFoundError as e:
            self._close_stderr_file()
            raise EngineUnavailable(
                f"llama-server binary not found: {self._binary!r}"
            ) from e

        self._wait_until_ready()
        self._check_auth()

    def _check_auth(self) -> None:
        """Confirm the server refuses a request that does not carry the key.

        ``/health`` is public in llama-server, so readiness says nothing
        about authentication; ``/v1/models`` is not. A 401/403 without the
        key means the key is enforced. A 200 means this build did not read
        ``LLAMA_API_KEY`` — older ones do not — and any local process can
        use the server, as before; that is logged loudly rather than
        refused, so an older binary keeps working with the risk named.
        """
        try:
            resp = httpx.get(f"{self.base_url}/v1/models", timeout=2.0)
        except httpx.HTTPError:
            return
        if resp.status_code in (401, 403):
            self.auth_enforced = True
        elif resp.status_code == 200:
            self.auth_enforced = False
            logger.warning(
                "llama-server at %s answered without its API key: this build does "
                "not read LLAMA_API_KEY, so any local process can use it (the "
                "level-2 exposure in SECURITY.md). A newer llama-server enforces it.",
                self.base_url,
            )

    def _wait_until_ready(self) -> None:
        """Poll the health endpoint until the server answers or we give up."""
        deadline = time.monotonic() + self._readiness_timeout
        health = f"{self.base_url}/health"
        while time.monotonic() < deadline:
            # If the process already exited, don't keep polling a corpse.
            if self._proc is not None and self._proc.poll() is not None:
                code = self._proc.returncode
                tail = self._stderr_tail()
                self._close_stderr_file()
                detail = f": {tail}" if tail else ""
                raise EngineUnavailable(
                    f"llama-server exited during startup (code {code}){detail}"
                )
            try:
                resp = httpx.get(health, timeout=1.0)
                if resp.status_code == 200:
                    return
            except httpx.HTTPError:
                pass  # not up yet
            time.sleep(0.25)
        self.stop()
        raise EngineUnavailable(
            f"llama-server not ready within {self._readiness_timeout}s"
        )

    def _stderr_tail(self, max_bytes: int = 2048) -> str:
        """The last ``max_bytes`` of the child's stderr, for diagnostics."""
        f = self._stderr_file
        if f is None:
            return ""
        try:
            f.flush()
            size = f.seek(0, os.SEEK_END)
            f.seek(max(0, size - max_bytes))
            return f.read().decode("utf-8", errors="replace").strip()
        except (OSError, ValueError):
            return ""

    def _close_stderr_file(self) -> None:
        f = self._stderr_file
        self._stderr_file = None
        if f is not None:
            try:
                f.close()
            except OSError:
                pass

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def stop(self) -> None:
        """Terminate the server, escalating to kill, and reap it.

        Idempotent: safe to call whether or not the process is running,
        and safe to call twice (the second call is a no-op).
        """
        proc = self._proc
        if proc is None:
            self._close_stderr_file()
            return
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5.0)
        self._proc = None
        self._close_stderr_file()
