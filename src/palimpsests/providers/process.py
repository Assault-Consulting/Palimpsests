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
import socket
import subprocess
import time
from palimpsests.providers.errors import EngineUnavailable
from pathlib import Path


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

    @property
    def base_url(self) -> str:
        return f"http://{self._host}:{self._port}"

    @property
    def port(self) -> int:
        return self._port

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
        try:
            self._proc = subprocess.Popen(
                self.build_argv(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError as e:
            raise EngineUnavailable(
                f"llama-server binary not found: {self._binary!r}"
            ) from e

        self._wait_until_ready()

    def _wait_until_ready(self) -> None:
        """Poll the health endpoint until the server answers or we give up."""
        deadline = time.monotonic() + self._readiness_timeout
        health = f"{self.base_url}/health"
        while time.monotonic() < deadline:
            # If the process already exited, don't keep polling a corpse.
            if self._proc is not None and self._proc.poll() is not None:
                code = self._proc.returncode
                raise EngineUnavailable(
                    f"llama-server exited during startup (code {code})"
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

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def stop(self) -> None:
        """Terminate the server, escalating to kill, and reap it.

        Idempotent: safe to call whether or not the process is running,
        and safe to call twice (the second call is a no-op).
        """
        proc = self._proc
        if proc is None:
            return
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5.0)
        self._proc = None
