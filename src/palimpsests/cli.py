"""Command-line interface — a thin typer shell over ``core``.

Deliberately thin: every command resolves app state and delegates to a
``core`` function. All orchestration (registry, audit, context fitting)
lives in ``core`` so it is testable without going through argument
parsing, and so a downstream embedder can call the same functions
without a terminal.

Commands:
    palimpsests models              list models on the active engine
    palimpsests engine list         show known engines + active marker
    palimpsests engine use <id>     switch the active engine
    palimpsests chat <model>        one-shot chat (prompt via -m/stdin)
    palimpsests audit verify        check the audit log's hash chain
    palimpsests pala verify <file>  verify a PALA-1 stream (experimental)
"""
from __future__ import annotations

import json
import struct
import sys
import typer
from dataclasses import asdict
from palimpsests.audit import AuditIntegrityError
from palimpsests.audit.pala import (
    MalformedRecord,
    body_digest_of,
    iter_records,
    verify_headers,
)
from palimpsests.core import (
    AUDIT_DB_NAME,
    AppContext,
    chat,
    default_config_dir,
    init_app,
    list_engines,
    list_models,
    open_audit_log,
    select_engine,
)
from palimpsests.providers import EngineError
from pathlib import Path

app = typer.Typer(
    name="palimpsests",
    help="A layered local-LLM inference engine.",
    no_args_is_help=True,
    add_completion=False,
)

engine_app = typer.Typer(help="Inspect and switch inference engines.", no_args_is_help=True)
app.add_typer(engine_app, name="engine")

audit_app = typer.Typer(help="Inspect and verify the audit log.", no_args_is_help=True)
app.add_typer(audit_app, name="audit")

pala_app = typer.Typer(
    help="Work with PALA-1 audit streams (experimental; the spec is a draft).",
    no_args_is_help=True,
)
app.add_typer(pala_app, name="pala")


def _ctx() -> AppContext:
    """Build the app context, turning engine errors into clean exits."""
    return init_app()


# ─── models ──────────────────────────────────────────────────────────────


@app.command("models")
def models_cmd() -> None:
    """List models available on the active engine."""
    ctx = _ctx()
    try:
        models = list_models(ctx)
    except EngineError as e:
        typer.secho(f"error: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e

    if not models:
        typer.echo("no models found on the active engine")
        return
    for m in models:
        size = f"{m.size_bytes / 1e9:.1f} GB" if m.size_bytes else "?"
        quant = m.quant or "?"
        typer.echo(f"{m.name}\t{size}\t{quant}")


# ─── engine ──────────────────────────────────────────────────────────────


@engine_app.command("list")
def engine_list_cmd() -> None:
    """Show known engines, their control level, and which is active."""
    ctx = _ctx()
    for engine_id, level, installed, active in list_engines(ctx):
        marker = "*" if active else " "
        state = "installed" if installed else "not installed"
        typer.echo(f"{marker} {engine_id}\tL{level}\t{state}")


@engine_app.command("use")
def engine_use_cmd(engine_id: str) -> None:
    """Switch the active engine."""
    ctx = _ctx()
    try:
        select_engine(ctx, engine_id)
    except KeyError as e:
        typer.secho(
            f"error: unknown engine {engine_id!r}", fg=typer.colors.RED, err=True
        )
        raise typer.Exit(code=1) from e
    typer.secho(f"active engine is now {engine_id!r}", fg=typer.colors.GREEN)


# ─── audit ───────────────────────────────────────────────────────────────

# Exit codes are the contract for cron and CI, so they distinguish the
# three outcomes an operator must be able to act on differently. In
# particular a chain that verifies *without* its head anchor is not the
# same fact as a fully-verified one: wholesale replacement of the log
# would not have been detected, and reporting that as success would be
# the same silent over-claim the anchor exists to prevent.
EXIT_VERIFIED = 0
EXIT_TAMPERED = 1
EXIT_PARTIAL = 2
EXIT_UNREADABLE = 3


@audit_app.command("verify")
def audit_verify_cmd(
    json_out: bool = typer.Option(
        False, "--json", help="Emit the verification result as JSON."
    ),
    require_anchor: bool = typer.Option(
        False,
        "--require-anchor",
        help="Treat a missing head anchor as a failure rather than a partial pass.",
    ),
) -> None:
    """Verify the audit log's hash chain, and its head against the anchor.

    Read-only: verification never writes to the log or moves the anchor.

    Exit codes:

    \b
      0  verified   — chain intact and head matches the stored anchor
      1  TAMPERED   — a row was altered, deleted, reordered, or the whole
                      history was replaced
      2  PARTIAL    — chain intact, but no head anchor was available, so
                      wholesale replacement would not have been detected
                      (use --require-anchor to treat this as failure)
      3  UNREADABLE — the log could not be opened in a trustworthy state
    """
    cfg = default_config_dir()
    db = cfg / AUDIT_DB_NAME
    if not db.exists():
        _fail(json_out, EXIT_UNREADABLE, f"no audit log at {db}")

    try:
        log = open_audit_log(cfg)
    except AuditIntegrityError as e:
        _fail(json_out, EXIT_UNREADABLE, str(e))

    try:
        result = log.verify()
    finally:
        # close() anchors only rows this process wrote; we wrote none, so
        # the anchor is left exactly as we found it.
        log.close()

    if not result.ok:
        code = EXIT_TAMPERED
    elif not result.head_anchored:
        code = EXIT_TAMPERED if require_anchor else EXIT_PARTIAL
    else:
        code = EXIT_VERIFIED

    if json_out:
        payload = asdict(result) | {"exit_code": code}
        typer.echo(json.dumps(payload, indent=2))
        raise typer.Exit(code=code)

    if code == EXIT_VERIFIED:
        typer.secho(
            f"verified: {result.rows_checked} rows, chain intact, "
            "head matches the stored anchor",
            fg=typer.colors.GREEN,
        )
    elif code == EXIT_PARTIAL:
        typer.secho(
            f"PARTIAL: {result.rows_checked} rows, chain intact — "
            "but no head anchor was available, so wholesale replacement "
            "of the log would not have been detected",
            fg=typer.colors.YELLOW,
            err=True,
        )
    else:
        where = (
            f" (first bad row: {result.first_bad_row})"
            if result.first_bad_row is not None
            else ""
        )
        typer.secho(
            f"TAMPERED: {result.reason}{where}",
            fg=typer.colors.RED,
            err=True,
        )
    raise typer.Exit(code=code)


def _fail(json_out: bool, code: int, message: str) -> None:
    """Report a fatal condition in the requested format and exit."""
    if json_out:
        typer.echo(json.dumps({"ok": False, "reason": message, "exit_code": code}))
    else:
        typer.secho(f"error: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code=code)



# ─── pala (experimental) ─────────────────────────────────────────────────

# WITNESS is read from the frozen header fields directly (§7.6): a stream
# may carry record versions this build cannot fully interpret, and those
# must still be walked and reported, not rejected — so the scan below must
# not go through ``Header.decode``, which claims full interpretation.
_RT_WITNESS = 0x0051


@pala_app.command("verify")
def pala_verify_cmd(
    file: str = typer.Argument(
        ..., help="A PALA-1 file container: records concatenated back-to-back (§2.4)."
    ),
    anchor: str = typer.Option(
        None,
        "--anchor",
        help=(
            "Expected chain head, 64 hex chars, obtained OUTSIDE the file — "
            "an anchor store, or the head covered by the newest witness "
            "receipt. Without it, completeness (tail truncation, wholesale "
            "replacement) is NOT checked."
        ),
    ),
    json_out: bool = typer.Option(
        False, "--json", help="Emit the verification result as JSON."
    ),
) -> None:
    """Verify a PALA-1 stream — the three questions, answered separately.

    Read-only and header-only: no decryption key is needed or used.
    Encrypted bodies are checked against the digest bound into their
    header, never opened.

    \b
      consistency  — do the records chain, with no gaps, no violated
                     MUSTs, and every body matching its header digest?
      completeness — does the chain head match the anchor you supplied?
      witness      — which records claim external witness receipts?
                     (verifying a receipt follows the witness's own
                     protocol — Rekor proof, RFC 3161 — not this tool)

    Exit codes (the same contract as `palimpsests audit verify`):

    \b
      0  verified   — chain intact and head matches --anchor
      1  TAMPERED   — a break, gap, violated MUST, body-digest mismatch,
                      malformed container, or an anchor mismatch
      2  PARTIAL    — chain intact, but no --anchor was supplied, so
                      truncation or replacement would not have been
                      detected
      3  UNREADABLE — the file could not be read, or --anchor is invalid
    """
    expected: bytes | None = None
    if anchor is not None:
        try:
            expected = bytes.fromhex(anchor)
        except ValueError:
            _fail(json_out, EXIT_UNREADABLE, "--anchor is not valid hex")
        if len(expected) != 32:
            _fail(json_out, EXIT_UNREADABLE, "--anchor must be 32 bytes (64 hex chars)")

    path = Path(file)
    try:
        data = path.read_bytes()
    except OSError as e:
        _fail(json_out, EXIT_UNREADABLE, f"cannot read {path}: {e}")

    headers: list[bytes] = []
    body_mismatches: list[int] = []
    witness_seqs: list[int] = []
    malformed: str | None = None
    try:
        for hb, body in iter_records(data):
            headers.append(hb)
            (rtype,) = struct.unpack_from("<H", hb, 8)
            (seq,) = struct.unpack_from("<Q", hb, 12)
            if rtype == _RT_WITNESS:
                witness_seqs.append(seq)
            if body and body_digest_of(body) != hb[124:156]:
                body_mismatches.append(seq)
    except MalformedRecord as e:
        # A container defect (§2.4): boundaries cannot be trusted past this
        # point. Everything walked before it is still verified below.
        malformed = str(e)

    result = verify_headers(headers, expected_head=expected)

    consistent = result.chain_ok and not body_mismatches and malformed is None
    if not consistent:
        code = EXIT_TAMPERED
    elif expected is not None and not result.complete_to_anchor:
        code = EXIT_TAMPERED
    elif expected is None:
        code = EXIT_PARTIAL
    else:
        code = EXIT_VERIFIED

    if json_out:
        payload = {
            "file": str(path),
            "records": result.count,
            "head": result.head.hex(),
            "consistency": {
                "ok": consistent,
                "breaks": result.breaks,
                "gaps": result.gaps,
                "violations": result.violations,
                "body_digest_mismatches": body_mismatches,
                "uninterpretable": result.uninterpretable,
                "malformed_container": malformed,
            },
            "completeness": {
                "checked": expected is not None,
                "ok": result.complete_to_anchor,
                "anchor_lag": result.anchor_lag,
                "reason": result.anchor_reason,
            },
            "witness": {
                "records": witness_seqs,
                "note": "receipts are not verified by this tool",
            },
            "exit_code": code,
        }
        typer.echo(json.dumps(payload, indent=2))
        raise typer.Exit(code=code)

    if consistent:
        extra = (
            f", {len(result.uninterpretable)} uninterpretable record(s) "
            "(chain-checked, not rejected)"
            if result.uninterpretable
            else ""
        )
        typer.secho(
            f"consistency: {result.count} records, chain intact{extra}",
            fg=typer.colors.GREEN,
        )
    else:
        parts: list[str] = []
        if malformed:
            parts.append(f"malformed container: {malformed}")
        if result.breaks:
            parts.append(f"chain breaks at seq {result.breaks}")
        if result.gaps:
            parts.append(f"sequence gaps at seq {result.gaps}")
        if result.violations:
            parts.append(f"violated MUSTs: {result.violations}")
        if body_mismatches:
            parts.append(f"body digest mismatch at seq {body_mismatches}")
        typer.secho(
            "consistency: BROKEN — " + "; ".join(parts),
            fg=typer.colors.RED,
            err=True,
        )

    if expected is None:
        typer.secho(
            "completeness: NOT CHECKED — no --anchor supplied, so tail "
            "truncation or wholesale replacement would not have been detected",
            fg=typer.colors.YELLOW,
            err=True,
        )
    elif result.complete_to_anchor:
        typer.secho(
            "completeness: chain head matches the supplied anchor",
            fg=typer.colors.GREEN,
        )
    else:
        typer.secho(
            f"completeness: FAILED — {result.anchor_reason}",
            fg=typer.colors.RED,
            err=True,
        )

    if witness_seqs:
        typer.echo(
            f"witness: {len(witness_seqs)} WITNESS record(s) at seq "
            f"{witness_seqs} — receipts are not verified by this tool"
        )
    else:
        typer.echo(
            "witness: no WITNESS records — existence at a point in time "
            "is not attested"
        )

    raise typer.Exit(code=code)


# ─── chat ────────────────────────────────────────────────────────────────


@app.command("chat")
def chat_cmd(
    model: str = typer.Argument(..., help="Model name, e.g. qwen2.5:7b"),
    message: str = typer.Option(
        None, "--message", "-m", help="Prompt text (or piped via stdin)"
    ),
    context_size: int = typer.Option(
        8192, "--context-size", "-c", help="Token budget for context fitting"
    ),
) -> None:
    """Send one prompt to a model and stream the reply.

    The prompt comes from -m/--message, or from stdin if piped. Output
    streams token by token to stdout.
    """
    ctx = _ctx()

    if message is None:
        if sys.stdin.isatty():
            typer.secho(
                "error: no prompt; pass -m or pipe text via stdin",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(code=1)
        message = sys.stdin.read()

    messages = [{"role": "user", "content": message}]
    try:
        for chunk in chat(
            ctx, model=model, messages=messages, context_size=context_size
        ):
            typer.echo(chunk.delta, nl=False)
    except EngineError as e:
        typer.secho(f"\nerror: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from e
    typer.echo("")  # trailing newline after the stream


def main() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":
    main()
