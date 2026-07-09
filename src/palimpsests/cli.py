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
"""
from __future__ import annotations

import json
import sys
import typer
from dataclasses import asdict
from palimpsests.audit import AuditIntegrityError
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
