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
"""
from __future__ import annotations

import sys
import typer
from palimpsests.core import (
    AppContext,
    chat,
    init_app,
    list_engines,
    list_models,
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
