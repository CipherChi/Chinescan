"""User-facing CLI commands."""

from pathlib import Path

import typer

from chinescan import __version__
from chinescan.core.config.io import init_config, validate_config
from chinescan.core.errors import ConfigurationError


def version() -> None:
    typer.echo(__version__)


config_app = typer.Typer(help="Initialize and validate local configuration.")


@config_app.command("init")
def config_init(
    path: Path | None = typer.Option(  # noqa: B008
        None, "--path", help="Configuration file path."
    ),
) -> None:
    try:
        created = init_config(path)
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=exc.exit_code) from exc
    typer.echo(f"Created configuration: {created}")


@config_app.command("validate")
def config_validate(
    path: Path = typer.Option(  # noqa: B008
        ..., "--path", help="Configuration file path."
    ),
) -> None:
    try:
        validate_config(path)
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=exc.exit_code) from exc
    typer.echo("Configuration is valid.")


def not_implemented(phase: int, command: str) -> None:
    typer.echo(f"{command} is planned for Phase {phase} and is not implemented.", err=True)
    raise typer.Exit(code=2)
