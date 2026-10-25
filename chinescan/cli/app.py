"""Typer application entry point."""

import typer

from chinescan.cli import commands

app = typer.Typer(help="Authorization-first security investigation platform.")
app.command("version")(commands.version)
app.add_typer(commands.config_app, name="config")


@app.command("scan")
def scan_stub() -> None:
    """Run a scan (Phase 3)."""
    commands.not_implemented(3, "scan")


@app.command("report")
def report_stub() -> None:
    """Generate a report (Phase 5)."""
    commands.not_implemented(5, "report")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
