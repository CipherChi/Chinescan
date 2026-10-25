from typer.testing import CliRunner

from chinescan.cli.app import app

runner = CliRunner()


def test_help_and_version() -> None:
    assert runner.invoke(app, ["--help"]).exit_code == 0
    assert runner.invoke(app, ["version"]).stdout.strip() == "0.1.0"


def test_config_init_and_validate(tmp_path) -> None:
    path = tmp_path / "config.toml"
    assert runner.invoke(app, ["config", "init", "--path", str(path)]).exit_code == 0
    assert runner.invoke(app, ["config", "validate", "--path", str(path)]).exit_code == 0


def test_future_phase_command_is_stub() -> None:
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 2
    assert "Phase 3" in result.stderr
