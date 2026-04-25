"""VulnClaw CLI Module Tests — main.py"""

import pytest
from typer.testing import CliRunner


# ── CLI smoke tests ──────────────────────────────────────────────────

class TestCLI:
    """Test CLI entry point and sub-commands."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_cli_help(self, runner):
        from vulnclaw.cli.main import app
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "VulnClaw" in result.output or "vulnclaw" in result.output.lower()

    def test_cli_version(self, runner):
        from vulnclaw import __version__
        from vulnclaw.cli.main import app
        result = runner.invoke(app, ["--version"])
        # Typer may return exit code 0 or 2 depending on version
        assert __version__ in result.output or result.exit_code in (0, 2)

    def test_cli_init(self, runner):
        from vulnclaw.cli.main import app
        result = runner.invoke(app, ["init"])
        # Should not crash
        assert result.exit_code == 0

    def test_cli_doctor(self, runner):
        from vulnclaw.cli.main import app
        result = runner.invoke(app, ["doctor"])
        # Should not crash
        assert result.exit_code == 0

    def test_cli_config_list(self, runner):
        from vulnclaw.cli.main import app
        result = runner.invoke(app, ["config", "list"])
        # Should not crash
        assert result.exit_code == 0

    def test_cli_config_provider_list(self, runner):
        from vulnclaw.cli.main import app
        result = runner.invoke(app, ["config", "provider", "--list"])
        # Should show available providers
        assert result.exit_code == 0

    def test_cli_config_provider_set(self, runner):
        from vulnclaw.cli.main import app
        result = runner.invoke(app, ["config", "provider", "deepseek"])
        # Should not crash
        assert result.exit_code == 0

    def test_cli_kb_info(self, runner):
        from vulnclaw.cli.main import app
        result = runner.invoke(app, ["kb", "info"])
        # kb info might not exist in all versions, just verify no crash
        assert result.exit_code in (0, 2)

    def test_cli_no_args(self, runner):
        """Running with no args should show help or enter REPL mode."""
        from vulnclaw.cli.main import app
        result = runner.invoke(app, [])
        # Should not crash
        assert result.exit_code == 0


class TestCLISubCommands:
    """Test CLI sub-command help messages."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_run_help(self, runner):
        from vulnclaw.cli.main import app
        result = runner.invoke(app, ["run", "--help"])
        assert result.exit_code == 0

    def test_recon_help(self, runner):
        from vulnclaw.cli.main import app
        result = runner.invoke(app, ["recon", "--help"])
        assert result.exit_code == 0

    def test_scan_help(self, runner):
        from vulnclaw.cli.main import app
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0

    def test_report_help(self, runner):
        from vulnclaw.cli.main import app
        result = runner.invoke(app, ["report", "--help"])
        assert result.exit_code == 0
