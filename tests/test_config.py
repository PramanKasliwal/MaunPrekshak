"""
Unit tests for configuration loading and .maunprekshak.toml parsing.
"""
import tempfile
from pathlib import Path
import pytest
from maunprekshak.config import load_config, ScannerConfig, DEFAULT_CONFIG_TEMPLATE

try:
    import tomllib
except ImportError:
    try:
        import toml as tomllib
    except ImportError:
        tomllib = None


def test_default_config():
    """Test default scanner configuration when no config file is present."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = load_config(tmpdir)
        assert isinstance(cfg, ScannerConfig)
        assert "tests" in cfg.exclude
        assert cfg.fail_on == "critical"
        assert cfg.no_ai is False
        assert cfg.ignore_rules == []


def test_load_from_maunprekshak_toml():
    """Test loading configuration from .maunprekshak.toml."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / ".maunprekshak.toml"
        config_path.write_text(
            """
[scanner]
exclude = ["custom_dir", "legacy"]
fail_on = "high"
no_ai = true
ignore_rules = ["MP010", "MP005"]
"""
        )

        cfg = load_config(tmpdir)
        assert cfg.exclude == ["custom_dir", "legacy"]
        assert cfg.fail_on == "high"
        assert cfg.no_ai is True
        assert cfg.ignore_rules == ["MP010", "MP005"]


def test_load_from_pyproject_toml():
    """Test loading configuration from pyproject.toml [tool.maunprekshak]."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pyproject_path = Path(tmpdir) / "pyproject.toml"
        pyproject_path.write_text(
            """
[tool.maunprekshak]
exclude = ["vendor"]
fail_on = "medium"
no_ai = true
ignore_rules = ["MP001"]
"""
        )

        cfg = load_config(tmpdir)
        assert cfg.exclude == ["vendor"]
        assert cfg.fail_on == "medium"
        assert cfg.no_ai is True
        assert cfg.ignore_rules == ["MP001"]


def test_load_ai_config():
    """Test loading [ai] section from .maunprekshak.toml."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / ".maunprekshak.toml"
        config_path.write_text(
            """
[scanner]
fail_on = "high"

[ai]
provider = "openai"
model = "gpt-4o"
base_url = "https://custom.ai.gateway/v1"
"""
        )

        cfg = load_config(tmpdir)
        assert cfg.ai_provider == "openai"
        assert cfg.ai_model == "gpt-4o"
        assert cfg.ai_base_url == "https://custom.ai.gateway/v1"


def test_default_template_is_valid_toml():
    """Test that DEFAULT_CONFIG_TEMPLATE is syntactically valid TOML."""
    if tomllib is not None:
        data = tomllib.loads(DEFAULT_CONFIG_TEMPLATE)
        assert "scanner" in data
        assert "exclude" in data["scanner"]
        assert "fail_on" in data["scanner"]


# ─── CLI and Git Staged/Diff Tests ──────────────────────────────────────────

from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
from maunprekshak.cli.main import app, get_git_staged_files, get_git_diff_files

cli_runner = CliRunner()


def test_cli_version_command():
    result = cli_runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "MaunPrekshak" in result.stdout


def test_get_git_staged_files(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout="app.py\nconfig.toml\n",
            returncode=0,
        )
        files = get_git_staged_files(str(tmp_path))
        assert len(files) == 2
        assert any("app.py" in f for f in files)


def test_get_git_diff_files(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout="main.py\n",
            returncode=0,
        )
        files = get_git_diff_files(str(tmp_path), ref="HEAD~1")
        assert len(files) == 1
        assert any("main.py" in f for f in files)


def test_scan_staged_empty(tmp_path):
    with patch("maunprekshak.cli.main.get_git_staged_files", return_value=[]):
        result = cli_runner.invoke(app, ["scan", str(tmp_path), "--staged", "--no-ai"])
        assert result.exit_code == 0
        assert "Nothing to scan" in result.stdout or "No staged files" in result.stdout


def test_scan_staged_with_files(tmp_path):
    safe_file = tmp_path / "safe.py"
    safe_file.write_text("x = 1\n")

    with patch("maunprekshak.cli.main.get_git_staged_files", return_value=[str(safe_file)]):
        result = cli_runner.invoke(app, ["scan", str(tmp_path), "--staged", "--no-ai", "--output", "json"])
        assert result.exit_code == 0
        assert '"total": 0' in result.stdout


def test_scan_diff_with_files(tmp_path):
    safe_file = tmp_path / "safe.py"
    safe_file.write_text("x = 1\n")

    with patch("maunprekshak.cli.main.get_git_diff_files", return_value=[str(safe_file)]):
        result = cli_runner.invoke(app, ["scan", str(tmp_path), "--diff", "HEAD", "--no-ai", "--output", "json"])
        assert result.exit_code == 0
        assert '"total": 0' in result.stdout


def test_python_m_maunprekshak_module_execution():
    import sys
    import subprocess
    res = subprocess.run(
        [sys.executable, "-m", "maunprekshak", "version"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "MaunPrekshak" in res.stdout

