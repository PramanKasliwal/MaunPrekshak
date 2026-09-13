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


def test_default_template_is_valid_toml():
    """Test that DEFAULT_CONFIG_TEMPLATE is syntactically valid TOML."""
    if tomllib is not None:
        data = tomllib.loads(DEFAULT_CONFIG_TEMPLATE)
        assert "scanner" in data
        assert "exclude" in data["scanner"]
        assert "fail_on" in data["scanner"]
