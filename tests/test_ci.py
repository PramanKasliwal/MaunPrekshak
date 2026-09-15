"""CI exit codes must follow finding severity, independently of aggregate risk score."""

import pytest
from typer.testing import CliRunner

from maunprekshak.cli.main import app


@pytest.mark.parametrize(
    ("source", "threshold", "expected_exit", "severity"),
    [
        ("requests.get(url, verify=False)\n", "high", 1, "HIGH"),
        ("eval(user_input)\n", "critical", 1, "CRITICAL"),
        ("requests.get(url, verify=False)\n", "critical", 0, "HIGH"),
        ("DEBUG = True\n", "high", 0, "MEDIUM"),
    ],
)
def test_ci_fails_on_single_finding_at_threshold(tmp_path, source, threshold, expected_exit, severity):
    """One qualifying finding must fail CI even when its risk score is low."""
    (tmp_path / "app.py").write_text(source)
    result = CliRunner().invoke(
        app,
        ["scan", str(tmp_path), "--only", "sast", "--no-ai", "--ci", "--fail-on", threshold, "--output", "json"],
    )
    assert result.exit_code == expected_exit
    assert f'"severity": "{severity}"' in result.stdout
    if expected_exit:
        assert "CI Check Failed: 1 finding(s)" in result.stdout
        assert '"score": 5' in result.stdout or '"score": 10' in result.stdout


def test_ci_uses_findings_after_rule_exclusions(tmp_path):
    """Ignoring a SAST rule must also remove it from the CI gate."""
    (tmp_path / "app.py").write_text("requests.get(url, verify=False)\n")
    (tmp_path / ".maunprekshak.toml").write_text('[scanner]\nignore_rules = ["MP015"]\n')
    result = CliRunner().invoke(
        app,
        ["scan", str(tmp_path), "--only", "sast", "--no-ai", "--ci", "--fail-on", "high", "--output", "json"],
    )
    assert result.exit_code == 0
    assert '"total": 0' in result.stdout
