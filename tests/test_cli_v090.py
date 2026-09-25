"""
Tests for v0.9.0 CLI options: --rules-file, --history, --commits, and --output html
"""
import secrets
from typer.testing import CliRunner
from maunprekshak.cli.main import app


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "0.10.1" in result.stdout


def test_cli_output_html(tmp_path):
    (tmp_path / "main.py").write_text("print('hello world')\n")
    html_file = tmp_path / "report.html"

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--no-ai", "--output", "html", "--output-file", str(html_file)],
    )
    assert result.exit_code == 0
    assert html_file.exists()
    content = html_file.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "मौन प्रेक्षक — MaunPrekshak" in content


def test_cli_custom_rules_file(tmp_path):
    dyn_token = f"acme_corp_{secrets.token_hex(16)}"
    (tmp_path / "app.py").write_text(f'KEY = "{dyn_token}"\n')

    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text("""
custom_rules:
  secrets:
    - id: "ACME-001"
      name: "Acme Key"
      regex: "acme_corp_[0-9a-f]{32}"
      severity: "high"
""")

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--no-ai",
            "--rules-file",
            str(rules_file),
            "--output",
            "json",
        ],
    )
    assert result.exit_code == 0
    assert "ACME-001" in result.stdout


def test_cli_exclude_trailing_slash_and_dot_slash(tmp_path):
    sub = tmp_path / "legacy"
    sub.mkdir()
    (sub / "vuln.py").write_text("eval('1+1')\n")
    (tmp_path / "safe.py").write_text("print('safe')\n")

    runner = CliRunner()
    # Test trailing slash
    res1 = runner.invoke(app, ["scan", str(tmp_path), "--exclude", "legacy/", "--no-ai", "--output", "json"])
    assert res1.exit_code == 0
    assert "MP001" not in res1.stdout

    # Test leading ./ and trailing /
    res2 = runner.invoke(app, ["scan", str(tmp_path), "--exclude", "./legacy/", "--no-ai", "--output", "json"])
    assert res2.exit_code == 0
    assert "MP001" not in res2.stdout


def test_cli_exclude_multiple_flags_and_comma_separated(tmp_path):
    sub1 = tmp_path / "dir1"
    sub2 = tmp_path / "dir2"
    sub1.mkdir()
    sub2.mkdir()
    (sub1 / "a.py").write_text("eval('1')\n")
    (sub2 / "b.py").write_text("eval('2')\n")

    runner = CliRunner()
    # Multiple --exclude flags
    res = runner.invoke(app, ["scan", str(tmp_path), "--exclude", "dir1", "--exclude", "dir2", "--no-ai", "--output", "json"])
    assert res.exit_code == 0
    assert "MP001" not in res.stdout

    # Comma-separated
    res2 = runner.invoke(app, ["scan", str(tmp_path), "--exclude", "dir1,dir2", "--no-ai", "--output", "json"])
    assert res2.exit_code == 0
    assert "MP001" not in res2.stdout

