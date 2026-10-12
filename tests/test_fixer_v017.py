"""
Tests for MaunPrekshak Core v0.17.0 — Mechanical Auto-Fixing Engine Phase 6.
Tests DF006 (ADD -> COPY), MP069 (autoescape=False -> True), MP073 (host 0.0.0.0 -> 127.0.0.1), TF009 (bucket_key_enabled).
"""
import pytest
from maunprekshak.scanner.fixer import fix_file_findings
from maunprekshak.scanner.report import SASTFinding, Severity


def test_fix_df006_add_to_copy(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("""FROM python:3.11-slim
ADD src/ /app/
USER appuser
""")
    finding = SASTFinding(
        file_path=str(dockerfile),
        line=2,
        col=1,
        check_id="DF006",
        severity=Severity.MEDIUM.value,
        description="ADD used instead of COPY",
        recommendation="Use COPY",
        code_snippet="ADD src/ /app/",
    )
    applied = fix_file_findings(str(dockerfile), [finding])
    assert applied == 1
    content = dockerfile.read_text()
    assert "COPY src/ /app/" in content
    assert "ADD " not in content


def test_fix_mp069_autoescape_false(tmp_path):
    app_file = tmp_path / "app.py"
    app_file.write_text("""import jinja2
env = jinja2.Environment(autoescape=False)
""")
    finding = SASTFinding(
        file_path=str(app_file),
        line=2,
        col=1,
        check_id="MP069",
        severity=Severity.HIGH.value,
        description="Jinja2 autoescape disabled",
        recommendation="Enable autoescape",
        code_snippet="env = jinja2.Environment(autoescape=False)",
    )
    applied = fix_file_findings(str(app_file), [finding])
    assert applied == 1
    content = app_file.read_text()
    assert "autoescape=True" in content
    assert "autoescape=False" not in content


def test_fix_mp073_flask_host(tmp_path):
    flask_file = tmp_path / "server.py"
    flask_file.write_text("""from flask import Flask
app = Flask(__name__)
app.run(host="0.0.0.0", debug=True)
""")
    finding = SASTFinding(
        file_path=str(flask_file),
        line=3,
        col=1,
        check_id="MP073",
        severity=Severity.MEDIUM.value,
        description="Flask debugger on 0.0.0.0",
        recommendation="Bind localhost",
        code_snippet='app.run(host="0.0.0.0", debug=True)',
    )
    applied = fix_file_findings(str(flask_file), [finding])
    assert applied == 1
    content = flask_file.read_text()
    assert 'host="127.0.0.1"' in content
    assert "0.0.0.0" not in content


def test_fix_tf009_bucket_key_enabled(tmp_path):
    tf_file = tmp_path / "s3.tf"
    tf_file.write_text("""resource "aws_s3_bucket_server_side_encryption_configuration" "b" {
  bucket = "my-bucket"
  rule {
    bucket_key_enabled = false
  }
}
""")
    finding = SASTFinding(
        file_path=str(tf_file),
        line=4,
        col=1,
        check_id="TF009",
        severity=Severity.HIGH.value,
        description="Bucket key disabled",
        recommendation="Enable bucket key",
        code_snippet="bucket_key_enabled = false",
    )
    applied = fix_file_findings(str(tf_file), [finding])
    assert applied == 1
    content = tf_file.read_text()
    assert "bucket_key_enabled = true" in content
    assert "bucket_key_enabled = false" not in content
