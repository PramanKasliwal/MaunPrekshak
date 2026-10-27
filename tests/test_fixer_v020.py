"""
Tests for MaunPrekshak Core v0.20.0 — Mechanical Auto-Fixing Suite (TF019, TF020, DF016, MP090).
"""
import os
import tempfile
from maunprekshak.scanner.report import SASTFinding, Severity
from maunprekshak.scanner.fixer import fix_file_findings


def test_fix_tf019_cloudfront_viewer_protocol():
    content = """resource "aws_cloudfront_distribution" "s3_distribution" {
  default_cache_behavior {
    viewer_protocol_policy = "allow-all"
  }
}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = [
            SASTFinding(
                file_path=path, line=3, col=1, check_id="TF019",
                severity=Severity.HIGH.value, description="", recommendation="", code_snippet="",
            )
        ]
        applied = fix_file_findings(path, findings)
        assert applied == 1
        with open(path, "r") as f:
            fixed = f.read()
        assert 'viewer_protocol_policy = "redirect-to-https"' in fixed
    finally:
        os.unlink(path)


def test_fix_tf020_opensearch_encryption():
    content = """resource "aws_opensearch_domain" "example" {
  encrypt_at_rest {
    enabled = false
  }
}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = [
            SASTFinding(
                file_path=path, line=3, col=1, check_id="TF020",
                severity=Severity.HIGH.value, description="", recommendation="", code_snippet="",
            )
        ]
        applied = fix_file_findings(path, findings)
        assert applied == 1
        with open(path, "r") as f:
            fixed = f.read()
        assert "enabled = true" in fixed
    finally:
        os.unlink(path)


def test_fix_df016_pip_no_cache_dir():
    content = """FROM python:3.12-slim
USER appuser
RUN pip install flask requests
"""
    with tempfile.NamedTemporaryFile("w", suffix=".Dockerfile", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = [
            SASTFinding(
                file_path=path, line=3, col=1, check_id="DF016",
                severity=Severity.MEDIUM.value, description="", recommendation="", code_snippet="",
            )
        ]
        applied = fix_file_findings(path, findings)
        assert applied == 1
        with open(path, "r") as f:
            fixed = f.read()
        assert "pip install --no-cache-dir flask requests" in fixed
    finally:
        os.unlink(path)


def test_fix_mp090_tls_minimum_version():
    content = """import ssl

context = ssl.create_default_context()
context.minimum_version = ssl.TLSVersion.TLSv1_1
"""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = [
            SASTFinding(
                file_path=path, line=4, col=1, check_id="MP090",
                severity=Severity.HIGH.value, description="", recommendation="", code_snippet="",
            )
        ]
        applied = fix_file_findings(path, findings)
        assert applied == 1
        with open(path, "r") as f:
            fixed = f.read()
        assert "context.minimum_version = ssl.TLSVersion.TLSv1_2" in fixed
    finally:
        os.unlink(path)
