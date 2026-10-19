import tempfile
import os
from maunprekshak.scanner.report import SASTFinding, Severity
from maunprekshak.scanner.fixer import fix_file_findings


def test_fix_tf011_cloudtrail_logging():
    content = """resource "aws_cloudtrail" "trail" {
  name           = "audit-trail"
  enable_logging = false
}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = [
            SASTFinding(
                file_path=path, line=3, col=1, check_id="TF011",
                severity=Severity.HIGH.value, description="", recommendation="", code_snippet="",
            )
        ]
        applied = fix_file_findings(path, findings)
        assert applied == 1
        with open(path, "r") as f:
            fixed = f.read()
        assert "enable_logging = true" in fixed
    finally:
        os.unlink(path)


def test_fix_df011_chmod_permissive():
    content = """FROM python:3.11-slim
USER appuser
RUN chmod 777 /app/data
"""
    with tempfile.NamedTemporaryFile("w", suffix="Dockerfile", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = [
            SASTFinding(
                file_path=path, line=3, col=1, check_id="DF011",
                severity=Severity.HIGH.value, description="", recommendation="", code_snippet="",
            )
        ]
        applied = fix_file_findings(path, findings)
        assert applied == 1
        with open(path, "r") as f:
            fixed = f.read()
        assert "RUN chmod 755 /app/data" in fixed
    finally:
        os.unlink(path)


def test_fix_mp076_weak_key_generation():
    content = """import paramiko
key = paramiko.RSAKey.generate(1024)
"""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = [
            SASTFinding(
                file_path=path, line=2, col=1, check_id="MP076",
                severity=Severity.HIGH.value, description="", recommendation="", code_snippet="",
            )
        ]
        applied = fix_file_findings(path, findings)
        assert applied == 1
        with open(path, "r") as f:
            fixed = f.read()
        assert "generate(2048)" in fixed
    finally:
        os.unlink(path)


def test_fix_mp077_disabled_check_hostname():
    content = """import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
"""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = [
            SASTFinding(
                file_path=path, line=3, col=1, check_id="MP077",
                severity=Severity.HIGH.value, description="", recommendation="", code_snippet="",
            )
        ]
        applied = fix_file_findings(path, findings)
        assert applied == 1
        with open(path, "r") as f:
            fixed = f.read()
        assert "ctx.check_hostname = True" in fixed
    finally:
        os.unlink(path)
