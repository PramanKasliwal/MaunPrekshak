"""
Tests for MaunPrekshak Core v0.22.0 — Mechanical Auto-Fixing Suite (TF028, TF029, DF019, MP099, MP100).
"""
import os
import tempfile
from maunprekshak.scanner.report import SASTFinding, Severity
from maunprekshak.scanner.fixer import fix_file_findings


def test_fix_tf028_ecr_scan_on_push():
    content = """resource "aws_ecr_repository" "repo" {
  image_scanning_configuration {
    scan_on_push = false
  }
}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = [
            SASTFinding(
                file_path=path, line=3, col=1, check_id="TF028",
                severity=Severity.HIGH.value, description="", recommendation="", code_snippet="",
            )
        ]
        applied = fix_file_findings(path, findings)
        assert applied == 1
        with open(path, "r") as f:
            fixed = f.read()
        assert "scan_on_push = true" in fixed
    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_fix_tf029_redshift_encrypted():
    content = """resource "aws_redshift_cluster" "dw" {
  encrypted = false
}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = [
            SASTFinding(
                file_path=path, line=2, col=1, check_id="TF029",
                severity=Severity.HIGH.value, description="", recommendation="", code_snippet="",
            )
        ]
        applied = fix_file_findings(path, findings)
        assert applied == 1
        with open(path, "r") as f:
            fixed = f.read()
        assert "encrypted = true" in fixed
    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_fix_df019_apt_get_no_install_recommends():
    content = """FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl
"""
    with tempfile.NamedTemporaryFile("w", suffix=".Dockerfile", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = [
            SASTFinding(
                file_path=path, line=2, col=1, check_id="DF019",
                severity=Severity.MEDIUM.value, description="", recommendation="", code_snippet="",
            )
        ]
        applied = fix_file_findings(path, findings)
        assert applied == 1
        with open(path, "r") as f:
            fixed = f.read()
        assert "apt-get install --no-install-recommends -y curl" in fixed
    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_fix_mp099_rsa_public_exponent():
    content = """key1 = rsa.generate_private_key(public_exponent=3, key_size=2048)
key2 = RSA.generate(2048, e=3)
"""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = [
            SASTFinding(
                file_path=path, line=1, col=1, check_id="MP099",
                severity=Severity.HIGH.value, description="", recommendation="", code_snippet="",
            ),
            SASTFinding(
                file_path=path, line=2, col=1, check_id="MP099",
                severity=Severity.HIGH.value, description="", recommendation="", code_snippet="",
            ),
        ]
        applied = fix_file_findings(path, findings)
        assert applied == 2
        with open(path, "r") as f:
            fixed = f.read()
        assert "public_exponent=65537" in fixed
        assert "e=65537" in fixed
    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_fix_mp100_cookie_security_settings():
    content = """SESSION_COOKIE_HTTPONLY = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_HTTPONLY = False
response.set_cookie('token', 'val', httponly=False)
"""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        findings = [
            SASTFinding(file_path=path, line=1, col=1, check_id="MP100", severity=Severity.HIGH.value, description="", recommendation="", code_snippet=""),
            SASTFinding(file_path=path, line=2, col=1, check_id="MP100", severity=Severity.HIGH.value, description="", recommendation="", code_snippet=""),
            SASTFinding(file_path=path, line=3, col=1, check_id="MP100", severity=Severity.HIGH.value, description="", recommendation="", code_snippet=""),
            SASTFinding(file_path=path, line=4, col=1, check_id="MP100", severity=Severity.HIGH.value, description="", recommendation="", code_snippet=""),
        ]
        applied = fix_file_findings(path, findings)
        assert applied == 4
        with open(path, "r") as f:
            fixed = f.read()
        assert "SESSION_COOKIE_HTTPONLY = True" in fixed
        assert "SESSION_COOKIE_SECURE = True" in fixed
        assert "CSRF_COOKIE_HTTPONLY = True" in fixed
        assert "httponly=True" in fixed
    finally:
        if os.path.exists(path):
            os.unlink(path)
