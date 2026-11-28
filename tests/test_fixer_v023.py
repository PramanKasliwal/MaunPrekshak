"""
Tests for MaunPrekshak Core v0.23.0 — Deterministic Mechanical Auto-Fixing Phase 12.
Covers TF031, TF033, DF020, MP107, and MP110.
"""
import os
import tempfile
from maunprekshak.scanner.report import SASTFinding, Severity
from maunprekshak.scanner.fixer import fix_file_findings


def _apply_fixes(content: str, findings):
    with tempfile.NamedTemporaryFile("w", suffix=".tf", delete=False) as f:
        f.write(content)
        f.flush()
        temp_path = f.name
    try:
        fixed_count = fix_file_findings(temp_path, findings)
        with open(temp_path, "r") as f:
            new_content = f.read()
        return fixed_count, new_content
    finally:
        os.remove(temp_path)


def test_fix_tf031_rds_deletion_protection():
    orig = 'resource "aws_db_instance" "x" {\n  deletion_protection = false\n}\n'
    finding = SASTFinding(
        file_path="main.tf", line=2, col=1, check_id="TF031",
        severity=Severity.HIGH.value, description="RDS deletion protection disabled",
        recommendation="Enable deletion protection", code_snippet="deletion_protection = false",
    )
    count, fixed = _apply_fixes(orig, [finding])
    assert count == 1
    assert "deletion_protection = true" in fixed


def test_fix_tf033_api_gateway_cache_and_authorization():
    orig1 = 'resource "aws_api_gateway_method_settings" "x" {\n  cache_data_encrypted = false\n}\n'
    finding1 = SASTFinding(
        file_path="main.tf", line=2, col=1, check_id="TF033",
        severity=Severity.HIGH.value, description="Cache unencrypted",
        recommendation="Encrypt cache", code_snippet="cache_data_encrypted = false",
    )
    count1, fixed1 = _apply_fixes(orig1, [finding1])
    assert count1 == 1
    assert "cache_data_encrypted = true" in fixed1

    orig2 = 'resource "aws_api_gateway_method" "x" {\n  authorization = "NONE"\n}\n'
    finding2 = SASTFinding(
        file_path="main.tf", line=2, col=1, check_id="TF033",
        severity=Severity.HIGH.value, description="Auth none",
        recommendation="Enable auth", code_snippet='authorization = "NONE"',
    )
    count2, fixed2 = _apply_fixes(orig2, [finding2])
    assert count2 == 1
    assert 'authorization = "AWS_IAM"' in fixed2


def test_fix_df020_package_manager_flags():
    orig = 'FROM python:3.11\nRUN pip install --trusted-host pypi.org requests\nRUN npm install --unsafe-perm\nRUN yarn install --ignore-engines\n'
    f1 = SASTFinding("Dockerfile", 2, 1, "DF020", Severity.HIGH.value, "pip trusted host", "remove flag", "pip install --trusted-host")
    f2 = SASTFinding("Dockerfile", 3, 1, "DF020", Severity.HIGH.value, "npm unsafe perm", "remove flag", "npm install --unsafe-perm")
    f3 = SASTFinding("Dockerfile", 4, 1, "DF020", Severity.HIGH.value, "yarn ignore engines", "remove flag", "yarn install --ignore-engines")
    count, fixed = _apply_fixes(orig, [f1, f2, f3])
    assert count == 3
    assert "--trusted-host" not in fixed
    assert "--unsafe-perm" not in fixed
    assert "--ignore-engines" not in fixed


def test_fix_mp107_disabled_ssl():
    orig = 'import httpx\nimport aiohttp\nclient = httpx.Client(verify=False)\nconn = aiohttp.TCPConnector(ssl=False)\n'
    f1 = SASTFinding("app.py", 3, 1, "MP107", Severity.HIGH.value, "verify false", "enable verify", "verify=False")
    f2 = SASTFinding("app.py", 4, 1, "MP107", Severity.HIGH.value, "ssl false", "enable ssl", "ssl=False")
    count, fixed = _apply_fixes(orig, [f1, f2])
    assert count == 2
    assert "verify=True" in fixed
    assert "ssl=True" in fixed


def test_fix_mp110_ecb_mode():
    orig = 'from Crypto.Cipher import AES\nfrom cryptography.hazmat.primitives.ciphers import modes\nc1 = AES.new(key, AES.MODE_ECB)\nc2 = modes.ECB()\n'
    f1 = SASTFinding("crypto.py", 3, 1, "MP110", Severity.HIGH.value, "ECB mode", "use GCM", "AES.MODE_ECB")
    f2 = SASTFinding("crypto.py", 4, 1, "MP110", Severity.HIGH.value, "ECB mode", "use GCM", "modes.ECB()")
    count, fixed = _apply_fixes(orig, [f1, f2])
    assert count == 2
    assert "AES.MODE_GCM" in fixed
    assert "modes.GCM(nonce)" in fixed
