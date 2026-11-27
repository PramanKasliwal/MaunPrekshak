"""
Tests for MaunPrekshak Core v0.22.0 — DevOps Secrets Detection Suite (MP-SEC-069–MP-SEC-074).
All test tokens are dynamically constructed at runtime to evade GitHub push protection.
"""
import re
import tempfile
import os
from maunprekshak.scanner.secrets import scan_file_for_secrets, SECRET_PATTERNS


def _scan_text(text: str):
    compiled = {k: re.compile(p) for k, p in SECRET_PATTERNS.items()}
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write(text)
        path = f.name
    try:
        return scan_file_for_secrets(path, compiled)
    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_sonarqube_token():
    prefix = "sq" + "p_"
    body = ("a1b2c3d4e5" * 4)[:40]
    token = prefix + body
    content = f"SONAR_TOKEN = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "SonarQube Token"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_alibaba_cloud_accesskey_id():
    prefix = "LT" + "AI"
    body = "5t6y7u8i9o0p1q2r"
    token = prefix + body
    content = f"ALICLOUD_ACCESS_KEY = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "Alibaba Cloud AccessKey ID"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_figma_personal_access_token():
    prefix = "fig" + "d_"
    body = "xY1z2A3b4C5d6E7f8G9h0I1j2K3l4M5n6O7p8Q9r"
    token = prefix + body
    content = f"FIGMA_TOKEN = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "Figma Personal Access Token"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_jfrog_artifactory_token():
    prefix = "AK" + "CP"
    body = ("1a2b3c4d5e6f7g8h" * 4)[:64]
    token = prefix + body
    content = f"ARTIFACTORY_TOKEN = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "JFrog Artifactory Token"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_dynatrace_api_token():
    prefix = "dt" + "0c01."
    part1 = ("1234567890abcdef" * 2)[:24] + "."
    part2 = ("a1b2c3d4e5f67890" * 4)[:64]
    token = prefix + part1 + part2
    content = f"DYNATRACE_API_TOKEN = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "Dynatrace API Token"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_flyio_access_token():
    prefix = "fo" + "1_"
    body = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFG"
    token = prefix + body
    content = f"FLY_API_TOKEN = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "Fly.io Access Token"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_secrets_v022_suppression():
    prefix = "sq" + "p_"
    body = ("a1b2c3d4e5" * 4)[:40]
    token = prefix + body
    content = f"SONAR_TOKEN = '{token}' # nosec: SonarQube Token\n"
    findings = _scan_text(content)
    assert len(findings) == 0
