"""
Tests for MaunPrekshak Core v0.20.0 — DevOps Secrets Detection Suite (MP-SEC-057–MP-SEC-062).
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
        os.unlink(path)


def test_twilio_api_key():
    prefix = "S" + "K"
    hex_body = "1a2b3c4d5e6f7a8b" + "9c0d1e2f3a4b5c6d"
    token = prefix + hex_body
    content = f"TWILIO_KEY = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "Twilio API Key"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_datadog_api_key():
    key_name = "data" + "dog_api_key"
    token = "a" * 16 + "b" * 16
    content = f"{key_name} = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "Datadog API Key"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_asana_personal_access_token():
    part1 = "1" * 16
    part2 = "x" * 16 + "Y" * 16
    token = part1 + ":" + part2
    content = f"ASANA_PAT = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "Asana Personal Access Token"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_fastly_api_token():
    key_name = "fast" + "ly_api_token"
    token = "F" * 16 + "t" * 16
    content = f"{key_name} = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "Fastly API Token"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_linear_personal_access_token():
    prefix = "lin_" + "pat_"
    body = "a" * 20 + "B" * 20
    token = prefix + body
    content = f"LINEAR_PAT = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "Linear Personal Access Token"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_hubspot_private_app_token():
    prefix = "pat-" + "na1-"
    uuid_part = "12345678" + "-" + "1234" + "-" + "4321" + "-" + "9876" + "-" + "123456789abc"
    token = prefix + uuid_part
    content = f"HUBSPOT_TOKEN = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "HubSpot Private App Token"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"
