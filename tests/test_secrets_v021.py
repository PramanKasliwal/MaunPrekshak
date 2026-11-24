"""
Tests for MaunPrekshak Core v0.21.0 — DevOps Secrets Detection Suite (MP-SEC-063–MP-SEC-068).
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


def test_circleci_personal_api_token():
    key_name = "circle" + "_token"
    token = ("1a2b3c4d5e" * 4)[:40]
    content = f"{key_name} = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "CircleCI Personal API Token"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_mailchimp_api_key():
    token = ("a1b2c3d4e5f6" * 3)[:32] + "-us" + "1"
    content = f"MAILCHIMP_KEY = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "Mailchimp API Key"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_contentful_api_token():
    prefix = "CF" + "PAT-"
    body = "aBcDeFg12345" * 4
    token = prefix + body
    content = f"CONTENTFUL_TOKEN = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "Contentful API Token"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_bitly_access_token():
    key_name = "bit" + "ly_token"
    token = ("9f8e7d6c5b" * 4)[:40]
    content = f"{key_name} = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "Bitly Access Token"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_yandex_cloud_iam_token():
    prefix = "t" + "1."
    body = "AbCdEf123456" * 6
    token = prefix + body
    content = f"YANDEX_TOKEN = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "Yandex Cloud IAM Token"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_sentry_user_auth_token():
    prefix = "sntryu" + "_"
    body = "0123456789abcdef" * 4
    token = prefix + body
    content = f"SENTRY_AUTH_TOKEN = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "Sentry User Auth Token"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_v021_secrets_suppression():
    content = (
        f"circle_token = '{'1a2b3c4d5e' * 4}' # nosec\n"
        f"MAILCHIMP_KEY = '{('a1b2c3d4e5f6' * 3)[:32]}-us1' # ignore-secret\n"
        f"CONTENTFUL = 'CFPAT-{'aBcDeFg12345' * 4}' # maunprekshak: ignore\n"
        f"bitly_token = '{'9f8e7d6c5b' * 4}' # nosec\n"
        f"YANDEX = 't1.{'AbCdEf123456' * 6}' // ignore-secret\n"
        f"SENTRY = 'sntryu_{'0123456789abcdef' * 4}' # nosec\n"
    )
    findings = _scan_text(content)
    assert len(findings) == 0
