"""
Tests for MaunPrekshak Core v0.16.0 — Cloud & DevOps Secrets Detection.
Constructing test tokens dynamically at runtime to avoid GitHub Push Protection triggers.
"""
import os
import tempfile
import pytest

from maunprekshak.scanner.secrets import scan_secrets


def _scan_content(content: str):
    with tempfile.TemporaryDirectory() as tmpdir:
        fpath = os.path.join(tmpdir, "config.py")
        with open(fpath, "w") as f:
            f.write(content)
        return scan_secrets(tmpdir)


def test_vercel_access_token():
    pfx = "vercel_"
    tok = pfx + "a1B2c3D4e5F6g7H8i9J0k1L2"
    code = f'VERCEL_TOKEN = "{tok}"\n'
    findings = _scan_content(code)
    types = [f.secret_type for f in findings]
    assert "Vercel Access Token" in types


def test_doppler_service_token():
    pfx = "dp.st."
    tok = pfx + "dev." + "a" * 40
    code = f'DOPPLER_TOKEN = "{tok}"\n'
    findings = _scan_content(code)
    types = [f.secret_type for f in findings]
    assert "Doppler Service Token" in types


def test_resend_api_key():
    pfx = "re_"
    tok = pfx + "a" * 24
    code = f'RESEND_API_KEY = "{tok}"\n'
    findings = _scan_content(code)
    types = [f.secret_type for f in findings]
    assert "Resend API Key" in types


def test_posthog_api_key():
    pfx = "phc_"
    tok = pfx + "a" * 43
    code = f'POSTHOG_KEY = "{tok}"\n'
    findings = _scan_content(code)
    types = [f.secret_type for f in findings]
    assert "PostHog API Key" in types


def test_terraform_cloud_token():
    user_part = "abcdefghijklmn"
    tail = "a" * 65
    tok = f"{user_part}.atlasv1.{tail}"
    code = f'TF_TOKEN = "{tok}"\n'
    findings = _scan_content(code)
    types = [f.secret_type for f in findings]
    assert "Terraform Cloud / Atlas Token" in types


def test_heroku_api_key():
    uuid_str = "12345678-1234-1234-1234-123456789abc"
    code = f'HEROKU_API_KEY = "{uuid_str}"\n'
    findings = _scan_content(code)
    types = [f.secret_type for f in findings]
    assert "Heroku API Key" in types
