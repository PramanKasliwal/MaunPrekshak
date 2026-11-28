"""
Tests for MaunPrekshak Core v0.23.0 — DevOps & Cloud Secrets Detection Phase 12 (MP-SEC-075–MP-SEC-080).
All secret patterns are verified with dynamically concatenated test strings to strictly comply
with GitHub Push Protection.
"""
import os
import tempfile
from maunprekshak.scanner.secrets import scan_secrets


def _scan_secret_content(content: str):
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(content)
        f.flush()
        temp_path = f.name
    try:
        return scan_secrets(temp_path, target_files=[temp_path])
    finally:
        os.remove(temp_path)


def test_groq_api_key():
    pfx = "gsk_"
    body = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4"
    code = f'GROQ_KEY = "{pfx}{body}"\n'
    findings = _scan_secret_content(code)
    matches = [f for f in findings if f.secret_type == "Groq API Key"]
    assert len(matches) == 1
    assert matches[0].severity == "HIGH"


def test_tailscale_key():
    pfx = "tskey-auth-"
    body = "k1234567890abcdefghijklmn"
    code = f'TAILSCALE_AUTH_KEY = "{pfx}{body}"\n'
    findings = _scan_secret_content(code)
    matches = [f for f in findings if f.secret_type == "Tailscale Auth / API Key"]
    assert len(matches) == 1
    assert matches[0].severity == "HIGH"


def test_datadog_app_key():
    pfx = "a1b2c3d4e5f67890"
    sfx = "1234567890abcdef12345678"
    code = f'DD_APP_KEY = "{pfx}{sfx}"\n'
    findings = _scan_secret_content(code)
    matches = [f for f in findings if f.secret_type == "Datadog App Key"]
    assert len(matches) == 1
    assert matches[0].severity == "HIGH"


def test_linear_webhook_secret():
    pfx = "lin_wh_"
    body = "0123456789abcdef0123456789abcdef"
    code = f'WEBHOOK_SECRET = "{pfx}{body}"\n'
    findings = _scan_secret_content(code)
    matches = [f for f in findings if f.secret_type == "Linear Webhook Signing Secret"]
    assert len(matches) == 1
    assert matches[0].severity == "HIGH"


def test_sentry_dsn_secret():
    pub = "a" * 32
    sec = "b" * 32
    code = f'SENTRY_DSN = "https://{pub}:{sec}@o12345.ingest.sentry.io/12345"\n'
    findings = _scan_secret_content(code)
    matches = [f for f in findings if f.secret_type == "Sentry DSN Secret"]
    assert len(matches) == 1
    assert matches[0].severity == "HIGH"


def test_mistral_ai_api_key():
    pfx = "MISTRAL_API_KEY = "
    val = "m1sTr4l" + "9876543210abcdef012345678"
    code = f'{pfx}"{val}"\n'
    findings = _scan_secret_content(code)
    matches = [f for f in findings if f.secret_type == "Mistral AI API Key"]
    assert len(matches) == 1
    assert matches[0].severity == "HIGH"


def test_suppression_and_safe_patterns():
    pfx = "gsk_"
    body = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4"
    code = f'GROQ_KEY = "{pfx}{body}" # nosec\n'
    findings = _scan_secret_content(code)
    assert len(findings) == 0
