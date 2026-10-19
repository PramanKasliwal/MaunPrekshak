import tempfile
import os
import re
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


def test_bitbucket_app_password():
    # Synthesize token dynamically to evade GitHub Push Protection
    token = "bku_" + "a" * 32
    content = f"BITBUCKET_TOKEN = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "Bitbucket App Password / Token"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_pulumi_access_token():
    token = "pul-" + "f" * 40
    content = f"PULUMI_ACCESS_TOKEN = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "Pulumi Access Token"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_new_relic_ingest_key():
    token_ingest = "NRAK-" + "A" * 27
    token_insights = "NRII-" + "b" * 32
    content = f"NR_INGEST = '{token_ingest}'\nNR_INSIGHTS = '{token_insights}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "New Relic Ingest / User API Key"]
    assert len(matched) == 2


def test_scaleway_api_key():
    token = "SCW" + "K" * 18
    content = f"SCW_SECRET_KEY = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "Scaleway API Key"]
    assert len(matched) == 1


def test_doppler_personal_token():
    token = "dp.pt." + "1" * 40
    content = f"DOPPLER_TOKEN = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "Doppler Personal / CLI Token"]
    assert len(matched) == 1


def test_openai_org_key():
    token = "org-" + "z" * 24
    content = f"OPENAI_ORG_ID = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "OpenAI Organization Key"]
    assert len(matched) == 1
