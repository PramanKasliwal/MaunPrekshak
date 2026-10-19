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


def test_supabase_access_token():
    # Synthesize dynamically at runtime to avoid push protection
    prefix = "sbp_"
    suffix = "a" * 40
    token = prefix + suffix
    content = f"SUPABASE_TOKEN = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "Supabase Access Token"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_postman_api_key():
    prefix = "PMAK-"
    part1 = "a" * 24
    part2 = "b" * 34
    token = prefix + part1 + "-" + part2
    content = f"POSTMAN_API_KEY = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "Postman API Key"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_airtable_personal_access_token():
    prefix = "pat"
    part1 = "a" * 14
    part2 = "b" * 64
    token = prefix + part1 + "." + part2
    content = f"AIRTABLE_TOKEN = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "Airtable Personal Access Token"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_render_api_key():
    prefix = "rnd_"
    suffix = "a" * 32
    token = prefix + suffix
    content = f"RENDER_API_KEY = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "Render API Key"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_segment_public_api_token():
    prefix = "sgp_"
    suffix = "a" * 64
    token = prefix + suffix
    content = f"SEGMENT_TOKEN = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "Segment Public API Token"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"


def test_pagerduty_api_token():
    prefix = "y_"
    suffix = "a" * 20
    token = prefix + suffix
    content = f"PAGERDUTY_TOKEN = '{token}'\n"
    findings = _scan_text(content)
    matched = [f for f in findings if f.secret_type == "PagerDuty API Token"]
    assert len(matched) == 1
    assert matched[0].severity == "HIGH"
