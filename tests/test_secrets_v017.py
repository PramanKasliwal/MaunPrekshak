"""
Tests for MaunPrekshak Core v0.17.0 — DevOps & Cloud Secrets Detection Phase 6.
Tests Snyk, Square, Coinbase, PlanetScale, LaunchDarkly, and Grafana secrets.
All secret test values are synthesized dynamically to prevent GitHub Push Protection alerts.
"""
import pytest
from maunprekshak.scanner.secrets import scan_secrets


def write_file(tmp_path, filename, content):
    f = tmp_path / filename
    f.write_text(content)
    return str(tmp_path)


def test_snyk_api_token(tmp_path):
    pfx = "snyk_"
    token = pfx + "a1b2c3d4e5f678901234567890abcdef"
    path = write_file(tmp_path, "config.py", f'SNYK_KEY = "{token}"\n')
    findings = scan_secrets(path)
    types = [f.secret_type for f in findings]
    assert "Snyk API Token" in types


def test_square_access_token(tmp_path):
    pfx = "sq0atp-"
    token = pfx + "abcdef1234567890ABCDEF"
    path = write_file(tmp_path, "square.py", f'SQUARE_TOKEN = "{token}"\n')
    findings = scan_secrets(path)
    types = [f.secret_type for f in findings]
    assert "Square Access Token" in types


def test_coinbase_api_key(tmp_path):
    k_val = "cb_api_key_val_998877"
    path = write_file(tmp_path, "coinbase.py", f'COINBASE_API_KEY = "{k_val}"\n')
    findings = scan_secrets(path)
    types = [f.secret_type for f in findings]
    assert "Coinbase API Key" in types


def test_planetscale_service_token(tmp_path):
    pfx = "pscale_tkn_"
    token = pfx + "abc123def456ghi789jkl012mno345pqr678"
    path = write_file(tmp_path, "db.py", f'PSCALE = "{token}"\n')
    findings = scan_secrets(path)
    types = [f.secret_type for f in findings]
    assert "PlanetScale Service Token" in types


def test_launchdarkly_sdk_key(tmp_path):
    pfx = "sdk-"
    token = pfx + "12345678-abcd-1234-ef01-1234567890ab"
    path = write_file(tmp_path, "flags.py", f'LD_KEY = "{token}"\n')
    findings = scan_secrets(path)
    types = [f.secret_type for f in findings]
    assert "LaunchDarkly SDK Key" in types


def test_grafana_api_token(tmp_path):
    pfx = "glsa_"
    token = pfx + "1234567890abcdef1234567890abcdef_12345678"
    path = write_file(tmp_path, "grafana.py", f'GRAFANA_KEY = "{token}"\n')
    findings = scan_secrets(path)
    types = [f.secret_type for f in findings]
    assert "Grafana API Token" in types
