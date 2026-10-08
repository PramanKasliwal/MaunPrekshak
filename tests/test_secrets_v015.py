"""
Tests for MaunPrekshak Core v0.15.0 — Enterprise DevOps & Cloud Secrets Detection.
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


def test_gitlab_pipeline_runner_token():
    pfx1 = "glptt-"
    pfx2 = "glrt-"
    tok1 = pfx1 + "a" * 24
    tok2 = pfx2 + "b" * 24
    code = f'GITLAB_TRIGGER = "{tok1}"\nGITLAB_RUNNER = "{tok2}"\n'
    findings = _scan_content(code)
    types = [f.secret_type for f in findings]
    assert "GitLab Pipeline / Runner Token" in types
    gl_findings = [f for f in findings if f.secret_type == "GitLab Pipeline / Runner Token"]
    assert len(gl_findings) == 2


def test_atlassian_api_token():
    tok = "a" * 24
    code = f'jira_token = "atlassian_api_key = \'{tok}\'"\n'
    findings = _scan_content(code)
    types = [f.secret_type for f in findings]
    assert "Atlassian API Token" in types


def test_sentry_auth_token():
    pfx = "sntrys_"
    tok = pfx + "0" * 64
    code = f'SENTRY_TOKEN = "{tok}"\n'
    findings = _scan_content(code)
    types = [f.secret_type for f in findings]
    assert "Sentry Auth Token" in types


def test_shopify_access_token():
    pfx1 = "shpat_"
    pfx2 = "shpca_"
    tok1 = pfx1 + "0" * 32
    tok2 = pfx2 + "1" * 32
    code = f'SHOPIFY_1 = "{tok1}"\nSHOPIFY_2 = "{tok2}"\n'
    findings = _scan_content(code)
    types = [f.secret_type for f in findings]
    assert "Shopify Access Token" in types
    shopify_findings = [f for f in findings if f.secret_type == "Shopify Access Token"]
    assert len(shopify_findings) == 2


def test_linear_api_key():
    pfx = "lin_api_"
    tok = pfx + "a" * 40
    code = f'LINEAR_API = "{tok}"\n'
    findings = _scan_content(code)
    types = [f.secret_type for f in findings]
    assert "Linear API Key" in types


def test_cloudflare_api_token():
    pfx = "cfe_"
    tok = pfx + "0" * 40
    code = f'CLOUDFLARE_AUTH = "{tok}"\n'
    findings = _scan_content(code)
    types = [f.secret_type for f in findings]
    assert "Cloudflare API Token" in types
