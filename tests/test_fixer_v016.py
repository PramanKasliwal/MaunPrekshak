"""
Tests for MaunPrekshak Core v0.16.0 — Mechanical Auto-Fixing Engine Phase 5.
"""
import os
import tempfile
import pytest

from maunprekshak.scanner.fixer import fix_file_findings
from maunprekshak.scanner.report import SASTFinding, Severity


def _apply_fix(content: str, finding: SASTFinding) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write(content)
        fname = f.name
    try:
        count = fix_file_findings(fname, [finding])
        assert count > 0, "Expected fix to be applied"
        with open(fname, "r") as f:
            return f.read()
    finally:
        os.unlink(fname)


def test_fix_gha004_permissions_write_all():
    original = "permissions: write-all\n"
    finding = SASTFinding(
        file_path="workflow.yml", line=1, col=0,
        check_id="GHA004", severity=Severity.HIGH.value,
        description="Overly permissive permissions", recommendation="", code_snippet=original,
    )
    fixed = _apply_fix(original, finding)
    assert "permissions: read-all" in fixed


def test_fix_k8s003_run_as_non_root():
    original = "    runAsNonRoot: false\n"
    finding = SASTFinding(
        file_path="pod.yaml", line=1, col=0,
        check_id="K8S003", severity=Severity.HIGH.value,
        description="Root execution", recommendation="", code_snippet=original,
    )
    fixed = _apply_fix(original, finding)
    assert "runAsNonRoot: true" in fixed


def test_fix_mp063_jwt_verify_signature():
    original = "data = jwt.decode(token, key, options={'verify_signature': False})\n"
    finding = SASTFinding(
        file_path="app.py", line=1, col=0,
        check_id="MP063", severity=Severity.CRITICAL.value,
        description="JWT signature verification bypass", recommendation="", code_snippet=original,
    )
    fixed = _apply_fix(original, finding)
    assert "'verify_signature': True" in fixed


def test_fix_mp068_yaml_full_loader():
    original = "doc = yaml.load(data, Loader=yaml.FullLoader)\n"
    finding = SASTFinding(
        file_path="app.py", line=1, col=0,
        check_id="MP068", severity=Severity.MEDIUM.value,
        description="Insecure YAML FullLoader", recommendation="", code_snippet=original,
    )
    fixed = _apply_fix(original, finding)
    assert "Loader=yaml.SafeLoader" in fixed
