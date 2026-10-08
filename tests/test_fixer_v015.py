"""
Tests for MaunPrekshak Core v0.15.0 — Mechanical Auto-Fixing Engine Phase 4.
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


def test_fix_mp054_resolve_entities():
    original = "parser = etree.XMLParser(resolve_entities=True)\n"
    finding = SASTFinding(
        file_path="dummy.py", line=1, col=0,
        check_id="MP054", severity=Severity.HIGH.value,
        description="XXE", recommendation="", code_snippet=original,
    )
    fixed = _apply_fix(original, finding)
    assert "resolve_entities=False" in fixed


def test_fix_mp059_cookie_flags():
    original = "response.set_cookie('token', 'val', secure=False, httponly=False)\n"
    finding = SASTFinding(
        file_path="dummy.py", line=1, col=0,
        check_id="MP059", severity=Severity.HIGH.value,
        description="Insecure cookie", recommendation="", code_snippet=original,
    )
    fixed = _apply_fix(original, finding)
    assert "secure=True" in fixed
    assert "httponly=True" in fixed


def test_fix_mp060_check_hostname():
    original = "ctx.check_hostname = False\n"
    finding = SASTFinding(
        file_path="dummy.py", line=1, col=0,
        check_id="MP060", severity=Severity.HIGH.value,
        description="Disabled check_hostname", recommendation="", code_snippet=original,
    )
    fixed = _apply_fix(original, finding)
    assert "ctx.check_hostname = True" in fixed


def test_fix_k8s011_seccomp_unconfined():
    original = "    type: Unconfined\n"
    finding = SASTFinding(
        file_path="dummy.yaml", line=1, col=0,
        check_id="K8S011", severity=Severity.MEDIUM.value,
        description="Unconfined seccomp", recommendation="", code_snippet=original,
    )
    fixed = _apply_fix(original, finding)
    assert "type: RuntimeDefault" in fixed


def test_fix_k8s019_image_pull_policy_never():
    original = "      imagePullPolicy: Never\n"
    finding = SASTFinding(
        file_path="dummy.yaml", line=1, col=0,
        check_id="K8S019", severity=Severity.HIGH.value,
        description="Insecure pull policy", recommendation="", code_snippet=original,
    )
    fixed = _apply_fix(original, finding)
    assert "imagePullPolicy: Always" in fixed
