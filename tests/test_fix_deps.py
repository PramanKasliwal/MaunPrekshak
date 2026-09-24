"""
Unit tests for automated requirements.txt dependency vulnerability auto-fix.
"""
import os
import tempfile
import pytest
from maunprekshak.scanner.fixer import fix_requirements_txt
from maunprekshak.scanner.report import DepVulnerability


def _make_req_file(content: str) -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    f.write(content)
    f.close()
    return f.name


class TestFixRequirementsTxt:
    def test_patches_pinned_vulnerable_dep(self):
        req_path = _make_req_file("requests==2.25.0\n")
        deps = [DepVulnerability(
            package="requests", version="2.25.0", cve_id="CVE-2023-32681",
            severity="HIGH", cvss_score=7.5, description="Proxy injection",
            fix_version="2.31.0",
        )]
        try:
            count = fix_requirements_txt(req_path, deps)
            assert count == 1
            with open(req_path) as f:
                content = f.read()
            assert "requests>=2.31.0" in content
        finally:
            os.unlink(req_path)

    def test_does_not_modify_unpinned_dep(self):
        req_path = _make_req_file("requests>=2.25.0\n")
        deps = [DepVulnerability(
            package="requests", version="2.25.0", cve_id="CVE-2023-32681",
            severity="HIGH", cvss_score=7.5, description="Proxy injection",
            fix_version="2.31.0",
        )]
        try:
            count = fix_requirements_txt(req_path, deps)
            # >= operator: should NOT be patched (already flexible)
            assert count == 0
        finally:
            os.unlink(req_path)

    def test_preserves_comments_and_other_deps(self):
        original = "# Production dependencies\nflask==2.0.0\nrequests==2.25.0\n"
        req_path = _make_req_file(original)
        deps = [DepVulnerability(
            package="requests", version="2.25.0", cve_id="CVE-2023-32681",
            severity="HIGH", cvss_score=7.5, description="Proxy injection",
            fix_version="2.31.0",
        )]
        try:
            fix_requirements_txt(req_path, deps)
            with open(req_path) as f:
                content = f.read()
            assert "# Production dependencies" in content
            assert "flask==2.0.0" in content
            assert "requests>=2.31.0" in content
        finally:
            os.unlink(req_path)

    def test_returns_zero_for_dep_without_fix_version(self):
        req_path = _make_req_file("requests==2.25.0\n")
        deps = [DepVulnerability(
            package="requests", version="2.25.0", cve_id="CVE-2023-32681",
            severity="HIGH", cvss_score=7.5, description="No fix available",
            fix_version="",
        )]
        try:
            count = fix_requirements_txt(req_path, deps)
            assert count == 0
        finally:
            os.unlink(req_path)

    def test_returns_zero_for_missing_file(self):
        deps = [DepVulnerability(
            package="flask", version="0.12.0", cve_id="CVE-2019-1234",
            severity="HIGH", cvss_score=7.0, description="XSS",
            fix_version="1.0.0",
        )]
        count = fix_requirements_txt("/nonexistent/requirements.txt", deps)
        assert count == 0

    def test_patches_multiple_vulnerable_deps(self):
        req_path = _make_req_file("flask==0.12.0\npillow==8.0.0\ndjango==2.2.0\n")
        deps = [
            DepVulnerability("flask", "0.12.0", "CVE-2019-1", "HIGH", 7.0, "XSS", "1.0.0"),
            DepVulnerability("pillow", "8.0.0", "CVE-2021-1", "CRITICAL", 9.0, "Code exec", "9.0.0"),
        ]
        try:
            count = fix_requirements_txt(req_path, deps)
            assert count == 2
            with open(req_path) as f:
                content = f.read()
            assert "flask>=1.0.0" in content
            assert "pillow>=9.0.0" in content
            assert "django==2.2.0" in content  # unchanged
        finally:
            os.unlink(req_path)
