"""
Unit tests for GitHub Actions workflow annotation emitter (format_github_annotations).
"""
import pytest
from maunprekshak.scanner.report import (
    format_github_annotations, aggregate, SASTFinding, SecretFinding, DepVulnerability,
)


def _make_result():
    sast = [SASTFinding(
        file_path="/proj/app.py", line=10, col=4,
        check_id="MP001", severity="CRITICAL",
        description="eval() detected", recommendation="Use ast.literal_eval()",
        code_snippet="eval(x)",
    )]
    secrets = [SecretFinding(
        file_path="/proj/secrets.py", line=3,
        secret_type="GitHub Token", masked_value="ghp_***", severity="HIGH",
    )]
    deps = [DepVulnerability(
        package="flask", version="0.12.0", cve_id="CVE-2019-1234",
        severity="HIGH", cvss_score=7.0, description="Flask XSS vuln",
        fix_version="1.0.0",
    )]
    return aggregate(deps, secrets, sast)


class TestGitHubAnnotations:
    def test_output_is_string(self):
        result = _make_result()
        out = format_github_annotations(result)
        assert isinstance(out, str)

    def test_critical_finding_is_error_level(self):
        result = _make_result()
        out = format_github_annotations(result)
        lines = out.splitlines()
        sast_lines = [l for l in lines if "MP001" in l]
        assert sast_lines
        assert sast_lines[0].startswith("::error")

    def test_annotation_contains_file_and_line(self):
        result = _make_result()
        out = format_github_annotations(result)
        assert "app.py" in out
        assert "line=10" in out

    def test_secret_annotation_is_error(self):
        result = _make_result()
        out = format_github_annotations(result)
        lines = out.splitlines()
        secret_lines = [l for l in lines if "GitHub Token" in l or "secrets.py" in l]
        assert secret_lines
        assert secret_lines[0].startswith("::error")

    def test_dep_annotation_has_cve_id(self):
        result = _make_result()
        out = format_github_annotations(result)
        assert "CVE-2019-1234" in out

    def test_empty_result_produces_empty_string(self):
        result = aggregate([], [], [])
        out = format_github_annotations(result)
        assert out == ""

    def test_medium_finding_is_warning_level(self):
        sast = [SASTFinding(
            file_path="/proj/code.py", line=5, col=0,
            check_id="MP008", severity="MEDIUM",
            description="Weak hash", recommendation="Use SHA-256",
            code_snippet="hashlib.md5(data)",
        )]
        result = aggregate([], [], sast)
        out = format_github_annotations(result)
        assert out.startswith("::warning")
