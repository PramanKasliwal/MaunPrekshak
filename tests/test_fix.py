"""
Tests for deterministic mechanical auto-fixing (--fix) of safe anti-patterns.
"""
import pytest
from maunprekshak.scanner.sast import scan_sast
from maunprekshak.scanner.fixer import fix_file_findings, apply_auto_fixes
from maunprekshak.scanner.report import ScanResult, RiskScore


def write_file(tmp_path, filename, content):
    f = tmp_path / filename
    f.write_text(content)
    return f


class TestAutoFix:
    def test_fix_mp012_yaml_load(self, tmp_path):
        f = write_file(tmp_path, "load_yaml.py", "import yaml\nconfig = yaml.load(data)\n")
        findings = scan_sast(str(tmp_path))
        assert any(f.check_id == "MP012" for f in findings)

        fixes = fix_file_findings(str(f), findings)
        assert fixes == 1

        new_content = f.read_text()
        assert "yaml.safe_load(data)" in new_content

        # Re-scan to verify finding is gone
        new_findings = scan_sast(str(tmp_path))
        assert not any(f.check_id == "MP012" for f in new_findings)

    def test_fix_mp014_tempfile_mktemp(self, tmp_path):
        f = write_file(tmp_path, "temp_file.py", "import tempfile\ntmp = tempfile.mktemp()\n")
        findings = scan_sast(str(tmp_path))
        assert any(f.check_id == "MP014" for f in findings)

        fixes = fix_file_findings(str(f), findings)
        assert fixes == 1

        new_content = f.read_text()
        assert "tempfile.NamedTemporaryFile().name" in new_content

        # Re-scan to verify finding is gone
        new_findings = scan_sast(str(tmp_path))
        assert not any(f.check_id == "MP014" for f in new_findings)

    def test_fix_mp023_tarfile_extractall_empty(self, tmp_path):
        f = write_file(tmp_path, "extract.py", "import tarfile\ntar = tarfile.open('a.tar')\ntar.extractall()\n")
        findings = scan_sast(str(tmp_path))
        assert any(f.check_id == "MP023" for f in findings)

        fixes = fix_file_findings(str(f), findings)
        assert fixes == 1

        new_content = f.read_text()
        assert "tar.extractall(filter='data')" in new_content

        # Re-scan to verify finding is gone
        new_findings = scan_sast(str(tmp_path))
        assert not any(f.check_id == "MP023" for f in new_findings)

    def test_fix_mp023_tarfile_extractall_with_path(self, tmp_path):
        f = write_file(tmp_path, "extract2.py", "import tarfile\ntar = tarfile.open('a.tar')\ntar.extractall(dest_path)\n")
        findings = scan_sast(str(tmp_path))
        assert any(f.check_id == "MP023" for f in findings)

        fixes = fix_file_findings(str(f), findings)
        assert fixes == 1

        new_content = f.read_text()
        assert "tar.extractall(dest_path, filter='data')" in new_content

        # Re-scan to verify finding is gone
        new_findings = scan_sast(str(tmp_path))
        assert not any(f.check_id == "MP023" for f in new_findings)

    def test_apply_auto_fixes_integration(self, tmp_path):
        f1 = write_file(tmp_path, "app1.py", "import yaml\nyaml.load(data)\n")
        f2 = write_file(tmp_path, "app2.py", "import tempfile\ntempfile.mktemp()\n")

        sast_findings = scan_sast(str(tmp_path))
        assert len(sast_findings) == 2

        scan_res = ScanResult(
            deps=[],
            secrets=[],
            sast=sast_findings,
            risk_score=RiskScore(score=60, level="HIGH"),
        )

        total_fixed, updated_result = apply_auto_fixes(scan_res)
        assert total_fixed == 2
        assert len(updated_result.sast) == 0
        assert updated_result.risk_score.level == "LOW"
        assert updated_result.risk_score.score == 0
