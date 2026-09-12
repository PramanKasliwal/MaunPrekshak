"""
Tests for MaunPrekshak SAST Scanner
"""
import pytest
from maunprekshak.scanner.sast import scan_sast


def write_py(tmp_path, filename, code):
    f = tmp_path / filename
    f.write_text(code)
    return str(tmp_path)


class TestEvalExec:
    def test_detects_eval(self, tmp_path):
        path = write_py(tmp_path, "vuln.py", 'result = eval(user_input)\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP001" in check_ids  # eval usage

    def test_detects_exec(self, tmp_path):
        path = write_py(tmp_path, "vuln.py", 'exec(user_code)\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP002" in check_ids  # exec usage

    def test_no_flag_on_safe_code(self, tmp_path):
        path = write_py(tmp_path, "safe.py", 'x = 1 + 1\nprint(x)\n')
        findings = scan_sast(path)
        assert len(findings) == 0


class TestPickle:
    def test_detects_pickle_loads(self, tmp_path):
        path = write_py(tmp_path, "vuln.py", 'import pickle\ndata = pickle.loads(raw)\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP003" in check_ids  # pickle usage

    def test_detects_marshal_loads(self, tmp_path):
        path = write_py(tmp_path, "vuln.py", 'import marshal\nobj = marshal.loads(raw)\n')
        findings = scan_sast(path)
        assert len(findings) > 0


class TestSubprocess:
    def test_detects_shell_true(self, tmp_path):
        path = write_py(tmp_path, "vuln.py", 'import subprocess\nsubprocess.run(cmd, shell=True)\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP004" in check_ids

    def test_no_flag_without_shell_true(self, tmp_path):
        path = write_py(tmp_path, "safe.py", 'import subprocess\nsubprocess.run(["ls", "-la"])\n')
        findings = scan_sast(path)
        mp004 = [f for f in findings if f.check_id == "MP004"]
        assert len(mp004) == 0


class TestInsecureHashing:
    def test_detects_md5(self, tmp_path):
        path = write_py(tmp_path, "vuln.py", 'import hashlib\nhash = hashlib.md5(data).hexdigest()\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP008" in check_ids

    def test_detects_sha1(self, tmp_path):
        path = write_py(tmp_path, "vuln.py", 'import hashlib\nhash = hashlib.sha1(data).hexdigest()\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP008" in check_ids


class TestYamlLoad:
    def test_detects_unsafe_yaml_load(self, tmp_path):
        path = write_py(tmp_path, "vuln.py", 'import yaml\ndata = yaml.load(stream)\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP012" in check_ids

    def test_no_flag_on_safe_yaml_load(self, tmp_path):
        path = write_py(tmp_path, "safe.py", 'import yaml\ndata = yaml.safe_load(stream)\n')
        findings = scan_sast(path)
        mp012 = [f for f in findings if f.check_id == "MP012"]
        assert len(mp012) == 0


class TestFindings:
    def test_finding_has_line_number(self, tmp_path):
        path = write_py(tmp_path, "vuln.py", 'x = 1\nresult = eval(user_input)\ny = 2\n')
        findings = scan_sast(path)
        assert len(findings) > 0
        assert findings[0].line == 2

    def test_finding_has_severity(self, tmp_path):
        path = write_py(tmp_path, "vuln.py", 'result = eval(user_input)\n')
        findings = scan_sast(path)
        assert findings[0].severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_finding_has_recommendation(self, tmp_path):
        path = write_py(tmp_path, "vuln.py", 'result = eval(user_input)\n')
        findings = scan_sast(path)
        assert len(findings[0].recommendation) > 0
