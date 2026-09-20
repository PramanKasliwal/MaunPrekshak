"""
Tests for inline comment and file-level suppression in SAST and Secrets scanners.
"""
import pytest
from maunprekshak.scanner.sast import scan_sast
from maunprekshak.scanner.secrets import scan_secrets


def write_file(tmp_path, filename, content):
    f = tmp_path / filename
    f.write_text(content)
    return str(tmp_path)


class TestSastSuppression:
    def test_inline_ignore_all(self, tmp_path):
        code = "result = eval(user_input)  # maunprekshak: ignore\n"
        path = write_file(tmp_path, "test.py", code)
        findings = scan_sast(path)
        assert len(findings) == 0

    def test_inline_ignore_specific_rule(self, tmp_path):
        code = "result = eval(user_input)  # maunprekshak: ignore[MP001]\n"
        path = write_file(tmp_path, "test.py", code)
        findings = scan_sast(path)
        assert len(findings) == 0

    def test_inline_ignore_unrelated_rule_still_flags(self, tmp_path):
        code = "result = eval(user_input)  # maunprekshak: ignore[MP002]\n"
        path = write_file(tmp_path, "test.py", code)
        findings = scan_sast(path)
        assert len(findings) == 1
        assert findings[0].check_id == "MP001"

    def test_inline_nosec(self, tmp_path):
        code = "result = eval(user_input)  # nosec\n"
        path = write_file(tmp_path, "test.py", code)
        findings = scan_sast(path)
        assert len(findings) == 0

    def test_inline_nosec_with_rule(self, tmp_path):
        code = "result = eval(user_input)  # nosec: MP001\n"
        path = write_file(tmp_path, "test.py", code)
        findings = scan_sast(path)
        assert len(findings) == 0

    def test_file_level_disable_all(self, tmp_path):
        code = "# maunprekshak: disable-file\nresult = eval(user_input)\nexec('x=1')\n"
        path = write_file(tmp_path, "test.py", code)
        findings = scan_sast(path)
        assert len(findings) == 0

    def test_file_level_disable_specific_rule(self, tmp_path):
        code = "# maunprekshak: disable-file[MP001]\nresult = eval(user_input)\nexec('x=1')\n"
        path = write_file(tmp_path, "test.py", code)
        findings = scan_sast(path)
        assert len(findings) == 1
        assert findings[0].check_id == "MP002"


class TestSecretSuppression:
    def test_secret_inline_ignore(self, tmp_path):
        # Generate token dynamically to avoid static token scanners
        token_prefix = "gh" + "p_"
        token = token_prefix + ("A" * 36)
        code = f'GITHUB_TOKEN = "{token}"  # maunprekshak: ignore\n'
        path = write_file(tmp_path, "secrets.py", code)
        findings = scan_secrets(path)
        assert len(findings) == 0

    def test_secret_inline_nosec(self, tmp_path):
        token_prefix = "gh" + "p_"
        token = token_prefix + ("B" * 36)
        code = f'GITHUB_TOKEN = "{token}"  # nosec\n'
        path = write_file(tmp_path, "secrets.py", code)
        findings = scan_secrets(path)
        assert len(findings) == 0

    def test_secret_inline_ignore_secret(self, tmp_path):
        token_prefix = "gh" + "p_"
        token = token_prefix + ("C" * 36)
        code = f'GITHUB_TOKEN = "{token}"  # maunprekshak: ignore-secret\n'
        path = write_file(tmp_path, "secrets.py", code)
        findings = scan_secrets(path)
        assert len(findings) == 0
