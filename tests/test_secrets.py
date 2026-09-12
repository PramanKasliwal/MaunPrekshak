"""
Tests for MaunPrekshak Secrets Scanner
"""
import pytest
from maunprekshak.scanner.secrets import scan_secrets, SECRET_PATTERNS


class TestSecretPatterns:
    """Test that regex patterns correctly identify known secret formats."""

    def test_detects_aws_access_key(self, tmp_path):
        py_file = tmp_path / "config.py"
        py_file.write_text('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n')
        findings = scan_secrets(str(tmp_path))
        secret_types = [f.secret_type for f in findings]
        assert "AWS Access Key ID" in secret_types

    def test_detects_aws_secret_key(self, tmp_path):
        py_file = tmp_path / "config.py"
        py_file.write_text('AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n')
        findings = scan_secrets(str(tmp_path))
        assert len(findings) > 0

    def test_detects_github_token(self, tmp_path):
        py_file = tmp_path / "deploy.py"
        py_file.write_text('token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"\n')
        findings = scan_secrets(str(tmp_path))
        secret_types = [f.secret_type for f in findings]
        assert "GitHub Token" in secret_types

    def test_detects_stripe_secret_key(self, tmp_path):
        py_file = tmp_path / "payment.py"
        py_file.write_text('STRIPE_KEY = "sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ"\n')
        findings = scan_secrets(str(tmp_path))
        assert len(findings) > 0

    def test_detects_private_key(self, tmp_path):
        key_file = tmp_path / "private.pem"
        key_file.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n")
        findings = scan_secrets(str(tmp_path))
        assert len(findings) > 0

    def test_scans_env_files(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text('STRIPE_SECRET_KEY=sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ\n')
        findings = scan_secrets(str(tmp_path))
        assert len(findings) > 0

    def test_masks_secret_value(self, tmp_path):
        py_file = tmp_path / "config.py"
        py_file.write_text('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n')
        findings = scan_secrets(str(tmp_path))
        assert len(findings) > 0
        # Value should be masked, not full plaintext
        assert "AKIAIOSFODNN7EXAMPLE" not in findings[0].masked_value
        assert "***" in findings[0].masked_value

    def test_skips_excluded_directories(self, tmp_path):
        venv_dir = tmp_path / "venv" / "lib"
        venv_dir.mkdir(parents=True)
        py_file = venv_dir / "config.py"
        py_file.write_text('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n')
        findings = scan_secrets(str(tmp_path))
        # Files inside venv/ should be excluded
        assert len(findings) == 0

    def test_returns_file_and_line_number(self, tmp_path):
        py_file = tmp_path / "app.py"
        py_file.write_text("x = 1\nAWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"\ny = 2\n")
        findings = scan_secrets(str(tmp_path))
        assert len(findings) > 0
        assert findings[0].line == 2
        assert "app.py" in findings[0].file_path

    def test_no_false_positives_on_clean_code(self, tmp_path):
        py_file = tmp_path / "clean.py"
        py_file.write_text(
            'import os\n'
            'key = os.getenv("AWS_ACCESS_KEY_ID")\n'
            'def hello():\n'
            '    return "world"\n'
        )
        findings = scan_secrets(str(tmp_path))
        # Reading from env vars is safe — should not flag
        assert len(findings) == 0
