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


class TestShannonEntropy:
    """Test Shannon entropy calculation and candidate secret detection."""

    def test_detects_high_entropy_hex_token(self, tmp_path):
        py_file = tmp_path / "crypto.py"
        py_file.write_text('auth_hash = "4f9b2d8e1a3c7b5f9e2d4a6c8e0b1f3a"\n')
        findings = scan_secrets(str(tmp_path))
        entropy_findings = [f for f in findings if "High-Entropy" in f.secret_type]
        assert len(entropy_findings) > 0

    def test_detects_high_entropy_base64_token(self, tmp_path):
        py_file = tmp_path / "auth.py"
        # High-entropy un-prefixed base64 string
        py_file.write_text('payload = "dGhpcy1pcy1hLXZlcnktcmFuZG9tLXNlY3JldC1rZXktMTIzNDU2Nzg5"\n')
        findings = scan_secrets(str(tmp_path))
        entropy_findings = [f for f in findings if "High-Entropy" in f.secret_type]
        assert len(entropy_findings) > 0

    def test_suppresses_uuid(self, tmp_path):
        py_file = tmp_path / "models.py"
        py_file.write_text('session_id = "550e8400-e29b-41d4-a716-446655440000"\n')
        findings = scan_secrets(str(tmp_path))
        assert len(findings) == 0

    def test_suppresses_urls_and_file_paths(self, tmp_path):
        py_file = tmp_path / "client.py"
        py_file.write_text(
            'url = "https://api.example.com/v1/auth/oauth2/token"\n'
            'path = "/usr/local/share/data/templates/index.html"\n'
        )
        findings = scan_secrets(str(tmp_path))
        assert len(findings) == 0

    def test_suppresses_placeholder_and_dummy_tokens(self, tmp_path):
        py_file = tmp_path / "config.py"
        py_file.write_text('sample_token = "dummy_placeholder_token_for_testing_purposes"\n')
        findings = scan_secrets(str(tmp_path))
        assert len(findings) == 0

    def test_target_files_only_scans_specified_files(self, tmp_path):
        vuln_file = tmp_path / "vuln.py"
        vuln_file.write_text('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n')

        safe_file = tmp_path / "safe.py"
        safe_file.write_text('x = 42\n')

        # When target_files points only to safe_file, vuln_file must be ignored
        findings = scan_secrets(str(tmp_path), target_files=[str(safe_file)])
        assert len(findings) == 0

        # When target_files points to vuln_file, it is scanned
        findings_vuln = scan_secrets(str(tmp_path), target_files=[str(vuln_file)])
        assert len(findings_vuln) > 0

