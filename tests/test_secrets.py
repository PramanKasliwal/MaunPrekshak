"""
Tests for MaunPrekshak Secrets Scanner
"""
import uuid
import secrets as py_secrets
import string
import pytest
from maunprekshak.scanner.secrets import scan_secrets, SECRET_PATTERNS


def _aws_access_key():
    return "AKIA" + "".join(py_secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))


def _stripe_key():
    return "sk_live_" + py_secrets.token_hex(12)


def _openai_proj_key():
    chars = string.ascii_letters + string.digits + "_-"
    return "sk-proj-" + "".join(py_secrets.choice(chars) for _ in range(85))


def _anthropic_key():
    chars = string.ascii_letters + string.digits + "_-"
    return "sk-ant-" + "".join(py_secrets.choice(chars) for _ in range(85))


def _huggingface_token():
    chars = string.ascii_letters + string.digits
    return "hf_" + "".join(py_secrets.choice(chars) for _ in range(34))


class TestSecretPatterns:
    """Test that regex patterns correctly identify known secret formats."""

    def test_detects_openai_key(self, tmp_path):
        py_file = tmp_path / "ai.py"
        py_file.write_text(f'OPENAI_API_KEY = "{_openai_proj_key()}"\n')
        findings = scan_secrets(str(tmp_path))
        secret_types = [f.secret_type for f in findings]
        assert "OpenAI API Key" in secret_types

    def test_detects_anthropic_key(self, tmp_path):
        py_file = tmp_path / "ai.py"
        py_file.write_text(f'ANTHROPIC_API_KEY = "{_anthropic_key()}"\n')
        findings = scan_secrets(str(tmp_path))
        secret_types = [f.secret_type for f in findings]
        assert "Anthropic API Key" in secret_types

    def test_detects_huggingface_token(self, tmp_path):
        py_file = tmp_path / "ai.py"
        py_file.write_text(f'HF_TOKEN = "{_huggingface_token()}"\n')
        findings = scan_secrets(str(tmp_path))
        secret_types = [f.secret_type for f in findings]
        assert "HuggingFace Token" in secret_types

    def test_detects_aws_access_key(self, tmp_path):
        py_file = tmp_path / "config.py"
        py_file.write_text(f'AWS_ACCESS_KEY_ID = "{_aws_access_key()}"\n')
        findings = scan_secrets(str(tmp_path))
        secret_types = [f.secret_type for f in findings]
        assert "AWS Access Key ID" in secret_types

    def test_detects_aws_secret_key(self, tmp_path):
        py_file = tmp_path / "config.py"
        py_file.write_text(f'AWS_SECRET = "{py_secrets.token_hex(20)}"\n')
        findings = scan_secrets(str(tmp_path))
        assert len(findings) > 0

    def test_detects_github_token(self, tmp_path):
        py_file = tmp_path / "deploy.py"
        py_file.write_text(f'token = "ghp_{py_secrets.token_hex(20)}"\n')
        findings = scan_secrets(str(tmp_path))
        secret_types = [f.secret_type for f in findings]
        assert "GitHub Token" in secret_types

    def test_detects_stripe_secret_key(self, tmp_path):
        py_file = tmp_path / "payment.py"
        py_file.write_text(f'STRIPE_KEY = "{_stripe_key()}"\n')
        findings = scan_secrets(str(tmp_path))
        assert len(findings) > 0

    def test_detects_private_key(self, tmp_path):
        key_file = tmp_path / "private.pem"
        key_file.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n")
        findings = scan_secrets(str(tmp_path))
        assert len(findings) > 0

    def test_scans_env_files(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text(f'STRIPE_SECRET_KEY={_stripe_key()}\n')
        findings = scan_secrets(str(tmp_path))
        assert len(findings) > 0

    def test_masks_secret_value(self, tmp_path):
        py_file = tmp_path / "config.py"
        access_key = _aws_access_key()
        py_file.write_text(f'AWS_ACCESS_KEY_ID = "{access_key}"\n')
        findings = scan_secrets(str(tmp_path))
        assert len(findings) > 0
        # Value should be masked, not full plaintext
        assert access_key not in findings[0].masked_value
        assert "***" in findings[0].masked_value

    def test_skips_excluded_directories(self, tmp_path):
        venv_dir = tmp_path / "venv" / "lib"
        venv_dir.mkdir(parents=True)
        py_file = venv_dir / "config.py"
        py_file.write_text(f'AWS_ACCESS_KEY_ID = "{_aws_access_key()}"\n')
        findings = scan_secrets(str(tmp_path))
        # Files inside venv/ should be excluded
        assert len(findings) == 0

    def test_returns_file_and_line_number(self, tmp_path):
        py_file = tmp_path / "app.py"
        py_file.write_text(f'x = 1\nAWS_ACCESS_KEY_ID = "{_aws_access_key()}"\ny = 2\n')
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
        # Dynamically generate random 32-char hex token at runtime (no hardcoded credentials)
        dummy_hex = py_secrets.token_hex(16)
        py_file.write_text(f'auth_hash = "{dummy_hex}"\n')
        findings = scan_secrets(str(tmp_path))
        entropy_findings = [f for f in findings if "High-Entropy" in f.secret_type]
        assert len(entropy_findings) > 0

    def test_detects_high_entropy_base64_token(self, tmp_path):
        py_file = tmp_path / "auth.py"
        # Dynamically generate random base64 token at runtime
        dummy_b64 = py_secrets.token_urlsafe(32)
        py_file.write_text(f'payload = "{dummy_b64}"\n')
        findings = scan_secrets(str(tmp_path))
        entropy_findings = [f for f in findings if "High-Entropy" in f.secret_type]
        assert len(entropy_findings) > 0

    def test_suppresses_uuid(self, tmp_path):
        py_file = tmp_path / "models.py"
        # Dynamically generate random UUID
        dummy_uuid = str(uuid.uuid4())
        py_file.write_text(f'session_id = "{dummy_uuid}"\n')
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
        vuln_file.write_text(f'AWS_ACCESS_KEY_ID = "{_aws_access_key()}"\n')

        safe_file = tmp_path / "safe.py"
        safe_file.write_text('x = 42\n')

        # When target_files points only to safe_file, vuln_file must be ignored
        findings = scan_secrets(str(tmp_path), target_files=[str(safe_file)])
        assert len(findings) == 0

        # When target_files points to vuln_file, it is scanned
        findings_vuln = scan_secrets(str(tmp_path), target_files=[str(vuln_file)])
        assert len(findings_vuln) > 0
