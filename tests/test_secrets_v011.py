import re
import secrets
import pytest
from maunprekshak.scanner.secrets import scan_file_for_secrets, SECRET_PATTERNS


@pytest.fixture
def compiled_patterns():
    return {k: re.compile(v) for k, v in SECRET_PATTERNS.items()}


def test_pypi_token_detection(tmp_path, compiled_patterns):
    test_file = tmp_path / "deploy.py"
    # Construct dynamically to avoid static scanner match on test file
    token = "pypi-" + secrets.token_hex(30)
    test_file.write_text(f'PYPI_PASSWORD = "{token}"\n')

    findings = scan_file_for_secrets(str(test_file), compiled_patterns)
    assert any(f.secret_type == "PyPI API Token" for f in findings)


def test_npm_token_detection(tmp_path, compiled_patterns):
    test_file = tmp_path / "npm_auth.sh"
    # 36 hex chars after npm_
    token = "npm_" + secrets.token_hex(18)
    test_file.write_text(f'export NPM_TOKEN="{token}"\n')

    findings = scan_file_for_secrets(str(test_file), compiled_patterns)
    assert any(f.secret_type == "NPM Access Token" for f in findings)


def test_openai_project_key_detection(tmp_path, compiled_patterns):
    test_file = tmp_path / "ai.py"
    token = "sk-proj-" + secrets.token_hex(25)
    test_file.write_text(f'OPENAI_API_KEY = "{token}"\n')

    findings = scan_file_for_secrets(str(test_file), compiled_patterns)
    assert any(f.secret_type == "OpenAI API Key" for f in findings)


def test_anthropic_admin_key_detection(tmp_path, compiled_patterns):
    test_file = tmp_path / "claude.py"
    token = "sk-ant-admin" + secrets.token_hex(20)
    test_file.write_text(f'ANTHROPIC_KEY = "{token}"\n')

    findings = scan_file_for_secrets(str(test_file), compiled_patterns)
    assert any(f.secret_type == "Anthropic API Key" for f in findings)


def test_postman_api_key_detection(tmp_path, compiled_patterns):
    test_file = tmp_path / "postman.env"
    token = "PMAK-" + ("a" * 24) + "-" + ("b" * 34)
    test_file.write_text(f'API_KEY={token}\n')

    findings = scan_file_for_secrets(str(test_file), compiled_patterns)
    assert any(f.secret_type == "Postman API Key" for f in findings)


def test_supabase_key_detection(tmp_path, compiled_patterns):
    test_file = tmp_path / "supabase.env"
    token = "sbp_" + secrets.token_hex(25)
    test_file.write_text(f'SUPABASE_SERVICE_ROLE="{token}"\n')

    findings = scan_file_for_secrets(str(test_file), compiled_patterns)
    assert any(f.secret_type == "Supabase Key" for f in findings)


def test_suppressed_modern_secret(tmp_path, compiled_patterns):
    test_file = tmp_path / "safe.py"
    token = "pypi-" + secrets.token_hex(30)
    test_file.write_text(f'TOKEN = "{token}" # nosec\n')

    findings = scan_file_for_secrets(str(test_file), compiled_patterns)
    assert len(findings) == 0
