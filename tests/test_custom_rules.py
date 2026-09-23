"""
Tests for the MaunPrekshak Custom Rule Engine
"""
import os
import secrets
import tempfile
from maunprekshak.scanner.custom_rules import (
    load_custom_rules,
    evaluate_custom_secrets,
    evaluate_custom_sast,
    CustomSecretRule,
    CustomSASTRule,
    CustomRulesConfig,
)
from maunprekshak.scanner.report import Severity


def test_custom_secret_detection():
    # Dynamically generate mock internal token
    dyn_token = f"acme_corp_{secrets.token_hex(16)}"
    code = f'INTERNAL_TOKEN = "{dyn_token}"\n'

    rule = CustomSecretRule(
        id="ACME-001",
        name="Acme Internal Token",
        regex=r"acme_corp_[0-9a-f]{32}",
        severity=Severity.HIGH.value,
    )
    findings = evaluate_custom_secrets("src/auth.py", code, [rule])

    assert len(findings) == 1
    assert findings[0].file_path == "src/auth.py"
    assert findings[0].line == 1
    assert "ACME-001" in findings[0].secret_type
    assert findings[0].severity == "HIGH"
    assert "***" in findings[0].masked_value


def test_custom_secret_suppression():
    dyn_token = f"acme_corp_{secrets.token_hex(16)}"
    code = f'TOKEN = "{dyn_token}"  # maunprekshak: ignore\n'

    rule = CustomSecretRule(
        id="ACME-001",
        name="Acme Internal Token",
        regex=r"acme_corp_[0-9a-f]{32}",
    )
    findings = evaluate_custom_secrets("src/auth.py", code, [rule])
    assert len(findings) == 0


def test_custom_sast_banned_call():
    code = """
import os
def run(cmd):
    os.system(cmd)
"""
    rule = CustomSASTRule(
        id="CUST-001",
        name="Banned os.system Call",
        severity=Severity.HIGH.value,
        description="os.system is prohibited; use subprocess.run with shell=False.",
        banned_calls=["os.system"],
    )
    findings = evaluate_custom_sast("script.py", code, [rule])
    assert len(findings) == 1
    assert findings[0].check_id == "CUST-001"
    assert findings[0].line == 4
    assert findings[0].severity == "HIGH"


def test_custom_sast_banned_import():
    code = """
import telnetlib
import my_legacy_crypto
"""
    rule = CustomSASTRule(
        id="CUST-002",
        name="Banned Insecure Import",
        severity=Severity.CRITICAL.value,
        banned_imports=["telnetlib", "my_legacy_crypto"],
    )
    findings = evaluate_custom_sast("net.py", code, [rule])
    assert len(findings) == 2
    assert {f.line for f in findings} == {2, 3}


def test_custom_sast_regex_pattern():
    code = "DEBUG_PASSWORD_LOG = True\n"
    rule = CustomSASTRule(
        id="CUST-003",
        name="Debug Password Logging",
        regex_patterns=[r"DEBUG_PASSWORD_LOG\s*=\s*True"],
    )
    findings = evaluate_custom_sast("settings.py", code, [rule])
    assert len(findings) == 1
    assert findings[0].check_id == "CUST-003"


def test_load_custom_rules_yaml():
    yaml_content = """
custom_rules:
  secrets:
    - id: "ORG-001"
      name: "Org Key"
      regex: "org_secret_[0-9a-z]{16}"
      severity: "critical"
  sast:
    - id: "ORG-002"
      name: "No Raw Eval"
      severity: "high"
      banned_calls: ["eval"]
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(yaml_content)
        temp_path = f.name

    try:
        config = load_custom_rules(temp_path)
        assert len(config.secrets) == 1
        assert config.secrets[0].id == "ORG-001"
        assert config.secrets[0].severity == "CRITICAL"
        assert len(config.sast) == 1
        assert config.sast[0].id == "ORG-002"
        assert config.sast[0].banned_calls == ["eval"]
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
