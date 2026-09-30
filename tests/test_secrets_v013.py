"""
Tests for MaunPrekshak Core v0.13.0 — Enterprise Cloud Secrets (MP-SEC-021 through MP-SEC-026).
"""
import re
import secrets
import pytest
from maunprekshak.scanner.secrets import scan_file_for_secrets, SECRET_PATTERNS


@pytest.fixture
def compiled_patterns():
    return {k: re.compile(v) for k, v in SECRET_PATTERNS.items()}


def test_gcp_service_account_detection(tmp_path, compiled_patterns):
    test_file = tmp_path / "gcp_creds.json"
    content = '{\n  "type": "service_account",\n  "project_id": "corp-prod-1"\n}\n'
    test_file.write_text(content)

    findings = scan_file_for_secrets(str(test_file), compiled_patterns)
    assert any(f.secret_type == "GCP Service Account Key" for f in findings)


def test_azure_storage_connection_string(tmp_path, compiled_patterns):
    test_file = tmp_path / "azure.env"
    key_part = "A" * 86
    conn_str = f"DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey={key_part}"
    test_file.write_text(f"AZURE_STORAGE_CONNECTION_STRING={conn_str}\n")

    findings = scan_file_for_secrets(str(test_file), compiled_patterns)
    assert any(f.secret_type == "Azure Storage Connection String" for f in findings)


def test_azure_sas_token(tmp_path, compiled_patterns):
    test_file = tmp_path / "deploy.py"
    sas = "https://mystorage.blob.core.windows.net/data?sv=2021-06-08&ss=bfqt&srt=sco&sp=rwdlacup&se=2026-10-01&sig=" + ("X" * 44)
    test_file.write_text(f'BLOB_URL = "{sas}"\n')

    findings = scan_file_for_secrets(str(test_file), compiled_patterns)
    assert any(f.secret_type == "Azure SAS Token" for f in findings)


def test_github_copilot_or_app_token(tmp_path, compiled_patterns):
    test_file = tmp_path / "gh_app.py"
    token = "ghu_" + ("1" * 36)
    test_file.write_text(f'APP_TOKEN = "{token}"\n')

    findings = scan_file_for_secrets(str(test_file), compiled_patterns)
    assert any(f.secret_type == "GitHub Copilot / App Token" for f in findings)


def test_kubernetes_service_account_token(tmp_path, compiled_patterns):
    test_file = tmp_path / "k8s_client.py"
    header = "bearer "
    token_jwt = "eyJh" + ("A" * 60)
    test_file.write_text(f'AUTH_HEADER = "{header}{token_jwt}"\n')

    findings = scan_file_for_secrets(str(test_file), compiled_patterns)
    assert any(f.secret_type == "Kubernetes Service Account Token" for f in findings)


def test_databricks_api_token(tmp_path, compiled_patterns):
    test_file = tmp_path / "spark.py"
    dapi = "dapi" + ("a" * 32)
    test_file.write_text(f'DATABRICKS_TOKEN = "{dapi}"\n')

    findings = scan_file_for_secrets(str(test_file), compiled_patterns)
    assert any(f.secret_type == "Databricks API Token" for f in findings)
