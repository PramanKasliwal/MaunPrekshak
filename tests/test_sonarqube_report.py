import json
import pytest
from typer.testing import CliRunner
from maunprekshak.cli.main import app
from maunprekshak.scanner.report import (
    ScanResult,
    SASTFinding,
    SecretFinding,
    DepVulnerability,
    to_sonarqube,
    to_codeclimate,
)


@pytest.fixture
def sample_scan_result():
    sast = [
        SASTFinding(
            file_path="src/app.py",
            line=12,
            col=5,
            check_id="MP001",
            severity="CRITICAL",
            description="eval() usage detected",
            recommendation="Avoid eval()",
            code_snippet="eval(user_input)",
        ),
        SASTFinding(
            file_path="src/infra.tf",
            line=40,
            col=1,
            check_id="TF005",
            severity="CRITICAL",
            description="Publicly accessible database",
            recommendation="Set publicly_accessible = false",
            code_snippet="publicly_accessible = true",
        ),
    ]
    secrets = [
        SecretFinding(
            file_path="config.py",
            line=5,
            secret_type="GitHub Token",
            masked_value="ghp_***1234",
            severity="HIGH",
        )
    ]
    deps = [
        DepVulnerability(
            package="requests",
            version="2.19.0",
            cve_id="CVE-2018-18074",
            severity="HIGH",
            cvss_score=7.5,
            description="Credentials leak on redirect",
            fix_version="2.20.0",
        )
    ]
    return ScanResult(sast=sast, secrets=secrets, deps=deps)


def test_to_sonarqube_schema(sample_scan_result):
    json_str = to_sonarqube(sample_scan_result, project_root=".")
    data = json.loads(json_str)

    assert "issues" in data
    assert len(data["issues"]) == 4

    issue0 = data["issues"][0]
    assert issue0["engineId"] == "maunprekshak"
    assert issue0["ruleId"] == "MP001"
    assert issue0["severity"] == "BLOCKER"  # CRITICAL -> BLOCKER
    assert issue0["type"] == "VULNERABILITY"
    assert "textRange" in issue0["primaryLocation"]
    assert issue0["primaryLocation"]["textRange"]["startLine"] == 12
    assert issue0["primaryLocation"]["textRange"]["endLine"] == 12
    assert issue0["effortMinutes"] == 30

    secret_issue = next(i for i in data["issues"] if "SECRET" in i["ruleId"])
    assert secret_issue["severity"] == "BLOCKER"

    dep_issue = next(i for i in data["issues"] if i["ruleId"] == "CVE-2018-18074")
    assert dep_issue["severity"] == "CRITICAL"  # HIGH -> CRITICAL


def test_to_codeclimate_schema(sample_scan_result):
    json_str = to_codeclimate(sample_scan_result, project_root=".")
    data = json.loads(json_str)

    assert isinstance(data, list)
    assert len(data) == 4

    issue0 = data[0]
    assert issue0["type"] == "issue"
    assert issue0["check_name"] == "MP001"
    assert issue0["severity"] == "blocker"
    assert issue0["categories"] == ["Security"]
    assert issue0["location"]["path"] == "src/app.py"
    assert issue0["location"]["lines"]["begin"] == 12
    assert len(issue0["fingerprint"]) == 64  # SHA256 hex string
    assert issue0["remediation_points"] == 100000


def test_cli_sonarqube_and_codeclimate_output(tmp_path):
    runner = CliRunner()
    app_file = tmp_path / "app.py"
    app_file.write_text("print('clean code')\n")

    sonar_file = tmp_path / "sonar.json"
    res_sonar = runner.invoke(app, ["scan", str(tmp_path), "--output", "sonarqube", "--output-file", str(sonar_file), "--no-ai"])
    assert res_sonar.exit_code == 0
    assert sonar_file.exists()
    sonar_data = json.loads(sonar_file.read_text())
    assert "issues" in sonar_data

    cc_file = tmp_path / "cc.json"
    res_cc = runner.invoke(app, ["scan", str(tmp_path), "--output", "codeclimate", "--output-file", str(cc_file), "--no-ai"])
    assert res_cc.exit_code == 0
    assert cc_file.exists()
    cc_data = json.loads(cc_file.read_text())
    assert isinstance(cc_data, list)
