import os
import pytest
from maunprekshak.scanner.fixer import fix_file_findings, apply_auto_fixes
from maunprekshak.scanner.report import SASTFinding, ScanResult, aggregate


def test_fix_mp031_torch_load(tmp_path):
    py_file = tmp_path / "model.py"
    py_file.write_text('model = torch.load("weights.pth")\n')

    findings = [
        SASTFinding(
            file_path=str(py_file),
            line=1,
            col=9,
            check_id="MP031",
            severity="CRITICAL",
            description="torch.load() without weights_only=True",
            recommendation="Use weights_only=True",
            code_snippet='model = torch.load("weights.pth")',
        )
    ]

    fixed = fix_file_findings(str(py_file), findings)
    assert fixed == 1
    content = py_file.read_text()
    assert 'torch.load("weights.pth", weights_only=True)' in content


def test_fix_mp031_torch_load_weights_only_false(tmp_path):
    py_file = tmp_path / "model2.py"
    py_file.write_text('model = torch.load("weights.pth", weights_only=False)\n')

    findings = [
        SASTFinding(
            file_path=str(py_file),
            line=1,
            col=9,
            check_id="MP031",
            severity="CRITICAL",
            description="torch.load() with weights_only=False",
            recommendation="Use weights_only=True",
            code_snippet='model = torch.load("weights.pth", weights_only=False)',
        )
    ]

    fixed = fix_file_findings(str(py_file), findings)
    assert fixed == 1
    content = py_file.read_text()
    assert 'weights_only=True' in content
    assert 'weights_only=False' not in content


def test_fix_mp036_unsafe_yaml(tmp_path):
    py_file = tmp_path / "config.py"
    py_file.write_text(
        'data1 = yaml.unsafe_load(stream)\n'
        'data2 = yaml.load(stream, Loader=yaml.Loader)\n'
        'data3 = yaml.load(stream, Loader=yaml.UnsafeLoader)\n'
    )

    findings = [
        SASTFinding(str(py_file), 1, 1, "MP036", "HIGH", "unsafe_load", "safe_load"),
        SASTFinding(str(py_file), 2, 1, "MP036", "HIGH", "unsafe Loader", "SafeLoader"),
        SASTFinding(str(py_file), 3, 1, "MP036", "HIGH", "unsafe Loader", "SafeLoader"),
    ]

    fixed = fix_file_findings(str(py_file), findings)
    assert fixed == 3
    content = py_file.read_text()
    assert "yaml.safe_load(stream)" in content
    assert "Loader=yaml.SafeLoader" in content
    assert "yaml.unsafe_load" not in content
    assert "Loader=yaml.Loader" not in content
    assert "Loader=yaml.UnsafeLoader" not in content


def test_fix_mp033_permissive_chmod(tmp_path):
    py_file = tmp_path / "perms.py"
    py_file.write_text('os.chmod("/tmp/secret", 0o777)\nos.chmod("/tmp/data", 0o666)\n')

    findings = [
        SASTFinding(str(py_file), 1, 1, "MP033", "MEDIUM", "chmod 0o777", "0o700"),
        SASTFinding(str(py_file), 2, 1, "MP033", "MEDIUM", "chmod 0o666", "0o600"),
    ]

    fixed = fix_file_findings(str(py_file), findings)
    assert fixed == 2
    content = py_file.read_text()
    assert "0o700" in content
    assert "0o600" in content
    assert "0o777" not in content
    assert "0o666" not in content


def test_fix_mp015_disabled_ssl(tmp_path):
    py_file = tmp_path / "api_client.py"
    py_file.write_text('resp = requests.get("https://internal.api", verify=False)\n')

    findings = [
        SASTFinding(str(py_file), 1, 1, "MP015", "HIGH", "verify=False", "verify=True"),
    ]

    fixed = fix_file_findings(str(py_file), findings)
    assert fixed == 1
    content = py_file.read_text()
    assert "verify=True" in content
    assert "verify=False" not in content


def test_fix_tf004_tf005_tf006(tmp_path):
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(
        'resource "aws_db_instance" "db" {\n'
        '  storage_encrypted = false\n'
        '  publicly_accessible = true\n'
        '}\n'
        'resource "aws_s3_bucket_public_access_block" "block" {\n'
        '  block_public_acls = false\n'
        '}\n'
    )

    findings = [
        SASTFinding(str(tf_file), 2, 1, "TF004", "HIGH", "unencrypted", "encrypt"),
        SASTFinding(str(tf_file), 3, 1, "TF005", "CRITICAL", "publicly accessible", "private"),
        SASTFinding(str(tf_file), 6, 1, "TF006", "MEDIUM", "block disabled", "enable"),
    ]

    fixed = fix_file_findings(str(tf_file), findings)
    assert fixed == 3
    content = tf_file.read_text()
    assert "storage_encrypted = true" in content
    assert "publicly_accessible = false" in content
    assert "block_public_acls = true" in content


def test_fix_df002_dockerfile_user(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM python:3.11-slim\nWORKDIR /app\nCOPY . .\nCMD [\"python\", \"app.py\"]\n")

    findings = [
        SASTFinding(str(df), 1, 1, "DF002", "MEDIUM", "missing user", "add user"),
    ]

    fixed = fix_file_findings(str(df), findings)
    assert fixed == 1
    content = df.read_text()
    lines = content.splitlines()
    assert "USER 10001:10001" in lines
    # Verify USER comes before CMD
    user_idx = lines.index("USER 10001:10001")
    cmd_idx = next(i for i, l in enumerate(lines) if "CMD" in l)
    assert user_idx < cmd_idx


def test_apply_auto_fixes_integration(tmp_path):
    py_file = tmp_path / "script.py"
    py_file.write_text('os.chmod("/tmp/run", 0o777)\n')

    finding = SASTFinding(str(py_file), 1, 1, "MP033", "MEDIUM", "chmod 0o777", "0o700")
    scan_res = ScanResult(sast=[finding])
    scan_res.risk_score = aggregate([], [], [finding]).risk_score

    initial_score = scan_res.risk_score.score
    count, updated_res = apply_auto_fixes(scan_res)

    assert count == 1
    assert len(updated_res.sast) == 0
    assert updated_res.risk_score.score < initial_score
    assert "0o700" in py_file.read_text()
