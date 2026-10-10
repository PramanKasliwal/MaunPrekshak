import os
import tempfile
import pytest
from maunprekshak.scanner.sast import scan_sast


def _scan_snippet(code: str):
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(code)
        path = f.name
    try:
        return scan_sast(os.path.dirname(path), target_files=[path])
    finally:
        os.unlink(path)


def test_mp063_jwt_verify_signature_disabled():
    code = """
import jwt

payload = jwt.decode(token, key, options={"verify_signature": False})
"""
    findings = _scan_snippet(code)
    ids = [f.check_id for f in findings]
    assert "MP063" in ids
    assert any("verify_signature" in f.description for f in findings)


def test_mp063_jwt_none_algorithm():
    code = """
import jwt

payload = jwt.decode(token, key, algorithms=["none"])
"""
    findings = _scan_snippet(code)
    ids = [f.check_id for f in findings]
    assert "MP063" in ids
    assert any("none" in f.description for f in findings)


def test_mp064_zip_slip_extraction():
    code = """
import zipfile

with zipfile.ZipFile("archive.zip") as zf:
    zf.extractall("/tmp/extracted")
"""
    findings = _scan_snippet(code)
    ids = [f.check_id for f in findings]
    assert "MP064" in ids


def test_mp065_insecure_temp_dir():
    code = """
import os

os.mkdir("/tmp/my_app_cache")
os.makedirs("/var/tmp/upload_dir")
"""
    findings = _scan_snippet(code)
    ids = [f.check_id for f in findings]
    assert "MP065" in ids


def test_mp066_raw_sql_orm_injection():
    code = """
from sqlalchemy import text

stmt = text(f"SELECT * FROM users WHERE username = '{user_input}'")
"""
    findings = _scan_snippet(code)
    ids = [f.check_id for f in findings]
    assert "MP066" in ids


def test_mp067_subprocess_shell_true_dynamic():
    code = """
import subprocess

user_cmd = get_input()
subprocess.run(f"echo {user_cmd}", shell=True)
"""
    findings = _scan_snippet(code)
    ids = [f.check_id for f in findings]
    assert "MP067" in ids


def test_mp068_insecure_yaml_full_loader():
    code = """
import yaml

data = yaml.load(content, Loader=yaml.FullLoader)
"""
    findings = _scan_snippet(code)
    ids = [f.check_id for f in findings]
    assert "MP068" in ids
