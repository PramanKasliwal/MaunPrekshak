"""
Tests for MaunPrekshak Core v0.22.0 — Advanced AST SAST Suite (MP099–MP104).
"""
import ast
from maunprekshak.scanner.sast import SecurityVisitor, is_suppressed


def _scan_code(code: str):
    source_lines = code.splitlines()
    tree = ast.parse(code)
    visitor = SecurityVisitor("test_v022.py", source_lines)
    visitor.visit(tree)
    return [f for f in visitor.findings if not is_suppressed(f, source_lines)]


def test_mp099_rsa_small_public_exponent():
    code = """
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.PublicKey import RSA

key1 = rsa.generate_private_key(public_exponent=3, key_size=2048)
key2 = RSA.generate(2048, e=3)
key3 = rsa.generate_private_key(3, 2048)
"""
    findings = _scan_code(code)
    mp099 = [f for f in findings if f.check_id == "MP099"]
    assert len(mp099) == 3
    for f in mp099:
        assert f.severity == "HIGH"
        assert "exponent less than 65537" in f.description.lower() or "exponent" in f.description.lower()


def test_mp099_safe_exponent():
    code = """
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.PublicKey import RSA

key1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
key2 = RSA.generate(2048, e=65537)
key3 = rsa.generate_private_key(public_exponent=3, key_size=2048) # nosec: MP099
"""
    findings = _scan_code(code)
    mp099 = [f for f in findings if f.check_id == "MP099"]
    assert len(mp099) == 0


def test_mp100_insecure_cookie_configuration():
    code = """
SESSION_COOKIE_HTTPONLY = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_HTTPONLY = False
app.config['SESSION_COOKIE_HTTPONLY'] = False
response.set_cookie('auth_token', 'value', httponly=False)
"""
    findings = _scan_code(code)
    mp100 = [f for f in findings if f.check_id == "MP100"]
    assert len(mp100) == 5
    for f in mp100:
        assert f.severity == "HIGH"
        assert "cookie" in f.description.lower()


def test_mp100_safe_cookie_configuration():
    code = """
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
response.set_cookie('auth_token', 'value', httponly=True, secure=True)
SESSION_COOKIE_HTTPONLY = False # nosec: MP100
"""
    findings = _scan_code(code)
    mp100 = [f for f in findings if f.check_id == "MP100"]
    assert len(mp100) == 0


def test_mp101_pandas_read_sql_injection():
    code = """
import pandas as pd

table = "users"
user_id = 42
df1 = pd.read_sql(f"SELECT * FROM {table} WHERE id = {user_id}", conn)
df2 = pd.read_sql_query("SELECT * FROM orders WHERE id = " + str(user_id), conn)
df3 = pd.read_sql("SELECT * FROM items WHERE name = '{}'".format("book"), conn)
"""
    findings = _scan_code(code)
    mp101 = [f for f in findings if f.check_id == "MP101"]
    assert len(mp101) == 3
    for f in mp101:
        assert f.severity == "HIGH"
        assert "sql injection" in f.description.lower()


def test_mp101_safe_pandas_read_sql():
    code = """
import pandas as pd

query = "SELECT * FROM users WHERE id = %(id)s"
df1 = pd.read_sql(query, conn, params={"id": 42})
df2 = pd.read_sql_query("SELECT * FROM orders", conn)
df3 = pd.read_sql(f"SELECT * FROM {table}", conn) # nosec: MP101
"""
    findings = _scan_code(code)
    mp101 = [f for f in findings if f.check_id == "MP101"]
    assert len(mp101) == 0


def test_mp102_predictable_random_seed():
    code = """
import random
import time

random.seed(42)
random.seed(12345)
random.seed(int(time.time()))
random.seed("constant_seed")
"""
    findings = _scan_code(code)
    mp102 = [f for f in findings if f.check_id == "MP102"]
    assert len(mp102) == 4
    for f in mp102:
        assert f.severity == "HIGH"
        assert "prng" in f.description.lower() or "random" in f.description.lower()


def test_mp102_safe_random():
    code = """
import random
import secrets

token = secrets.token_hex(16)
num = secrets.randbelow(100)
val = random.random()
random.seed(42) # nosec: MP102
"""
    findings = _scan_code(code)
    mp102 = [f for f in findings if f.check_id == "MP102"]
    assert len(mp102) == 0


def test_mp103_insecure_yaml_dump():
    code = """
import yaml
from yaml import Dumper

data = {"key": "value"}
yaml.dump(data, Dumper=yaml.Dumper)
yaml.dump(data, Dumper=Dumper)
"""
    findings = _scan_code(code)
    mp103 = [f for f in findings if f.check_id == "MP103"]
    assert len(mp103) == 2
    for f in mp103:
        assert f.severity == "HIGH"
        assert "yaml.dump" in f.description.lower() or "yaml" in f.description.lower()


def test_mp103_safe_yaml_dump():
    code = """
import yaml

data = {"key": "value"}
yaml.safe_dump(data)
yaml.dump(data, Dumper=yaml.SafeDumper)
yaml.dump(data, Dumper=yaml.Dumper) # nosec: MP103
"""
    findings = _scan_code(code)
    mp103 = [f for f in findings if f.check_id == "MP103"]
    assert len(mp103) == 0


def test_mp104_shutil_unpack_archive():
    code = """
import shutil

shutil.unpack_archive("untrusted.zip", "/tmp/extracted")
shutil.unpack_archive("archive.tar.gz")
"""
    findings = _scan_code(code)
    mp104 = [f for f in findings if f.check_id == "MP104"]
    assert len(mp104) == 2
    for f in mp104:
        assert f.severity == "HIGH"
        assert "zip slip" in f.description.lower() or "path traversal" in f.description.lower()


def test_mp104_safe_unpack_archive():
    code = """
import shutil

shutil.unpack_archive("untrusted.zip", "/tmp/extracted") # nosec: MP104
"""
    findings = _scan_code(code)
    mp104 = [f for f in findings if f.check_id == "MP104"]
    assert len(mp104) == 0
