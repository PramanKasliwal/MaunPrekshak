"""
Tests for MaunPrekshak Core v0.15.0 — Advanced SAST Suite (MP056–MP062).
"""
import ast
import tempfile
import os
import pytest

from maunprekshak.scanner.sast import scan_sast, _scan_single_py_file


def _scan_code(code: str):
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(code)
        fname = f.name
    try:
        return _scan_single_py_file(fname)
    finally:
        os.unlink(fname)


def test_mp056_code_module_execution():
    code = """
import code
console = code.InteractiveConsole()
code.InteractiveInterpreter().runsource("print('hello')")
"""
    findings = _scan_code(code)
    mp056 = [f for f in findings if f.check_id == "MP056"]
    assert len(mp056) >= 2
    assert all(f.severity == "HIGH" for f in mp056)


def test_mp056_compile_dynamic_code():
    code = """
source_code = get_user_input()
compiled = compile(source_code, '<string>', 'exec')
"""
    findings = _scan_code(code)
    mp056 = [f for f in findings if f.check_id == "MP056"]
    assert len(mp056) == 1
    assert mp056[0].severity == "HIGH"


def test_mp057_hardcoded_secret_key():
    code = """
app.secret_key = "super-secret-hardcoded-key"
app.config['SECRET_KEY'] = "another-static-secret"
middleware = SessionMiddleware(app, secret_key="static-session-token")
"""
    findings = _scan_code(code)
    mp057 = [f for f in findings if f.check_id == "MP057"]
    assert len(mp057) == 3
    assert all(f.severity == "HIGH" for f in mp057)


def test_mp057_env_var_secret_key_passes():
    code = """
import os
app.secret_key = os.getenv("SECRET_KEY")
app.config['SECRET_KEY'] = os.environ.get("SESSION_SECRET")
"""
    findings = _scan_code(code)
    mp057 = [f for f in findings if f.check_id == "MP057"]
    assert len(mp057) == 0


def test_mp058_shelve_and_marshal():
    code = """
import shelve
import marshal

db = shelve.open("user_data.db")
obj = marshal.loads(raw_untrusted_bytes)
"""
    findings = _scan_code(code)
    mp058 = [f for f in findings if f.check_id == "MP058"]
    assert len(mp058) == 2
    assert all(f.severity == "HIGH" for f in mp058)


def test_mp059_insecure_cookie_flags():
    code = """
response.set_cookie("session", "abc", secure=False, httponly=False)
"""
    findings = _scan_code(code)
    mp059 = [f for f in findings if f.check_id == "MP059"]
    assert len(mp059) >= 1
    assert any(f.severity == "HIGH" for f in mp059)


def test_mp060_disabled_ssl_verification():
    code = """
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
unverified = ssl._create_unverified_context()
"""
    findings = _scan_code(code)
    mp060 = [f for f in findings if f.check_id == "MP060"]
    assert len(mp060) == 3
    assert all(f.severity == "HIGH" for f in mp060)


def test_mp061_graphql_query_injection():
    code = """
query = gql(f"query {{ search(term: '{user_input}') }}")
"""
    findings = _scan_code(code)
    mp061 = [f for f in findings if f.check_id == "MP061"]
    assert len(mp061) == 1
    assert mp061[0].severity == "HIGH"


def test_mp062_insecure_tempfile_path():
    code = """
import os
import tempfile

fpath = os.path.join(tempfile.gettempdir(), "my_app_file.txt")
"""
    findings = _scan_code(code)
    mp062 = [f for f in findings if f.check_id == "MP062"]
    assert len(mp062) == 1
    assert mp062[0].severity == "MEDIUM"


def test_mp057_inline_suppression():
    code = """
app.secret_key = "static-key" # maunprekshak: ignore[MP057]
"""
    findings = _scan_code(code)
    mp057 = [f for f in findings if f.check_id == "MP057"]
    assert len(mp057) == 0
