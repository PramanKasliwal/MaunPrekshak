"""
Tests for MaunPrekshak Core v0.21.0 — Advanced AST SAST Suite (MP093–MP098).
"""
import ast
from maunprekshak.scanner.sast import SecurityVisitor, is_suppressed


def _scan_code(code: str):
    source_lines = code.splitlines()
    tree = ast.parse(code)
    visitor = SecurityVisitor("test_v021.py", source_lines)
    visitor.visit(tree)
    return [f for f in visitor.findings if not is_suppressed(f, source_lines)]


def test_mp093_tempfile_delete_false():
    code = """
import tempfile

f1 = tempfile.NamedTemporaryFile(delete=False)
f2 = tempfile.NamedTemporaryFile("w+", -1, None, None, None, None, None, False)
"""
    findings = _scan_code(code)
    mp093 = [f for f in findings if f.check_id == "MP093"]
    assert len(mp093) == 2
    for f in mp093:
        assert f.severity == "HIGH"
        assert "NamedTemporaryFile(delete=False)" in f.description


def test_mp093_safe_and_suppression():
    code = """
import tempfile

f1 = tempfile.NamedTemporaryFile()
f2 = tempfile.NamedTemporaryFile(delete=True)
f3 = tempfile.NamedTemporaryFile(delete=False)  # nosec: MP093
"""
    findings = _scan_code(code)
    mp093 = [f for f in findings if f.check_id == "MP093"]
    assert len(mp093) == 0


def test_mp094_pbkdf2_iterations_low():
    code = """
import hashlib

h1 = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 50000)
h2 = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", iterations=1000)
"""
    findings = _scan_code(code)
    mp094 = [f for f in findings if f.check_id == "MP094"]
    assert len(mp094) == 2
    for f in mp094:
        assert f.severity == "HIGH"
        assert "less than 100,000" in f.description


def test_mp094_safe_and_suppression():
    code = """
import hashlib

h1 = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 100000)
h2 = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", iterations=600000)
h3 = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 1000)  # nosec: MP094
"""
    findings = _scan_code(code)
    mp094 = [f for f in findings if f.check_id == "MP094"]
    assert len(mp094) == 0


def test_mp095_render_template_string_ssti():
    code = """
from flask import render_template_string

def greet(user_input):
    s1 = render_template_string(f"Hello {user_input}!")
    s2 = render_template_string("Hello %s!" % user_input)
    s3 = render_template_string("Hello " + user_input)
    s4 = render_template_string("Hello {}!".format(user_input))
"""
    findings = _scan_code(code)
    mp095 = [f for f in findings if f.check_id == "MP095"]
    assert len(mp095) == 4
    for f in mp095:
        assert f.severity == "HIGH"
        assert "Server-Side Template Injection" in f.description


def test_mp095_safe_and_suppression():
    code = """
from flask import render_template_string

def greet(user_input):
    s1 = render_template_string("Hello {{ name }}!", name=user_input)
    s2 = render_template_string(f"Hello {user_input}!")  # nosec: MP095
"""
    findings = _scan_code(code)
    mp095 = [f for f in findings if f.check_id == "MP095"]
    assert len(mp095) == 0


def test_mp096_joblib_load_dynamic_path():
    code = """
import joblib

def load_user_model(path, user):
    m1 = joblib.load(path)
    m2 = joblib.load(f"models/{user}.pkl")
"""
    findings = _scan_code(code)
    mp096 = [f for f in findings if f.check_id == "MP096"]
    assert len(mp096) == 2
    for f in mp096:
        assert f.severity == "HIGH"
        assert "joblib.load" in f.description


def test_mp096_safe_and_suppression():
    code = """
import joblib

def load_model(path):
    m1 = joblib.load(path)  # nosec: MP096
"""
    findings = _scan_code(code)
    mp096 = [f for f in findings if f.check_id == "MP096"]
    assert len(mp096) == 0


def test_mp097_socket_bind_wildcard():
    code = """
import socket

s1 = socket.socket()
s1.bind(("0.0.0.0", 8080))

s2 = socket.socket()
s2.bind(("", 9090))

s3 = socket.socket()
s3.bind(("::", 443))
"""
    findings = _scan_code(code)
    mp097 = [f for f in findings if f.check_id == "MP097"]
    assert len(mp097) == 3
    for f in mp097:
        assert f.severity == "HIGH"
        assert "wildcard address" in f.description


def test_mp097_safe_and_suppression():
    code = """
import socket

s1 = socket.socket()
s1.bind(("127.0.0.1", 8080))
s2 = socket.socket()
s2.bind(("localhost", 9090))
s3 = socket.socket()
s3.bind(("0.0.0.0", 8080))  # nosec: MP097
"""
    findings = _scan_code(code)
    mp097 = [f for f in findings if f.check_id == "MP097"]
    assert len(mp097) == 0


def test_mp098_paramiko_auto_add_policy():
    code = """
import paramiko
from paramiko import AutoAddPolicy

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.set_missing_host_key_policy(AutoAddPolicy())
"""
    findings = _scan_code(code)
    mp098 = [f for f in findings if f.check_id == "MP098"]
    assert len(mp098) == 2
    for f in mp098:
        assert f.severity == "HIGH"
        assert "AutoAddPolicy" in f.description


def test_mp098_safe_and_suppression():
    code = """
import paramiko

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.RejectPolicy())
client.set_missing_host_key_policy(paramiko.WarningPolicy())
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # nosec: MP098
"""
    findings = _scan_code(code)
    mp098 = [f for f in findings if f.check_id == "MP098"]
    assert len(mp098) == 0
