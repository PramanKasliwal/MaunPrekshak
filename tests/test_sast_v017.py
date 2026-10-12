"""
Tests for MaunPrekshak Core v0.17.0 — Advanced AST SAST Scanner Phase 6.
Tests MP069 (Jinja2 autoescape=False), MP070 (eval/exec in comprehension/lambda),
MP071 (Cleartext FTP/Telnet protocol), MP072 (MongoDB $where injection),
MP073 (Flask debug on 0.0.0.0), MP074 (IPC Listener without authkey).
"""
import ast
import pytest
from maunprekshak.scanner.sast import SecurityVisitor


def check_source(source: str):
    source_lines = source.splitlines()
    tree = ast.parse(source)
    visitor = SecurityVisitor("test_file.py", source_lines)
    visitor.visit(tree)
    return visitor.findings


def test_mp069_jinja2_autoescape_disabled():
    src = """
import jinja2
env = jinja2.Environment(autoescape=False)
"""
    findings = check_source(src)
    assert any(f.check_id == "MP069" for f in findings)
    assert any(f.severity == "HIGH" for f in findings)


def test_mp070_eval_in_comprehension():
    src = """
items = ["1+1", "2+2"]
res = [eval(x) for x in items]
"""
    findings = check_source(src)
    assert any(f.check_id == "MP070" for f in findings)
    assert any(f.severity == "HIGH" for f in findings)


def test_mp070_exec_in_lambda():
    src = """
runner = lambda code: exec(code)
"""
    findings = check_source(src)
    assert any(f.check_id == "MP070" for f in findings)


def test_mp071_cleartext_ftp_and_telnet():
    src = """
import ftplib
import telnetlib

ftp = ftplib.FTP("ftp.example.com")
tn = telnetlib.Telnet("telnet.example.com")
"""
    findings = check_source(src)
    check_ids = [f.check_id for f in findings]
    assert check_ids.count("MP071") >= 2


def test_mp072_mongodb_where_injection():
    src = """
user_val = "admin"
query = {"$where": f"this.name == '{user_val}'"}
collection.find(query)
"""
    findings = check_source(src)
    assert any(f.check_id == "MP072" for f in findings)


def test_mp073_flask_debug_on_open_host():
    src = """
from flask import Flask
app = Flask(__name__)
app.run(host="0.0.0.0", debug=True)
"""
    findings = check_source(src)
    assert any(f.check_id == "MP073" for f in findings)
    mp073 = next(f for f in findings if f.check_id == "MP073")
    assert mp073.severity == "MEDIUM"


def test_mp074_ipc_listener_without_authkey():
    src = """
from multiprocessing.connection import Listener
listener = Listener(address=('localhost', 6000))
"""
    findings = check_source(src)
    assert any(f.check_id == "MP074" for f in findings)
    mp074 = next(f for f in findings if f.check_id == "MP074")
    assert mp074.severity == "HIGH"


def test_mp069_to_mp074_safe_or_suppressed():
    src = """
import jinja2
from multiprocessing.connection import Listener
import secrets

env = jinja2.Environment(autoescape=True)
listener = Listener(address=('localhost', 6000), authkey=secrets.token_bytes(32))
"""
    findings = check_source(src)
    check_ids = [f.check_id for f in findings]
    assert "MP069" not in check_ids
    assert "MP074" not in check_ids
