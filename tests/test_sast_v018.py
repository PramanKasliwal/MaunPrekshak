import ast
from maunprekshak.scanner.sast import SecurityVisitor, is_suppressed


def _scan_code(code: str):
    source_lines = code.splitlines()
    tree = ast.parse(code)
    visitor = SecurityVisitor("test_v018.py", source_lines)
    visitor.visit(tree)
    return [f for f in visitor.findings if not is_suppressed(f, source_lines)]


def test_mp075_unsafe_reflection():
    code = """
def update_profile(user_obj, request):
    attr = request.args.get("field")
    return getattr(user_obj, attr)
"""
    findings = _scan_code(code)
    mp075 = [f for f in findings if f.check_id == "MP075"]
    assert len(mp075) >= 1
    assert mp075[0].severity == "HIGH"


def test_mp075_safe_reflection():
    code = """
def get_severity(item):
    return getattr(item, "severity", "LOW")
"""
    findings = _scan_code(code)
    mp075 = [f for f in findings if f.check_id == "MP075"]
    assert len(mp075) == 0


def test_mp076_weak_key_generation():
    code = """
import paramiko

def create_key():
    return paramiko.RSAKey.generate(1024)
"""
    findings = _scan_code(code)
    mp076 = [f for f in findings if f.check_id == "MP076"]
    assert len(mp076) == 1
    assert mp076[0].severity == "HIGH"
    assert "1024 bits" in mp076[0].description


def test_mp076_strong_key_safe():
    code = """
import paramiko

def create_key():
    return paramiko.RSAKey.generate(2048)
"""
    findings = _scan_code(code)
    mp076 = [f for f in findings if f.check_id == "MP076"]
    assert len(mp076) == 0


def test_mp077_check_hostname_disabled():
    code = """
import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
"""
    findings = _scan_code(code)
    mp077 = [f for f in findings if f.check_id == "MP077"]
    assert len(mp077) == 1
    assert mp077[0].severity == "HIGH"


def test_mp077_check_hostname_safe():
    code = """
import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = True
"""
    findings = _scan_code(code)
    mp077 = [f for f in findings if f.check_id == "MP077"]
    assert len(mp077) == 0


def test_mp078_code_interactive_interpreter():
    code = """
import code

def run_user_code(user_snippet):
    interpreter = code.InteractiveInterpreter()
    interpreter.runsource(user_snippet)
"""
    findings = _scan_code(code)
    mp078 = [f for f in findings if f.check_id == "MP078"]
    assert len(mp078) == 1
    assert mp078[0].severity == "HIGH"


def test_mp079_tmp_path_formatting():
    code = """
import os

def write_cache(filename, data):
    path = f"/tmp/{filename}"
    join_path = os.path.join("/tmp", filename)
"""
    findings = _scan_code(code)
    mp079 = [f for f in findings if f.check_id == "MP079"]
    assert len(mp079) == 2
    assert all(f.severity == "HIGH" for f in mp079)


def test_mp080_celery_pickle():
    code = """
from celery import Celery

app = Celery('tasks')
app.conf.task_serializer = 'pickle'
app.conf.update(accept_content=['pickle'])
"""
    findings = _scan_code(code)
    mp080 = [f for f in findings if f.check_id == "MP080"]
    assert len(mp080) == 2
    assert all(f.severity == "CRITICAL" for f in mp080)


def test_mp080_celery_json_safe():
    code = """
from celery import Celery

app = Celery('tasks')
app.conf.task_serializer = 'json'
app.conf.update(accept_content=['json'])
"""
    findings = _scan_code(code)
    mp080 = [f for f in findings if f.check_id == "MP080"]
    assert len(mp080) == 0
