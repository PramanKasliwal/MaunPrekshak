"""
Tests for MaunPrekshak Core v0.20.0 — Advanced AST SAST Suite (MP087–MP092).
"""
import ast
from maunprekshak.scanner.sast import SecurityVisitor, is_suppressed


def _scan_code(code: str):
    source_lines = code.splitlines()
    tree = ast.parse(code)
    visitor = SecurityVisitor("test_v020.py", source_lines)
    visitor.visit(tree)
    return [f for f in visitor.findings if not is_suppressed(f, source_lines)]


def test_mp087_re_debug_flag():
    code = """
import re

pat1 = re.compile(r"^[a-z]+$", re.DEBUG)
pat2 = re.search(r"foo", "bar", flags=re.IGNORECASE | re.DEBUG)
"""
    findings = _scan_code(code)
    mp087 = [f for f in findings if f.check_id == "MP087"]
    assert len(mp087) == 2
    for f in mp087:
        assert f.severity == "HIGH"
        assert "re.DEBUG" in f.description


def test_mp087_safe_and_suppression():
    code = """
import re

pat1 = re.compile(r"^[a-z]+$", re.IGNORECASE)
pat2 = re.compile(r"^[a-z]+$", re.DEBUG)  # nosec: MP087
"""
    findings = _scan_code(code)
    mp087 = [f for f in findings if f.check_id == "MP087"]
    assert len(mp087) == 0


def test_mp088_asyncio_subprocess_shell_dynamic():
    code = """
import asyncio

async def run_command(user_input):
    proc = await asyncio.create_subprocess_shell(f"echo {user_input}")
    cmd = "ls " + user_input
    await asyncio.create_subprocess_shell(cmd)
"""
    findings = _scan_code(code)
    mp088 = [f for f in findings if f.check_id == "MP088"]
    assert len(mp088) == 2
    for f in mp088:
        assert f.severity == "HIGH"
        assert "asyncio.create_subprocess_shell" in f.description


def test_mp088_safe_and_suppression():
    code = """
import asyncio

async def run_safe(cmd):
    await asyncio.create_subprocess_exec("echo", "hello")
    await asyncio.create_subprocess_shell(f"echo {cmd}")  # nosec: MP088
"""
    findings = _scan_code(code)
    mp088 = [f for f in findings if f.check_id == "MP088"]
    assert len(mp088) == 0


def test_mp089_cursor_execute_pragma_fstring():
    code = """
def check_db(cursor, table_name):
    cursor.execute(f"PRAGMA table_info({table_name})")
    cursor.execute(f"SELECT * FROM {table_name}")
"""
    findings = _scan_code(code)
    mp089 = [f for f in findings if f.check_id == "MP089"]
    assert len(mp089) == 2
    for f in mp089:
        assert f.severity == "HIGH"
        assert "cursor.execute" in f.description


def test_mp089_safe_and_suppression():
    code = """
def check_safe(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    cursor.execute(f"PRAGMA table_info(static_table)")  # nosec: MP089
"""
    findings = _scan_code(code)
    mp089 = [f for f in findings if f.check_id == "MP089"]
    assert len(mp089) == 0


def test_mp090_insecure_tls_minimum_version():
    code = """
import ssl

context = ssl.create_default_context()
context.minimum_version = ssl.TLSVersion.TLSv1
context.minimum_version = ssl.TLSVersion.TLSv1_1
"""
    findings = _scan_code(code)
    mp090 = [f for f in findings if f.check_id == "MP090"]
    assert len(mp090) == 2
    for f in mp090:
        assert f.severity == "HIGH"
        assert "minimum_version" in f.description


def test_mp090_safe_and_suppression():
    code = """
import ssl

context = ssl.create_default_context()
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.minimum_version = ssl.TLSVersion.TLSv1  # nosec: MP090
"""
    findings = _scan_code(code)
    mp090 = [f for f in findings if f.check_id == "MP090"]
    assert len(mp090) == 0


def test_mp091_celery_task_global_mutation():
    code = """
from celery import shared_task

GLOBAL_COUNTER = 0

@shared_task(bind=True)
def unsafe_task(self):
    global GLOBAL_COUNTER
    GLOBAL_COUNTER += 1
"""
    findings = _scan_code(code)
    mp091 = [f for f in findings if f.check_id == "MP091"]
    assert len(mp091) == 1
    assert mp091[0].severity == "HIGH"
    assert "mutates global state" in mp091[0].description


def test_mp091_safe_and_suppression():
    code = """
from celery import shared_task

GLOBAL_COUNTER = 0

@shared_task(bind=False)
def safe_unbound_task():
    global GLOBAL_COUNTER
    GLOBAL_COUNTER += 1

@shared_task(bind=True)
def suppressed_task(self):  # nosec: MP091
    global GLOBAL_COUNTER
    GLOBAL_COUNTER += 1
"""
    findings = _scan_code(code)
    mp091 = [f for f in findings if f.check_id == "MP091"]
    assert len(mp091) == 0


def test_mp092_zipfile_extractall():
    code = """
import zipfile

def unpack(zip_path):
    with zipfile.ZipFile(zip_path) as z:
        z.extractall("/tmp/unpacked")
"""
    findings = _scan_code(code)
    mp092 = [f for f in findings if f.check_id == "MP092"]
    assert len(mp092) == 1
    assert mp092[0].severity == "HIGH"
    assert "extractall" in mp092[0].description


def test_mp092_safe_and_suppression():
    code = """
import zipfile

def unpack(zip_path):
    with zipfile.ZipFile(zip_path) as z:
        z.extractall("/tmp/unpacked")  # nosec: MP092
"""
    findings = _scan_code(code)
    mp092 = [f for f in findings if f.check_id == "MP092"]
    assert len(mp092) == 0
