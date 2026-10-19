import ast
from maunprekshak.scanner.sast import SecurityVisitor, is_suppressed


def _scan_code(code: str):
    source_lines = code.splitlines()
    tree = ast.parse(code)
    visitor = SecurityVisitor("test_v019.py", source_lines)
    visitor.visit(tree)
    return [f for f in visitor.findings if not is_suppressed(f, source_lines)]


def test_mp081_ctypes_dynamic_load():
    code = """
import ctypes
lib_name = "test"
ctypes.CDLL(f"/usr/local/lib/{lib_name}.so")
ctypes.cdll.LoadLibrary(lib_path)
"""
    findings = _scan_code(code)
    check_ids = [f.check_id for f in findings]
    assert "MP081" in check_ids
    mp081_findings = [f for f in findings if f.check_id == "MP081"]
    assert len(mp081_findings) == 2


def test_mp081_suppression():
    code = """
import ctypes
ctypes.CDLL(lib_path)  # nosec: MP081
"""
    findings = _scan_code(code)
    check_ids = [f.check_id for f in findings]
    assert "MP081" not in check_ids


def test_mp082_pymongo_empty_delete_update():
    code = """
def wipe_db(db):
    db.users.delete_many({})
    db.records.update_many({}, {"$set": {"archived": True}})
"""
    findings = _scan_code(code)
    check_ids = [f.check_id for f in findings]
    assert "MP082" in check_ids
    mp082_findings = [f for f in findings if f.check_id == "MP082"]
    assert len(mp082_findings) == 2


def test_mp082_suppression():
    code = """
def clean_users(db):
    db.users.delete_many({})  # maunprekshak: ignore[MP082]
"""
    findings = _scan_code(code)
    check_ids = [f.check_id for f in findings]
    assert "MP082" not in check_ids


def test_mp083_cors_allow_origins_wildcard_credentials():
    code = """
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
)
"""
    findings = _scan_code(code)
    check_ids = [f.check_id for f in findings]
    assert "MP083" in check_ids


def test_mp083_suppression():
    code = """
app.add_middleware(  # nosec: MP083, MP041
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
)
"""
    findings = _scan_code(code)
    check_ids = [f.check_id for f in findings]
    assert "MP083" not in check_ids


def test_mp084_asyncssh_known_hosts_none():
    code = """
import asyncssh

async def run_client():
    async with asyncssh.connect("10.0.0.1", known_hosts=None) as conn:
        result = await conn.run("ls -l")
"""
    findings = _scan_code(code)
    check_ids = [f.check_id for f in findings]
    assert "MP084" in check_ids


def test_mp084_suppression():
    code = """
asyncssh.connect("10.0.0.1", known_hosts=None)  # nosec: MP084
"""
    findings = _scan_code(code)
    check_ids = [f.check_id for f in findings]
    assert "MP084" not in check_ids


def test_mp085_ipc_manager_missing_authkey():
    code = """
from multiprocessing.managers import BaseManager, SyncManager

m1 = BaseManager(address=("", 50000))
m2 = SyncManager()
"""
    findings = _scan_code(code)
    check_ids = [f.check_id for f in findings]
    assert "MP085" in check_ids
    mp085_findings = [f for f in findings if f.check_id == "MP085"]
    assert len(mp085_findings) == 2


def test_mp085_suppression():
    code = """
from multiprocessing.managers import BaseManager
m = BaseManager(address=("", 50000))  # maunprekshak: ignore[MP085]
"""
    findings = _scan_code(code)
    check_ids = [f.check_id for f in findings]
    assert "MP085" not in check_ids


def test_mp086_mmap_prot_write_exec():
    code = """
import mmap

buf = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
"""
    findings = _scan_code(code)
    check_ids = [f.check_id for f in findings]
    assert "MP086" in check_ids


def test_mp086_suppression():
    code = """
buf = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)  # nosec: MP086
"""
    findings = _scan_code(code)
    check_ids = [f.check_id for f in findings]
    assert "MP086" not in check_ids
