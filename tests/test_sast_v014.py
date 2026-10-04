"""
Tests for MaunPrekshak Core v0.14.0 — Cryptographic & Data Science SAST Suite (MP049–MP055).
"""
import ast
import tempfile
import pytest
from maunprekshak.scanner.sast import SecurityVisitor, is_suppressed


def _scan_code(code: str):
    tree = ast.parse(code)
    lines = code.splitlines(keepends=True)
    visitor = SecurityVisitor(file_path="test_sample.py", source_lines=lines)
    visitor.visit(tree)
    # Filter out suppressed findings
    return [f for f in visitor.findings if not is_suppressed(f, lines)]


def test_mp049_insecure_password_hashing():
    code = """
import hashlib

def hash_user_pass(password: str):
    return hashlib.sha256(password.encode()).hexdigest()

def verify(pwd: str):
    hashed_pwd = hashlib.md5(pwd.encode()).hexdigest()
    return hashed_pwd
"""
    findings = _scan_code(code)
    mp049 = [f for f in findings if f.check_id == "MP049"]
    assert len(mp049) >= 2
    for f in mp049:
        assert f.severity == "HIGH"
        assert "password" in f.description.lower() or "credential" in f.description.lower()


def test_mp049_safe_file_digest_no_flag():
    code = """
import hashlib

def calculate_checksum(file_bytes: bytes):
    return hashlib.sha256(file_bytes).hexdigest()
"""
    findings = _scan_code(code)
    mp049 = [f for f in findings if f.check_id == "MP049"]
    assert len(mp049) == 0


def test_mp050_insecure_prng_tokens_and_secrets():
    code = """
import random
import string

def create_reset_token():
    chars = string.ascii_letters + string.digits
    reset_token = "".join(random.choice(chars) for _ in range(32))
    return reset_token

def generate_otp():
    otp_code = random.randint(100000, 999999)
    return otp_code
"""
    findings = _scan_code(code)
    mp050 = [f for f in findings if f.check_id == "MP050"]
    assert len(mp050) == 2
    for f in mp050:
        assert f.severity == "HIGH"
        assert "secrets" in f.recommendation


def test_mp050_game_random_safe_no_flag():
    code = """
import random

def roll_dice():
    dice_roll = random.randint(1, 6)
    return dice_roll
"""
    findings = _scan_code(code)
    mp050 = [f for f in findings if f.check_id == "MP050"]
    assert len(mp050) == 0


def test_mp051_dangerous_numpy_pickle():
    code = """
import numpy as np

def load_weights(path):
    data = np.load(path, allow_pickle=True)
    return data
"""
    findings = _scan_code(code)
    mp051 = [f for f in findings if f.check_id == "MP051"]
    assert len(mp051) == 1
    assert mp051[0].severity == "HIGH"
    assert "allow_pickle=True" in mp051[0].description


def test_mp051_safe_numpy_load_no_flag():
    code = """
import numpy as np

def load_data(path):
    return np.load(path, allow_pickle=False)
"""
    findings = _scan_code(code)
    mp051 = [f for f in findings if f.check_id == "MP051"]
    assert len(mp051) == 0


def test_mp052_weak_rsa_key_length():
    code = """
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_legacy_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)
"""
    findings = _scan_code(code)
    mp052 = [f for f in findings if f.check_id == "MP052"]
    assert len(mp052) == 1
    assert mp052[0].severity == "HIGH"
    assert "1024 bits" in mp052[0].description


def test_mp052_strong_rsa_key_safe():
    code = """
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_secure_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)
"""
    findings = _scan_code(code)
    mp052 = [f for f in findings if f.check_id == "MP052"]
    assert len(mp052) == 0


def test_mp053_insecure_rsa_pkcs1v15_padding():
    code = """
from cryptography.hazmat.primitives.asymmetric import padding

def encrypt_message(public_key, data):
    return public_key.encrypt(data, padding.PKCS1v15())
"""
    findings = _scan_code(code)
    mp053 = [f for f in findings if f.check_id == "MP053"]
    assert len(mp053) == 1
    assert mp053[0].severity == "MEDIUM"
    assert "PKCS#1 v1.5" in mp053[0].description


def test_mp054_insecure_xml_entity_resolution():
    code = """
from lxml import etree

def parse_xml(xml_content):
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(xml_content, parser)
"""
    findings = _scan_code(code)
    mp054 = [f for f in findings if f.check_id == "MP054"]
    assert len(mp054) == 1
    assert mp054[0].severity == "HIGH"
    assert "resolve_entities=True" in mp054[0].description


def test_mp055_deprecated_tls_version():
    code = """
import ssl

def create_client_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    context.minimum_version = ssl.TLSVersion.TLSv1_1
    return context
"""
    findings = _scan_code(code)
    mp055 = [f for f in findings if f.check_id == "MP055"]
    assert len(mp055) >= 2
    for f in mp055:
        assert f.severity == "MEDIUM"


def test_mp055_modern_tls_safe():
    code = """
import ssl

def create_secure_context():
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context
"""
    findings = _scan_code(code)
    mp055 = [f for f in findings if f.check_id == "MP055"]
    assert len(mp055) == 0
