"""
Tests for MaunPrekshak Core v0.23.0 — Advanced AST SAST Suite (MP105–MP110).
"""
import os
import tempfile
from maunprekshak.scanner.sast import scan_sast


def _scan_py(code: str):
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(code)
        f.flush()
        temp_path = f.name
    try:
        return scan_sast(temp_path, target_files=[temp_path])
    finally:
        os.remove(temp_path)


def test_mp105_minidom_insecure_xml_parse():
    bad_code = """
import xml.dom.minidom as minidom

def parse_xml_payload(xml_data):
    dom1 = minidom.parse("data.xml")
    dom2 = minidom.parseString(xml_data)
    return dom1, dom2
"""
    findings = _scan_py(bad_code)
    mp105 = [f for f in findings if f.check_id == "MP105"]
    assert len(mp105) == 2
    for f in mp105:
        assert f.severity == "HIGH"
        assert "minidom" in f.description.lower() or "billion laughs" in f.description.lower()


def test_mp105_safe_and_suppression():
    good_code = """
import defusedxml.minidom as defused_minidom
import xml.dom.minidom as minidom

def parse_safe(xml_data):
    dom1 = defused_minidom.parse("data.xml")
    dom2 = minidom.parseString(xml_data) # nosec: MP105
    return dom1, dom2
"""
    findings = _scan_py(good_code)
    mp105 = [f for f in findings if f.check_id == "MP105"]
    assert len(mp105) == 0


def test_mp106_redis_missing_auth():
    bad_code = """
import redis

def get_redis_client():
    r1 = redis.Redis(host="localhost", port=6379)
    r2 = redis.StrictRedis(host="10.0.0.1", port=6379, password=None)
    return r1, r2
"""
    findings = _scan_py(bad_code)
    mp106 = [f for f in findings if f.check_id == "MP106"]
    assert len(mp106) == 2
    for f in mp106:
        assert f.severity == "HIGH"
        assert "redis connection" in f.description.lower()


def test_mp106_safe_and_suppression():
    good_code = """
import redis
import os

def get_redis_safe():
    r1 = redis.Redis(host="localhost", port=6379, password=os.environ["REDIS_PW"])
    r2 = redis.StrictRedis(host="10.0.0.1", port=6379) # nosec: MP106
    return r1, r2
"""
    findings = _scan_py(good_code)
    mp106 = [f for f in findings if f.check_id == "MP106"]
    assert len(mp106) == 0


def test_mp107_http_disabled_ssl_verification():
    bad_code = """
import urllib3
import aiohttp
import httpx

def insecure_requests():
    http = urllib3.PoolManager(cert_reqs='CERT_NONE')
    connector = aiohttp.TCPConnector(ssl=False)
    client = httpx.Client(verify=False)
    return http, connector, client
"""
    findings = _scan_py(bad_code)
    mp107 = [f for f in findings if f.check_id == "MP107"]
    assert len(mp107) == 3
    for f in mp107:
        assert f.severity == "HIGH"
        assert "ssl" in f.description.lower() or "mitm" in f.description.lower()


def test_mp107_safe_and_suppression():
    good_code = """
import urllib3
import httpx

def secure_requests():
    http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED')
    client = httpx.Client(verify=True)
    insecure_client = httpx.Client(verify=False) # nosec: MP107
    return http, client, insecure_client
"""
    findings = _scan_py(good_code)
    mp107 = [f for f in findings if f.check_id == "MP107"]
    assert len(mp107) == 0


def test_mp108_sensitive_credential_logging():
    bad_code = """
import logging

logger = logging.getLogger(__name__)

def authenticate_user(user, password, api_key):
    logger.info(f"Authenticating user {user} with password: {password}")
    logger.debug(f"Received request with api_key={api_key}")
    logger.error("Authentication failed for token", extra={"token": password})
    logger.info("Raw token:", password)
"""
    findings = _scan_py(bad_code)
    mp108 = [f for f in findings if f.check_id == "MP108"]
    assert len(mp108) >= 2
    for f in mp108:
        assert f.severity == "HIGH"
        assert "credential logging" in f.description.lower()


def test_mp108_safe_and_suppression():
    good_code = """
import logging

logger = logging.getLogger(__name__)

def safe_log(user, password):
    logger.info(f"Authenticating user {user}")
    logger.debug(f"Password provided: {password}") # nosec: MP108
"""
    findings = _scan_py(good_code)
    mp108 = [f for f in findings if f.check_id == "MP108"]
    assert len(mp108) == 0


def test_mp109_insecure_tempfile_mkdtemp():
    bad_code = """
import tempfile

def create_workspace():
    tmp_path = tempfile.mkdtemp()
    return tmp_path
"""
    findings = _scan_py(bad_code)
    mp109 = [f for f in findings if f.check_id == "MP109"]
    assert len(mp109) == 1
    assert mp109[0].severity == "HIGH"
    assert "mkdtemp" in mp109[0].description.lower()


def test_mp109_safe_and_suppression():
    good_code = """
import tempfile

def safe_workspace():
    with tempfile.TemporaryDirectory() as tmp_dir:
        pass
    suppressed_dir = tempfile.mkdtemp() # nosec: MP109
"""
    findings = _scan_py(good_code)
    mp109 = [f for f in findings if f.check_id == "MP109"]
    assert len(mp109) == 0


def test_mp110_insecure_ecb_cipher_mode():
    bad_code = """
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import AES

def encrypt_data(key, data):
    cipher1 = Cipher(algorithms.AES(key), modes.ECB())
    cipher2 = AES.new(key, AES.MODE_ECB)
    return cipher1, cipher2
"""
    findings = _scan_py(bad_code)
    mp110 = [f for f in findings if f.check_id == "MP110"]
    assert len(mp110) == 2
    for f in mp110:
        assert f.severity == "HIGH"
        assert "ecb" in f.description.lower()


def test_mp110_safe_and_suppression():
    good_code = """
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import AES

def safe_encrypt(key, nonce, data):
    cipher1 = Cipher(algorithms.AES(key), modes.GCM(nonce))
    cipher2 = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher3 = AES.new(key, AES.MODE_ECB) # nosec: MP110
    return cipher1, cipher2, cipher3
"""
    findings = _scan_py(good_code)
    mp110 = [f for f in findings if f.check_id == "MP110"]
    assert len(mp110) == 0
