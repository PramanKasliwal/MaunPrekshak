"""
Tests for MaunPrekshak SAST Scanner
"""
import pytest
from maunprekshak.scanner.sast import scan_sast


def write_py(tmp_path, filename, code):
    f = tmp_path / filename
    f.write_text(code)
    return str(tmp_path)


class TestEvalExec:
    def test_detects_eval(self, tmp_path):
        path = write_py(tmp_path, "vuln.py", 'result = eval(user_input)\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP001" in check_ids  # eval usage

    def test_detects_exec(self, tmp_path):
        path = write_py(tmp_path, "vuln.py", 'exec(user_code)\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP002" in check_ids  # exec usage

    def test_no_flag_on_safe_code(self, tmp_path):
        path = write_py(tmp_path, "safe.py", 'x = 1 + 1\nprint(x)\n')
        findings = scan_sast(path)
        assert len(findings) == 0


class TestPickle:
    def test_detects_pickle_loads(self, tmp_path):
        path = write_py(tmp_path, "vuln.py", 'import pickle\ndata = pickle.loads(raw)\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP003" in check_ids  # pickle usage

    def test_detects_marshal_loads(self, tmp_path):
        path = write_py(tmp_path, "vuln.py", 'import marshal\nobj = marshal.loads(raw)\n')
        findings = scan_sast(path)
        assert len(findings) > 0


class TestSubprocess:
    def test_detects_shell_true(self, tmp_path):
        path = write_py(tmp_path, "vuln.py", 'import subprocess\nsubprocess.run(cmd, shell=True)\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP004" in check_ids

    def test_no_flag_without_shell_true(self, tmp_path):
        path = write_py(tmp_path, "safe.py", 'import subprocess\nsubprocess.run(["ls", "-la"])\n')
        findings = scan_sast(path)
        mp004 = [f for f in findings if f.check_id == "MP004"]
        assert len(mp004) == 0


class TestInsecureHashing:
    def test_detects_md5(self, tmp_path):
        path = write_py(tmp_path, "vuln.py", 'import hashlib\nhash = hashlib.md5(data).hexdigest()\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP008" in check_ids

    def test_detects_sha1(self, tmp_path):
        path = write_py(tmp_path, "vuln.py", 'import hashlib\nhash = hashlib.sha1(data).hexdigest()\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP008" in check_ids


class TestYamlLoad:
    def test_detects_unsafe_yaml_load(self, tmp_path):
        path = write_py(tmp_path, "vuln.py", 'import yaml\ndata = yaml.load(stream)\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP012" in check_ids

    def test_no_flag_on_safe_yaml_load(self, tmp_path):
        path = write_py(tmp_path, "safe.py", 'import yaml\ndata = yaml.safe_load(stream)\n')
        findings = scan_sast(path)
        mp012 = [f for f in findings if f.check_id == "MP012"]
        assert len(mp012) == 0


class TestFindings:
    def test_finding_has_line_number(self, tmp_path):
        path = write_py(tmp_path, "vuln.py", 'x = 1\nresult = eval(user_input)\ny = 2\n')
        findings = scan_sast(path)
        assert len(findings) > 0
        assert findings[0].line == 2

    def test_finding_has_severity(self, tmp_path):
        path = write_py(tmp_path, "vuln.py", 'result = eval(user_input)\n')
        findings = scan_sast(path)
        assert findings[0].severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_finding_has_recommendation(self, tmp_path):
        path = write_py(tmp_path, "vuln.py", 'result = eval(user_input)\n')
        findings = scan_sast(path)
        assert len(findings[0].recommendation) > 0


class TestExtendedSASTRules:
    def test_detects_sql_injection_binop(self, tmp_path):
        path = write_py(tmp_path, "db.py", 'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP006" in check_ids

    def test_detects_sql_injection_fstring(self, tmp_path):
        path = write_py(tmp_path, "db.py", 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP006" in check_ids

    def test_detects_sql_injection_format(self, tmp_path):
        path = write_py(tmp_path, "db.py", 'cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP006" in check_ids

    def test_no_flag_on_parameterized_query(self, tmp_path):
        path = write_py(tmp_path, "db.py", 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n')
        findings = scan_sast(path)
        mp006 = [f for f in findings if f.check_id == "MP006"]
        assert len(mp006) == 0

    def test_detects_disabled_ssl_verification(self, tmp_path):
        path = write_py(tmp_path, "api.py", 'import requests\nresp = requests.get("https://example.com", verify=False)\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP015" in check_ids

    def test_detects_ssl_unverified_context(self, tmp_path):
        path = write_py(tmp_path, "api.py", 'import ssl\nctx = ssl._create_unverified_context()\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP015" in check_ids

    def test_detects_wildcard_binding(self, tmp_path):
        path = write_py(tmp_path, "server.py", 'app.run(host="0.0.0.0", port=8000)\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP016" in check_ids

    def test_detects_insecure_tmp_file(self, tmp_path):
        path = write_py(tmp_path, "util.py", 'with open("/tmp/output.dat", "w") as f:\n    f.write("test")\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP017" in check_ids

    def test_detects_unsafe_shelve(self, tmp_path):
        path = write_py(tmp_path, "store.py", 'import shelve\ns = shelve.open("mydb")\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP018" in check_ids

    def test_detects_unsafe_jsonpickle(self, tmp_path):
        path = write_py(tmp_path, "store.py", 'import jsonpickle\nobj = jsonpickle.decode(payload)\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP018" in check_ids

    def test_detects_paramiko_auto_add_policy(self, tmp_path):
        path = write_py(tmp_path, "ssh.py", 'import paramiko\nclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP019" in check_ids

    def test_detects_jwt_unverified_options(self, tmp_path):
        path = write_py(tmp_path, "auth.py", 'import jwt\npayload = jwt.decode(token, options={"verify_signature": False})\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP020" in check_ids

    def test_detects_jwt_verify_false(self, tmp_path):
        path = write_py(tmp_path, "auth.py", 'import jwt\npayload = jwt.decode(token, verify=False)\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP020" in check_ids

    def test_detects_insecure_chmod(self, tmp_path):
        path = write_py(tmp_path, "perm.py", 'import os\nos.chmod("/tmp/secret", 0o777)\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP021" in check_ids

    def test_no_flag_on_safe_chmod(self, tmp_path):
        path = write_py(tmp_path, "perm.py", 'import os\nos.chmod("/path/safe", 0o600)\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP021" not in check_ids

    def test_detects_legacy_xml_parsers(self, tmp_path):
        path = write_py(tmp_path, "parse_xml.py", 'from xml.dom import minidom\ndoc = minidom.parse("data.xml")\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP022" in check_ids

    def test_detects_xml_sax_make_parser(self, tmp_path):
        path = write_py(tmp_path, "parse_sax.py", 'import xml.sax\np = xml.sax.make_parser()\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP022" in check_ids

    def test_detects_tarfile_extractall_zipslip(self, tmp_path):
        path = write_py(tmp_path, "extract.py", 'import tarfile\ntf = tarfile.open("archive.tar")\ntf.extractall("/path/dest")\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP023" in check_ids

    def test_no_flag_on_safe_tarfile_filter(self, tmp_path):
        path = write_py(tmp_path, "extract.py", 'import tarfile\ntf = tarfile.open("archive.tar")\ntf.extractall("/path/dest", filter="data")\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP023" not in check_ids

    def test_detects_urllib_ssrf(self, tmp_path):
        path = write_py(tmp_path, "req.py", 'import urllib.request\nurllib.request.urlopen(user_url)\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP024" in check_ids

    def test_detects_insecure_ecb_cipher(self, tmp_path):
        path = write_py(tmp_path, "crypto.py", 'from cryptography.hazmat.primitives.ciphers import modes\nmode = modes.ECB()\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP025" in check_ids

    def test_no_flag_on_safe_gcm_cipher(self, tmp_path):
        path = write_py(tmp_path, "crypto.py", 'from cryptography.hazmat.primitives.ciphers import modes\nmode = modes.GCM(nonce)\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP025" not in check_ids

    def test_detects_dill_loads(self, tmp_path):
        path = write_py(tmp_path, "deserialize.py", 'import dill\nobj = dill.loads(payload)\n')
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP026" in check_ids

    def test_detects_jinja2_ssti(self, tmp_path):
        code = 'import jinja2\nuser_name = "guest"\ntemplate = jinja2.Template(f"Hello {user_name}!")\n'
        path = write_py(tmp_path, "ssti.py", code)
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP027" in check_ids

    def test_no_flag_on_static_jinja2_template(self, tmp_path):
        code = 'import jinja2\ntemplate = jinja2.Template("Hello {{ name }}!")\nresult = template.render(name="Alice")\n'
        path = write_py(tmp_path, "safe_template.py", code)
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP027" not in check_ids

    def test_detects_pandas_read_pickle(self, tmp_path):
        code = 'import pandas as pd\ndf = pd.read_pickle("user_data.pkl")\n'
        path = write_py(tmp_path, "ds_pickle.py", code)
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP028" in check_ids

    def test_no_flag_on_pandas_read_parquet(self, tmp_path):
        code = 'import pandas as pd\ndf = pd.read_parquet("user_data.parquet")\n'
        path = write_py(tmp_path, "ds_parquet.py", code)
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP028" not in check_ids

    def test_detects_insecure_cookie_missing_flags(self, tmp_path):
        code = 'response.set_cookie("session_id", "xyz123")\n'
        path = write_py(tmp_path, "cookie_insecure.py", code)
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP029" in check_ids

    def test_no_flag_on_secure_cookie(self, tmp_path):
        code = 'response.set_cookie("session_id", "xyz123", httponly=True, secure=True, samesite="Lax")\n'
        path = write_py(tmp_path, "cookie_secure.py", code)
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP029" not in check_ids

    def test_detects_hardcoded_crypto_iv_and_salt(self, tmp_path):
        code = 'from cryptography.hazmat.primitives.ciphers import modes\nmode = modes.CBC(b"1234567890123456")\n'
        path = write_py(tmp_path, "crypto_iv.py", code)
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP030" in check_ids

    def test_no_flag_on_dynamic_iv_and_salt(self, tmp_path):
        code = 'import os\nfrom cryptography.hazmat.primitives.ciphers import modes\niv = os.urandom(16)\nmode = modes.CBC(iv)\n'
        path = write_py(tmp_path, "crypto_dynamic.py", code)
        findings = scan_sast(path)
        check_ids = [f.check_id for f in findings]
        assert "MP030" not in check_ids

    def test_target_files_filters_sast_scan(self, tmp_path):
        vuln = tmp_path / "vuln.py"
        vuln.write_text('eval("1+1")\n')
        safe = tmp_path / "safe.py"
        safe.write_text('x = 1\n')

        findings = scan_sast(str(tmp_path), target_files=[str(safe)])
        assert len(findings) == 0

        findings_vuln = scan_sast(str(tmp_path), target_files=[str(vuln)])
        assert len(findings_vuln) > 0


