"""
MaunPrekshak — SAST (Static Application Security Testing) Scanner
Uses Python's `ast` module to walk source code and detect insecure patterns.
"""
import ast
import os
import re
from typing import List, Optional

from maunprekshak.scanner.report import SASTFinding, Severity


# ─── Check IDs ────────────────────────────────────────────────────────────────
# MP001  eval() usage                  CRITICAL
# MP002  exec() usage                  CRITICAL
# MP003  pickle/marshal deserialization CRITICAL
# MP004  subprocess with shell=True    HIGH
# MP005  os.system() usage             HIGH
# MP006  SQL string concatenation      CRITICAL
# MP007  compile() with user data      HIGH
# MP008  Weak hash (MD5/SHA1)          MEDIUM
# MP009  insecure random               MEDIUM
# MP010  assert for security checks    LOW
# MP011  DEBUG = True                  MEDIUM
# MP012  yaml.load() without Loader    HIGH
# MP013  xml.etree (use defusedxml)    MEDIUM
# MP014  tempfile.mktemp() race cond   MEDIUM
# MP015  Disabled SSL verification     HIGH
# MP016  Wildcard network binding      MEDIUM
# MP017  Hardcoded /tmp file usage     MEDIUM
# MP018  Unsafe shelve/jsonpickle      HIGH
# MP019  paramiko AutoAddPolicy (SSH)  HIGH
# MP020  jwt.decode() without verify   HIGH
# MP021  os.chmod() world-writable     MEDIUM
# MP022  legacy XML parser (XXE)       MEDIUM
# MP023  tarfile.extractall() Zip Slip HIGH
# MP024  urllib SSRF / URL injection   HIGH
# MP025  Insecure cipher / ECB mode    HIGH
# MP026  dill deserialization          HIGH
# MP027  Server-Side Template (SSTI)   HIGH
# MP028  pandas.read_pickle() code exec HIGH
# MP029  Missing secure cookie flags   MEDIUM
# MP030  Hardcoded crypto IV or salt   HIGH
# MP031  Insecure ML model load        CRITICAL
# MP032  Regular expression ReDoS      HIGH
# MP033  World-writable chmod (0o777)  MEDIUM
# MP034  LDAP injection                HIGH
# MP035  XPath injection               HIGH


class SecurityVisitor(ast.NodeVisitor):
    """AST Visitor that walks Python source and flags security anti-patterns."""

    def __init__(self, file_path: str, source_lines: List[str]):
        self.file_path = file_path
        self.source_lines = source_lines
        self.findings: List[SASTFinding] = []

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _add(self, node: ast.AST, check_id: str, severity: str, desc: str, rec: str) -> None:
        line = getattr(node, "lineno", 0)
        col = getattr(node, "col_offset", 0)
        snippet = self.source_lines[line - 1].rstrip() if 0 < line <= len(self.source_lines) else ""
        self.findings.append(SASTFinding(
            file_path=self.file_path,
            line=line,
            col=col,
            check_id=check_id,
            severity=severity,
            description=desc,
            recommendation=rec,
            code_snippet=snippet,
        ))

    def _get_func_name(self, node: ast.Call) -> str:
        """Get the simple function name from a Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""

    def _get_attr_chain(self, node: ast.Call) -> tuple[str, str]:
        """Return (object_name, method_name) for attr calls like foo.bar()."""
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            return node.func.value.id, node.func.attr
        return "", ""

    def _has_keyword(self, node: ast.Call, key: str, value: object) -> bool:
        """Check if a Call node has keyword=value."""
        for kw in node.keywords:
            if kw.arg == key and isinstance(kw.value, ast.Constant) and kw.value.value == value:
                return True
        return False

    def _get_full_func_name(self, node: ast.Call) -> str:
        """Get full dotted function name from a Call node."""
        parts = []
        curr = node.func
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
        return ".".join(reversed(parts))

    # ── Visitors ──────────────────────────────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._get_func_name(node)
        obj, method = self._get_attr_chain(node)
        full_func = self._get_full_func_name(node)

        # MP001 — eval()
        if func_name == "eval":
            self._add(node, "MP001", Severity.CRITICAL.value,
                      "Use of eval() detected — arbitrary code execution risk",
                      "Replace eval() with ast.literal_eval() for safe expression evaluation, "
                      "or redesign to avoid dynamic code execution entirely.")

        # MP002 — exec()
        elif func_name == "exec":
            self._add(node, "MP002", Severity.CRITICAL.value,
                      "Use of exec() detected — arbitrary code execution risk",
                      "Avoid exec() with user-controlled input. "
                      "Refactor to use explicit logic instead of dynamic code execution.")

        # MP003 — pickle / marshal deserialization
        elif method in ("loads", "load") and obj in ("pickle", "marshal"):
            self._add(node, "MP003", Severity.CRITICAL.value,
                      f"{obj}.{method}() can execute arbitrary code when deserializing untrusted data",
                      "Use JSON, MessagePack, or a safe serialization format. "
                      "Never deserialize data from untrusted sources with pickle.")

        # MP004 — subprocess shell=True
        elif obj == "subprocess" or (obj == "" and func_name in ("run", "call", "check_call", "check_output", "Popen")):
            if self._has_keyword(node, "shell", True):
                self._add(node, "MP004", Severity.HIGH.value,
                          "subprocess called with shell=True — command injection risk",
                          "Pass a list of arguments instead of a shell string: "
                          "subprocess.run(['ls', '-la']) instead of subprocess.run('ls -la', shell=True).")

        # MP005 — os.system()
        elif obj == "os" and method == "system":
            self._add(node, "MP005", Severity.HIGH.value,
                      "os.system() usage — command injection risk",
                      "Use subprocess.run() with a list of arguments instead.")

        # MP007 — compile() — only flag the bare built-in, NOT re.compile() etc.
        elif func_name == "compile" and isinstance(node.func, ast.Name):
            self._add(node, "MP007", Severity.HIGH.value,
                      "compile() can execute arbitrary code if called with untrusted input",
                      "Avoid compile() with user-controlled strings.")

        # MP008 — Weak hashing algorithms
        elif obj == "hashlib" and method in ("md5", "sha1"):
            self._add(node, "MP008", Severity.MEDIUM.value,
                      f"hashlib.{method}() is cryptographically weak",
                      "Use hashlib.sha256() or hashlib.sha3_256() for security-sensitive hashing. "
                      "MD5/SHA1 are only acceptable for non-security uses like checksums.")

        # MP009 — Insecure random
        elif obj == "random" and method in ("random", "randint", "choice", "randrange", "shuffle"):
            self._add(node, "MP009", Severity.MEDIUM.value,
                      f"random.{method}() is not cryptographically secure",
                      "Use the `secrets` module for security-sensitive randomness: "
                      "secrets.token_hex(), secrets.choice(), secrets.randbelow().")

        # MP012 — yaml.load() without Loader
        elif obj == "yaml" and method == "load":
            # Only flag if no Loader= kwarg is passed (unsafe)
            has_loader = any(kw.arg == "Loader" for kw in node.keywords)
            if not has_loader:
                self._add(node, "MP012", Severity.HIGH.value,
                          "yaml.load() without explicit Loader can execute arbitrary Python",
                          "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader) instead.")

        # MP013 — xml.etree (XXE vulnerable)
        elif obj == "ElementTree" and method == "parse":
            self._add(node, "MP013", Severity.MEDIUM.value,
                      "xml.etree.ElementTree is vulnerable to XML attacks (XXE, entity expansion)",
                      "Use defusedxml.ElementTree instead: pip install defusedxml.")

        # MP014 — tempfile.mktemp() race condition
        elif obj == "tempfile" and method == "mktemp":
            self._add(node, "MP014", Severity.MEDIUM.value,
                      "tempfile.mktemp() has a race condition — insecure temp file creation",
                      "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead.")

        # MP006 — SQL string concatenation / formatting
        elif method in ("execute", "executemany", "raw") or func_name in ("execute", "executemany", "raw"):
            if node.args:
                arg0 = node.args[0]
                is_formatted = (
                    isinstance(arg0, (ast.JoinedStr, ast.BinOp))
                    or (
                        isinstance(arg0, ast.Call)
                        and isinstance(arg0.func, ast.Attribute)
                        and arg0.func.attr == "format"
                    )
                )
                if is_formatted:
                    self._add(node, "MP006", Severity.CRITICAL.value,
                              "SQL query constructed via string formatting/concatenation — SQL injection risk",
                              "Use parameterized queries with placeholders: "
                              "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)).")

        # MP020 — Unverified JWT decode
        elif (obj == "jwt" and method == "decode") or full_func in ("jwt.decode", "jwt.api_jwt.decode"):
            has_verify_false = self._has_keyword(node, "verify", False)
            has_unverified_sig = False
            for kw in node.keywords:
                if kw.arg == "options" and isinstance(kw.value, ast.Dict):
                    for k, v in zip(kw.value.keys, kw.value.values):
                        if isinstance(k, ast.Constant) and k.value == "verify_signature":
                            if isinstance(v, ast.Constant) and v.value is False:
                                has_unverified_sig = True
            if has_verify_false or has_unverified_sig:
                self._add(node, "MP020", Severity.HIGH.value,
                          "jwt.decode() called without signature verification — token tampering and authentication bypass risk",
                          "Always verify JWT signatures using a secret key and expected algorithms: jwt.decode(token, secret, algorithms=['HS256']).")

        # MP015 — Insecure SSL/TLS verification disabled
        elif self._has_keyword(node, "verify", False) or (obj == "ssl" and method == "_create_unverified_context"):
            self._add(node, "MP015", Severity.HIGH.value,
                      "Insecure SSL/TLS verification disabled — Man-in-the-Middle (MitM) attack risk",
                      "Never disable SSL verification (verify=False) in production. Ensure proper CA certificates are configured.")

        # MP016 — Wildcard network binding (0.0.0.0)
        elif self._has_keyword(node, "host", "0.0.0.0") or self._has_keyword(node, "bind", "0.0.0.0") or (
            method == "bind" and node.args and isinstance(node.args[0], (ast.Tuple, ast.List))
            and node.args[0].elts and isinstance(node.args[0].elts[0], ast.Constant)
            and node.args[0].elts[0].value == "0.0.0.0"
        ):
            self._add(node, "MP016", Severity.MEDIUM.value,
                      "Binding to wildcard address '0.0.0.0' exposes service on all network interfaces",
                      "Bind to 127.0.0.1 for local development, or configure a specific host interface/reverse proxy for production.")

        # MP017 — Insecure hardcoded temporary file usage
        elif ((obj == "" and func_name == "open") or (obj == "os" and method in ("open", "remove", "unlink"))) and node.args:
            if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                if node.args[0].value.startswith(("/tmp/", "/var/tmp/")):
                    self._add(node, "MP017", Severity.MEDIUM.value,
                              "Hardcoded /tmp file path in open() — race condition and symlink vulnerability risk",
                              "Use tempfile.NamedTemporaryFile() or tempfile.TemporaryDirectory() for secure temporary files.")

        # MP018 — Unsafe deserialization via shelve or jsonpickle
        elif (obj == "shelve" and method == "open") or (obj == "jsonpickle" and method in ("decode", "unpickler")):
            self._add(node, "MP018", Severity.HIGH.value,
                      f"Unsafe deserialization with {obj}.{method}() — arbitrary code execution risk",
                      f"Avoid {obj}.{method}() on untrusted data. Use safe serialization formats like JSON.")

        # MP019 — Insecure paramiko SSH host key policy
        elif (obj == "paramiko" and method in ("AutoAddPolicy", "WarningPolicy")) or full_func in (
            "paramiko.AutoAddPolicy", "paramiko.WarningPolicy",
            "paramiko.client.AutoAddPolicy", "paramiko.client.WarningPolicy",
        ) or func_name in ("AutoAddPolicy", "WarningPolicy"):
            self._add(node, "MP019", Severity.HIGH.value,
                      f"paramiko {method or func_name}() automatically trusts unknown SSH host keys — vulnerable to Man-in-the-Middle attacks",
                      "Use paramiko.RejectPolicy() and verify host keys explicitly with client.load_system_host_keys().")

        # MP021 — Insecure chmod permissions (world-writable 0o777 / 0o002)
        elif ((obj == "os" and method == "chmod") or full_func == "os.chmod") and len(node.args) >= 2:
            arg1 = node.args[1]
            if isinstance(arg1, ast.Constant) and isinstance(arg1.value, int):
                if (arg1.value & 0o002) != 0:
                    self._add(node, "MP021", Severity.MEDIUM.value,
                              f"os.chmod() sets world-writable permissions ({oct(arg1.value)}) — local privilege escalation risk",
                              "Use restrictive permissions such as 0o600 for sensitive files or 0o700 for private directories.")

        # MP022 — Insecure legacy XML parsers (minidom, pulldom, sax)
        elif (
            full_func in (
                "xml.sax.make_parser", "xml.dom.minidom.parse", "xml.dom.minidom.parseString",
                "xml.dom.pulldom.parse", "xml.dom.pulldom.parseString"
            )
            or (obj in ("minidom", "pulldom") and method in ("parse", "parseString"))
            or (obj == "sax" and method == "make_parser")
        ):
            self._add(node, "MP022", Severity.MEDIUM.value,
                      "Legacy standard library XML parser is vulnerable to XML entity expansion and XXE attacks",
                      "Use defusedxml (defusedxml.minidom, defusedxml.sax) to safely parse untrusted XML documents.")

        # MP023 — tarfile.extractall() directory traversal / Zip Slip (CVE-2007-4559)
        elif (
            (method == "extractall" and obj in ("tarfile", "tar", "archive", "tf"))
            or full_func.endswith(".extractall")
            or full_func in ("tarfile.extractall", "tarfile.TarFile.extractall")
        ):
            has_safe_filter = False
            for kw in node.keywords:
                if kw.arg == "filter" and isinstance(kw.value, ast.Constant) and kw.value.value in ("data", "tar"):
                    has_safe_filter = True
            if not has_safe_filter:
                self._add(node, "MP023", Severity.HIGH.value,
                          "tarfile.extractall() without a safe filter is vulnerable to directory traversal (Zip Slip / CVE-2007-4559)",
                          "Use filter='data' (Python 3.12+) or sanitize member paths before extraction.")

        # MP024 — SSRF via urllib.request.urlopen / urlretrieve
        elif (
            full_func in ("urllib.request.urlopen", "urllib.request.urlretrieve", "urllib.urlopen", "urllib.urlretrieve")
            or (obj in ("urllib.request", "request") and method in ("urlopen", "urlretrieve"))
            or (obj == "urllib" and method in ("urlopen", "urlretrieve"))
        ):
            self._add(node, "MP024", Severity.HIGH.value,
                      f"urllib.request.{method}() is vulnerable to Server-Side Request Forgery (SSRF) and scheme injection",
                      "Validate URL scheme against an allowlist (https only) and restrict target host, or use httpx/requests with strict timeouts.")

        # MP025 — Insecure Cipher Mode (ECB) or weak ciphers (DES, RC4, Blowfish)
        elif (
            full_func in (
                "modes.ECB", "ciphers.modes.ECB", "AES.MODE_ECB", "DES.new", "ARC4.new", "Blowfish.new",
            )
            or (obj == "modes" and method == "ECB")
            or (obj == "AES" and method == "MODE_ECB")
            or (obj in ("DES", "ARC4", "Blowfish") and method == "new")
            or (isinstance(node.func, ast.Attribute) and node.func.attr == "MODE_ECB")
        ):
            self._add(node, "MP025", Severity.HIGH.value,
                      "Insecure cryptographic cipher mode (ECB) or weak cipher (DES/RC4) detected",
                      "Use secure authenticated encryption like AES-GCM (modes.GCM) or ChaCha20-Poly1305.")

        # MP026 — Unsafe dill deserialization
        elif (obj == "dill" and method in ("load", "loads")) or full_func in ("dill.load", "dill.loads"):
            self._add(node, "MP026", Severity.HIGH.value,
                      f"Unsafe deserialization with dill.{method}() executes arbitrary Python bytecode",
                      "Never deserialize untrusted input with dill. Use safe structured serialization like JSON.")

        # MP027 — Server-Side Template Injection (SSTI) in Jinja2 / Mako
        elif (
            (method in ("Template", "from_string") and obj in ("jinja2", "Environment", "env"))
            or full_func in ("jinja2.Template", "jinja2.Environment.from_string", "Environment.from_string", "mako.template.Template")
            or (func_name == "Template" and obj == "")
        ):
            if node.args:
                first_arg = node.args[0]
                is_dynamic = (
                    isinstance(first_arg, (ast.JoinedStr, ast.BinOp))
                    or (isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format")
                )
                if is_dynamic:
                    self._add(node, "MP027", Severity.HIGH.value,
                              "Server-Side Template Injection (SSTI) risk: template instantiated with dynamic string formatting",
                              "Pass data via template context parameters (e.g. template.render(key=value)) instead of formatting the template string.")

        # MP028 — Unsafe deserialization with pandas.read_pickle
        elif (
            (obj in ("pandas", "pd") and method == "read_pickle")
            or full_func in ("pandas.read_pickle", "pd.read_pickle")
            or (func_name == "read_pickle" and isinstance(node.func, ast.Attribute) and node.func.attr == "read_pickle")
        ):
            self._add(node, "MP028", Severity.HIGH.value,
                      "Unsafe deserialization: pandas.read_pickle() can execute arbitrary code on untrusted pickle files",
                      "Use safe formats such as Parquet (pandas.read_parquet), Arrow, or Feather instead of pickle.")

        # MP029 — Missing Cookie Security Flags (httponly, secure)
        elif method == "set_cookie" or (isinstance(node.func, ast.Attribute) and node.func.attr == "set_cookie"):
            has_httponly = False
            has_secure = False
            for kw in node.keywords:
                if kw.arg == "httponly" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    has_httponly = True
                elif kw.arg == "secure" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    has_secure = True
            if not (has_httponly and has_secure):
                self._add(node, "MP029", Severity.MEDIUM.value,
                          "response.set_cookie() called without secure flags (httponly=True, secure=True)",
                          "Always include httponly=True and secure=True (and samesite='Lax'/'Strict') when setting cookies.")

        # MP030 — Hardcoded Cryptographic IV or Salt
        elif (
            (obj == "modes" and method in ("CBC", "CTR", "CFB", "OFB"))
            or full_func in ("modes.CBC", "modes.CTR", "modes.CFB", "modes.OFB", "ciphers.modes.CBC", "ciphers.modes.CTR")
            or (obj == "hashlib" and method == "pbkdf2_hmac")
            or full_func == "hashlib.pbkdf2_hmac"
        ):
            is_hardcoded = False
            if method in ("CBC", "CTR", "CFB", "OFB") and node.args:
                if isinstance(node.args[0], ast.Constant):
                    is_hardcoded = True
            elif method == "pbkdf2_hmac":
                for kw in node.keywords:
                    if kw.arg == "salt" and isinstance(kw.value, ast.Constant):
                        is_hardcoded = True
                if len(node.args) >= 3 and isinstance(node.args[2], ast.Constant):
                    is_hardcoded = True
            if is_hardcoded:
                self._add(node, "MP030", Severity.HIGH.value,
                          "Hardcoded cryptographic IV or salt detected — predictable values weaken encryption and hashing",
                          "Generate dynamic, cryptographically secure random IVs and salts using os.urandom() or secrets.token_bytes().")

        # MP031 — Insecure ML model deserialization (torch.load without weights_only=True)
        elif (
            (obj in ("torch",) and method == "load")
            or full_func in ("torch.load",)
        ):
            has_weights_only = False
            for kw in node.keywords:
                if kw.arg == "weights_only" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    has_weights_only = True
            if not has_weights_only:
                self._add(node, "MP031", Severity.CRITICAL.value,
                          "torch.load() without weights_only=True can execute arbitrary pickle bytecode — remote code execution risk",
                          "Use torch.load(path, weights_only=True) to safely load only tensor weights without executing pickle bytecode.")

        # MP034 — LDAP Injection via dynamic filter construction
        elif (
            (obj in ("ldap", "ldap3", "Connection", "conn", "c") and method in ("search", "search_s", "search_ext", "search_ext_s"))
            or full_func in ("ldap.search", "ldap.search_s", "ldap3.Connection.search")
        ):
            if node.args and len(node.args) >= 2:
                filter_arg = node.args[1] if len(node.args) > 1 else None
                if filter_arg and isinstance(filter_arg, (ast.JoinedStr, ast.BinOp)):
                    self._add(node, "MP034", Severity.HIGH.value,
                              "LDAP injection risk: search filter constructed via string formatting with dynamic input",
                              "Sanitize all user-controlled input using ldap.filter.escape_filter_chars() before embedding in LDAP filters.")
                elif filter_arg and isinstance(filter_arg, ast.Call) and isinstance(filter_arg.func, ast.Attribute):
                    if filter_arg.func.attr == "format":
                        self._add(node, "MP034", Severity.HIGH.value,
                                  "LDAP injection risk: search filter constructed via .format() with dynamic input",
                                  "Sanitize all user-controlled input using ldap.filter.escape_filter_chars() before embedding in LDAP filters.")

        # MP035 — XPath Injection via unparameterized dynamic expression
        elif (
            (obj in ("etree", "tree", "root", "doc") and method in ("xpath", "find", "findall", "iterfind"))
            or (func_name == "XPath" and isinstance(node.func, ast.Name))
            or full_func in ("lxml.etree.XPath", "etree.XPath")
        ):
            if node.args:
                expr_arg = node.args[0]
                is_dynamic = (
                    isinstance(expr_arg, (ast.JoinedStr, ast.BinOp))
                    or (isinstance(expr_arg, ast.Call) and isinstance(expr_arg.func, ast.Attribute) and expr_arg.func.attr == "format")
                )
                if is_dynamic:
                    self._add(node, "MP035", Severity.HIGH.value,
                              "XPath injection risk: XPath expression constructed via string formatting with dynamic input",
                              "Use parameterized XPath with a dictionary of variables (e.g. etree.XPath('//item[@id=$val]')(tree, val=user_input)) or sanitize input before use.")

        self._extra_call_checks(node)
        self.generic_visit(node)

    # ── MP032 / MP033 extra visitors ─────────────────────────────────────────

    # Patterns indicative of catastrophic exponential backtracking (ReDoS)
    _REDOS_PATTERNS = re.compile(  # nosec: MP032 — intentional ReDoS detection pattern, not user-controlled
        r"""
        (\([^)]*[+*]\)+[+*])   # (a+)+ style nested
        |(\([^)]*\)[*+]\{)     # (a){m,n}+ overlapping
        |(\[[^\]]+\][+*]\{)    # [a-z]+{m,n}
        |(\([^)]*[|][^)]*\)[+*]\{)  # alternation + repeat
        |(\([^)]*\+[^)]*\)\+)  # inner + with outer +
        """,
        re.VERBOSE,
    )

    def _check_redos(self, node: ast.Call, pattern_arg: ast.expr) -> None:
        """Check a compiled/called regex pattern argument for ReDoS signatures."""
        if not isinstance(pattern_arg, ast.Constant) or not isinstance(pattern_arg.value, str):
            return
        pattern_str = pattern_arg.value
        if self._REDOS_PATTERNS.search(pattern_str):
            self._add(node, "MP032", Severity.HIGH.value,
                      f"Regular Expression Denial of Service (ReDoS) risk: nested quantifiers in pattern '{pattern_str[:60]}'",
                      "Rewrite the regex to avoid nested quantifiers like (a+)+, ([a-z]+)*, (a|aa)+. Use atomic groups or possessive quantifiers if available.")

    def visit_Call_mp032_mp033(self, node: ast.Call) -> None:
        """
        Secondary visitor pass for MP032 (ReDoS) and MP033 (world-writable chmod).
        Called from the main visit_Call via the check below.
        """
        pass  # Logic injected directly into visit_Call chain via _extra_call_checks

    def _extra_call_checks(self, node: ast.Call) -> None:
        """
        Run additional per-call checks that are independent of the main elif chain.
        Called unconditionally at the end of visit_Call processing.
        """
        func_name = self._get_func_name(node)
        obj, method = self._get_attr_chain(node)
        full_func = self._get_full_func_name(node)

        # MP032 — ReDoS: re.compile() or re.match/search/fullmatch with dangerous pattern
        if (obj == "re" and method in ("compile", "match", "search", "fullmatch", "sub", "findall", "split")) or (
            func_name in ("compile",) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "re"
        ):
            if node.args:
                self._check_redos(node, node.args[0])

        # MP033 — World-writable chmod 0o777 / 0o666 / 0o757 etc.
        if ((obj == "os" and method == "chmod") or full_func == "os.chmod") and len(node.args) >= 2:
            arg1 = node.args[1]
            if isinstance(arg1, ast.Constant) and isinstance(arg1.value, int):
                # 0o777 → & 0o022 != 0 means group-or-world writable
                # We specifically flag world-writable (others write bit 0o002)
                # and also the common insecure pattern 0o777
                if arg1.value in (0o777, 0o666, 0o776, 0o775, 0o757, 0o755 | 0o022):
                    # Only flag if it's strictly world-writable beyond MP021's coverage
                    if arg1.value == 0o777:
                        self._add(node, "MP033", Severity.MEDIUM.value,
                                  f"os.chmod() sets fully permissive mode {oct(arg1.value)} (world-readable, writable, and executable)",
                                  "Use restrictive permissions: 0o600 for private files, 0o644 for readable files, 0o700 for private executables.")

    def visit_Assert(self, node: ast.Assert) -> None:
        """MP010 — assert used for security checks (stripped in optimized mode)."""
        # Skip assert statements in test files (tests use assertions legitimately)
        base_name = os.path.basename(self.file_path)
        path_parts = set(self.file_path.replace("\\", "/").split("/"))
        if (
            base_name.startswith("test_")
            or base_name.endswith("_test.py")
            or bool(path_parts & {"tests", "test", "testing", "fixtures"})
        ):
            self.generic_visit(node)
            return

        self._add(node, "MP010", Severity.LOW.value,
                  "assert statement: assertions are stripped when Python runs with -O (optimized)",
                  "Do not use assert for security validation. Use explicit if checks with exceptions.")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """MP011 — Detect DEBUG = True assignments."""
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "DEBUG":
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                    self._add(node, "MP011", Severity.MEDIUM.value,
                              "DEBUG = True detected — ensure this is not in production configuration",
                              "Use environment variables to control debug mode: "
                              "DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'.")
        self.generic_visit(node)


# ─── Main Scanner ─────────────────────────────────────────────────────────────

EXCLUDE_DIRS = {
    "node_modules", ".git", "__pycache__", "venv", ".venv",
    "dist", "build", ".eggs", "site-packages", "tests", "test",
    "testing", "fixtures",
}


def is_suppressed(finding: SASTFinding, source_lines: List[str]) -> bool:
    """
    Check if a SAST finding is suppressed via inline or file-level comment.
    Supported comments:
      - # maunprekshak: disable-file or # maunprekshak: disable-file[MP001, MP004]
      - # maunprekshak: ignore or # maunprekshak: ignore[MP001, MP004]
      - # nosec or # nosec: MP001
    """
    # 1. File-level suppression
    for line in source_lines[:25]:
        line_clean = line.strip().lower()
        if "maunprekshak: disable-file" in line_clean or "maunprekshak:disable-file" in line_clean:
            match = re.search(r"disable-file(?:\[(.*?)\])?", line_clean)
            if match:
                rules_str = match.group(1)
                if not rules_str:
                    return True
                rules = [r.strip().upper() for r in rules_str.split(",") if r.strip()]
                if finding.check_id.upper() in rules:
                    return True

    # 2. Line-level suppression
    target_indices = []
    line_num = finding.line
    if 1 <= line_num <= len(source_lines):
        target_indices.append(line_num - 1)
    if line_num - 2 >= 0 and line_num - 2 < len(source_lines):
        target_indices.append(line_num - 2)

    for idx in target_indices:
        text = source_lines[idx].strip()
        if "#" not in text:
            continue
        comment = text[text.find("#") :].lower()

        if "maunprekshak: ignore" in comment or "maunprekshak:ignore" in comment:
            match = re.search(r"ignore(?:\[(.*?)\])?", comment)
            if match:
                rules_str = match.group(1)
                if not rules_str:
                    return True
                rules = [r.strip().upper() for r in rules_str.split(",") if r.strip()]
                if finding.check_id.upper() in rules:
                    return True

        if "nosec" in comment:
            match = re.search(r"nosec(?::\s*(.*?))?(?:\s|$)", comment)
            if match:
                rules_str = match.group(1)
                if not rules_str:
                    return True
                rules = [r.strip().upper() for r in rules_str.split(",") if r.strip()]
                if finding.check_id.upper() in rules:
                    return True

    return False


def _scan_single_py_file(file_path: str) -> List[SASTFinding]:
    """Scan a single Python source file for AST security issues."""
    findings: List[SASTFinding] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()

        source_lines = source.splitlines()
        tree = ast.parse(source, filename=file_path)
        visitor = SecurityVisitor(file_path, source_lines)
        visitor.visit(tree)
        for finding in visitor.findings:
            if not is_suppressed(finding, source_lines):
                findings.append(finding)
    except SyntaxError:
        pass  # Skip files with syntax errors
    except Exception:
        pass
    return findings


def scan_sast(
    path: str,
    exclude: Optional[List[str]] = None,
    target_files: Optional[List[str]] = None,
) -> List[SASTFinding]:
    """
    Scan Python files in the project directory for security issues.

    Args:
        path: Absolute path to the project root directory.
        exclude: Optional list of additional directories to exclude.
        target_files: Optional list of specific files to check (e.g. for git diff / staged mode).

    Returns:
        List of SASTFinding objects, sorted by severity then file/line.
    """
    findings: List[SASTFinding] = []
    active_excludes = set(EXCLUDE_DIRS)
    if exclude:
        active_excludes.update(exclude)

    if target_files is not None:
        for f in target_files:
            abs_path = f if os.path.isabs(f) else os.path.join(path, f)
            if not os.path.isfile(abs_path) or not abs_path.endswith(".py"):
                continue
            path_parts = set(abs_path.replace("\\", "/").split("/"))
            if path_parts & active_excludes:
                continue
            findings.extend(_scan_single_py_file(abs_path))
    else:
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in active_excludes]
            for filename in files:
                if not filename.endswith(".py"):
                    continue
                file_path = os.path.join(root, filename)
                findings.extend(_scan_single_py_file(file_path))

    # Sort: CRITICAL first, then by file + line
    severity_order = {
        Severity.CRITICAL.value: 0,
        Severity.HIGH.value: 1,
        Severity.MEDIUM.value: 2,
        Severity.LOW.value: 3,
    }
    findings.sort(key=lambda f: (severity_order.get(f.severity, 9), f.file_path, f.line))
    return findings
