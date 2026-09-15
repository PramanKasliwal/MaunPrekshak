"""
MaunPrekshak — SAST (Static Application Security Testing) Scanner
Uses Python's `ast` module to walk source code and detect insecure patterns.
"""
import ast
import os
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

    # ── Visitors ──────────────────────────────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._get_func_name(node)
        obj, method = self._get_attr_chain(node)

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

        self.generic_visit(node)

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
        findings.extend(visitor.findings)
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
