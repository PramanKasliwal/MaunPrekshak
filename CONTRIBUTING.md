# Contributing to MaunPrekshak (मौन प्रेक्षक)

Thank you for your interest in making Python codebases safer! We welcome contributions from security researchers, Python developers, and open-source enthusiasts.

---

## 🛠️ Development Setup

1. **Fork & Clone** the repository:
   ```bash
   git clone https://github.com/cr4ckb0x/maunprekshak.git
   cd maunprekshak
   ```

2. **Create a virtual environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

3. **Run the test suite**:
   ```bash
   pytest tests/ -v
   ```

---

## 🔍 How to Contribute

### 1. Adding a New Secret Detector Rule
Exposed secret patterns are defined in `maunprekshak/scanner/secrets.py`:
- Add your regex pattern to the `PATTERNS` dictionary.
- Add a corresponding test case in `tests/test_secrets.py`.
- Ensure common false positives (e.g. `os.getenv(...)`, dummy placeholders) are suppressed by `SAFE_PATTERNS`.

### 2. Adding a New SAST AST Rule
Code security patterns are analyzed via Python AST in `maunprekshak/scanner/sast.py`:
- Implement a visitor method in `SecurityVisitor` (e.g. `visit_Call`, `visit_Import`).
- Assign a unique Check ID (e.g. `MP015`).
- Provide severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), clear description, and actionable remediation advice.
- Add a corresponding unit test in `tests/test_sast.py`.

### 3. Enhancing Dependency Scanning
Dependency vulnerability parsing is in `maunprekshak/scanner/deps.py`:
- Supports `requirements.txt`, `pyproject.toml`, and `Pipfile`.
- Queries OSV.dev batch/single API asynchronously using `httpx`.

---

## 🧪 Code Quality Standards

Before opening a pull request, please ensure:
1. All tests pass: `pytest tests/ -v`
2. Coverage remains high: `pytest tests/ --cov=maunprekshak`
3. Code is formatted cleanly with type annotations and docstrings.

---

## 🔒 Reporting Security Vulnerabilities

If you discover a security vulnerability in MaunPrekshak itself, please **do not open a public GitHub issue**. Instead, email us directly at `security@maunprekshak.dev` or use GitHub's private vulnerability reporting feature.
