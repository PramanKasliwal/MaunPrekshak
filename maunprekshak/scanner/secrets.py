import math
import os
import re
from collections import Counter
from typing import List, Optional, Set
from maunprekshak.scanner.report import SecretFinding, Severity

# Secret patterns
PATTERNS = {
    "AWS Access Key ID": r"(?i)AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)(aws_secret_access_key|aws_secret_key|aws_secret)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?",
    "GCP API Key": r"(?i)AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token": r"(?i)gh[pousr]_[A-Za-z0-9_]{30,40}",
    "Stripe Secret/Publishable Key": r"(?i)(sk_live|pk_live)_[0-9a-zA-Z]{24}",
    "Stripe Webhook Secret": r"(?i)whsec_[0-9a-zA-Z]{24}",
    "Slack Token": r"(?i)xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}",
    "Slack Webhook": r"(?i)https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    "Twilio Auth Token": r"(?i)twilio.*['\"][0-9a-f]{32}['\"]",
    "SendGrid API Key": r"(?i)SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
    "Mailgun API Key": r"(?i)key-[0-9a-zA-Z]{32}",
    "SSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "JWT Secret": r"(?i)(jwt_secret|jwt_key)\s*[:=]\s*['\"][A-Za-z0-9\-_]{16,}['\"]",
    "OpenAI API Key": r"(?i)(?:sk-[A-Za-z0-9]{48}|sk-proj-[A-Za-z0-9_\-]{80,})",
    "Anthropic API Key": r"(?i)sk-ant-[A-Za-z0-9_\-]{80,}",
    "HuggingFace Token": r"hf_[A-Za-z0-9]{34}",
    "GitLab Personal Access Token": r"(?i)glpat-[0-9a-zA-Z_\-]{20,}",
    "GitHub Fine-Grained PAT": r"github_pat_[0-9a-zA-Z_]{82}",
    "Discord Bot Token": r"(?i)(?:bot\s+)?[MN][A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,39}",
    "HashiCorp Vault Token": r"(?i)(?:hvs\.[a-zA-Z0-9_-]{24,}|s\.[a-zA-Z0-9]{24,})",
    "Generic Secret": r"(?i)(secret|token|password|api_key)\s*[:=]\s*['\"][A-Za-z0-9\-_]{16,}['\"]"
}

SECRET_PATTERNS = PATTERNS

def mask_secret(secret: str) -> str:
    """Mask a secret value, showing first 4 and last 4 characters."""
    # Remove quotes
    secret = re.sub(r"['\"]", "", secret)
    
    if len(secret) <= 8:
        return "***"
    return f"{secret[:4]}***{secret[-4:]}"

SAFE_PATTERNS = [
    re.compile(r'os\.getenv\('),
    re.compile(r'os\.environ\.get\('),
    re.compile(r'environ\['),
    re.compile(r'your_.*_here', re.IGNORECASE),
    re.compile(r'\.\.\.$'),
    re.compile(r'r".*PRIVATE KEY'),    # Skip regex pattern definitions
    re.compile(r"r'.*PRIVATE KEY"),    # Skip regex pattern definitions
]

# Files to never scan for secrets (scanner internals, fixtures)
SELF_EXCLUDE_FILES = {
    "secrets.py",   # The scanner's own pattern file
}

UUID_PATTERN = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
CANDIDATE_TOKEN_PATTERN = re.compile(
    r"""['"]([A-Za-z0-9+/_\-]{16,128})['"]|(?:^|[\s=:])([A-Za-z0-9+/_\-]{20,128})"""
)
HEX_CHARS_PATTERN = re.compile(r"^[0-9a-fA-F]+$")
FILE_EXT_PATTERN = re.compile(r"\.(py|json|yaml|yml|toml|txt|html|css|js|ts|jsx|tsx|md|svg|png|jpg|lock|cfg|ini)$", re.IGNORECASE)

SUPPRESSION_KEYWORDS = {
    "example", "sample", "placeholder", "dummy", "test", "fake", "changeme", "your_",
    "localhost", "127.0.0.1", "0.0.0.0", "application/json", "text/plain", "schema.org"
}


def calculate_shannon_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string: H(S) = -sum(p * log2(p)).
    Measures information density and randomness.
    """
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_suppressed_candidate(token: str, line_content: str) -> bool:
    """Check whether a candidate string should be suppressed as a false positive."""
    token_lower = token.lower()

    # Skip URLs
    if "http://" in line_content or "https://" in line_content or "ftp://" in line_content:
        if "://" in token:
            return True

    # Skip UUIDs
    if UUID_PATTERN.match(token):
        return True

    # Skip file paths or module imports
    if "/" in token or "\\" in token or FILE_EXT_PATTERN.search(token):
        return True

    # Skip placeholder / dummy values
    if any(kw in token_lower for kw in SUPPRESSION_KEYWORDS):
        return True

    # Skip pure lowercase or pure uppercase alphabetic strings (English words / identifiers)
    if token.isalpha() and (token.islower() or token.isupper()):
        return True

    # Repetitive characters: single char > 50% of string
    counts = Counter(token)
    if max(counts.values()) > len(token) * 0.5:
        return True

    return False


def scan_file_for_secrets(
    file_path: str,
    compiled_patterns: dict,
) -> List[SecretFinding]:
    """Scan a single file for regex secrets and high-entropy secrets."""
    findings: List[SecretFinding] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line_content in enumerate(f, 1):
                if any(sp.search(line_content) for sp in SAFE_PATTERNS):
                    continue

                # Check for inline suppression comments
                if "#" in line_content:
                    comment = line_content[line_content.find("#") :].lower()
                    if any(k in comment for k in ("maunprekshak: ignore", "maunprekshak:ignore", "nosec", "ignore-secret")):
                        continue
                if "//" in line_content:
                    comment = line_content[line_content.find("//") :].lower()
                    if any(k in comment for k in ("maunprekshak: ignore", "maunprekshak:ignore", "nosec", "ignore-secret")):
                        continue

                line_flagged_values: Set[str] = set()

                # 1. Regex pattern matches
                for secret_type, regex in compiled_patterns.items():
                    for match in regex.finditer(line_content):
                        matched_text = match.group(0)
                        # Filter generic secrets for dummy/placeholder values
                        if secret_type == "Generic Secret":
                            v_lower = matched_text.lower()
                            if any(p in v_lower for p in ("dummy", "placeholder", "fake", "changeme", "sample_token")):
                                continue
                        line_flagged_values.add(matched_text)
                        findings.append(SecretFinding(
                            file_path=file_path,
                            line=line_num,
                            secret_type=secret_type,
                            masked_value=mask_secret(matched_text),
                            severity=Severity.HIGH.value,
                        ))

                # 2. Shannon Entropy detection for un-prefixed/generic secrets
                for match in CANDIDATE_TOKEN_PATTERN.finditer(line_content):
                    candidate = match.group(1) or match.group(2)
                    if not candidate:
                        continue
                    candidate = candidate.strip("'\"")

                    # Avoid duplicate reporting if already caught by regex
                    if any(candidate in val or val in candidate for val in line_flagged_values):
                        continue

                    if _is_suppressed_candidate(candidate, line_content):
                        continue

                    # Hex string (>= 32 chars): Threshold 3.0
                    is_hex = bool(HEX_CHARS_PATTERN.match(candidate)) and len(candidate) >= 32
                    # Base64/Alphanumeric string (>= 20 chars): Threshold 4.5
                    is_base64 = len(candidate) >= 20 and not candidate.isalpha()

                    if is_hex or is_base64:
                        entropy = calculate_shannon_entropy(candidate)
                        threshold = 3.0 if is_hex else 4.5

                        if entropy >= threshold:
                            line_flagged_values.add(candidate)
                            secret_label = f"High-Entropy Token (Entropy: {entropy:.2f})"
                            findings.append(SecretFinding(
                                file_path=file_path,
                                line=line_num,
                                secret_type=secret_label,
                                masked_value=mask_secret(candidate),
                                severity=Severity.HIGH.value,
                            ))
    except Exception:
        pass
    return findings


def scan_secrets(
    path: str,
    exclude: Optional[List[str]] = None,
    target_files: Optional[List[str]] = None,
) -> List[SecretFinding]:
    """
    Scan source and config files for hardcoded secrets and credentials.
    Supports regex pattern detection and Shannon entropy token analysis.
    """
    findings: List[SecretFinding] = []

    exclude_dirs = {
        "node_modules", ".git", "__pycache__", "venv", ".venv",
        "dist", "build", ".eggs", "site-packages", "tests", "test",
        "testing", "fixtures",
    }
    if exclude:
        for e in exclude:
            cleaned = e.strip().rstrip("/\\")
            if cleaned.startswith("./"):
                cleaned = cleaned[2:]
            if cleaned:
                exclude_dirs.add(cleaned)
                base = os.path.basename(cleaned)
                if base:
                    exclude_dirs.add(base)

    valid_extensions = {".py", ".yaml", ".yml", ".json", ".cfg", ".ini", ".toml", ".pem", ".key", ".go", ".js", ".ts", ".env"}
    compiled_patterns = {name: re.compile(pattern) for name, pattern in PATTERNS.items()}

    # If target_files is provided, only inspect those files
    if target_files is not None:
        for file_path in target_files:
            abs_path = file_path if os.path.isabs(file_path) else os.path.join(path, file_path)
            if not os.path.isfile(abs_path):
                continue
            filename = os.path.basename(abs_path)
            if filename in SELF_EXCLUDE_FILES or filename in exclude_dirs:
                continue
            rel_file = os.path.relpath(abs_path, path).replace("\\", "/")
            path_parts = set(abs_path.replace("\\", "/").split("/"))
            if path_parts & exclude_dirs or rel_file in exclude_dirs:
                continue
            _, ext = os.path.splitext(filename)
            is_env_file = filename.startswith(".env")
            if ext not in valid_extensions and not is_env_file:
                continue

            findings.extend(scan_file_for_secrets(abs_path, compiled_patterns))
        return findings

    for root, dirs, files in os.walk(path):
        dirs[:] = [
            d for d in dirs
            if d not in exclude_dirs
            and os.path.relpath(os.path.join(root, d), path).replace("\\", "/") not in exclude_dirs
        ]

        for file in files:
            # Skip scanner internals to avoid self-referential false positives
            if file in SELF_EXCLUDE_FILES or file in exclude_dirs:
                continue

            rel_file = os.path.relpath(os.path.join(root, file), path).replace("\\", "/")
            if rel_file in exclude_dirs:
                continue

            _, ext = os.path.splitext(file)
            is_env_file = file.startswith(".env")
            if ext not in valid_extensions and not is_env_file:
                continue

            file_path = os.path.join(root, file)
            findings.extend(scan_file_for_secrets(file_path, compiled_patterns))

    return findings
