import os
import re
from typing import List, Optional
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


def scan_secrets(path: str, exclude: Optional[List[str]] = None) -> List[SecretFinding]:
    """
    Scan all source and config files for hardcoded secrets and credentials.
    Suppresses common false positives (os.getenv, placeholders).
    """
    findings: List[SecretFinding] = []

    exclude_dirs = {
        "node_modules", ".git", "__pycache__", "venv", ".venv",
        "dist", "build", ".eggs", "site-packages", "tests", "test",
        "testing", "fixtures",
    }
    if exclude:
        exclude_dirs.update(exclude)

    valid_extensions = {".py", ".yaml", ".yml", ".json", ".cfg", ".ini", ".toml", ".pem", ".key"}
    compiled_patterns = {name: re.compile(pattern) for name, pattern in PATTERNS.items()}

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]

        for file in files:
            # Skip scanner internals to avoid self-referential false positives
            if file in SELF_EXCLUDE_FILES:
                continue

            _, ext = os.path.splitext(file)
            is_env_file = file.startswith(".env")
            if ext not in valid_extensions and not is_env_file:
                continue

            file_path = os.path.join(root, file)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line_content in enumerate(f, 1):
                        if any(sp.search(line_content) for sp in SAFE_PATTERNS):
                            continue
                        for secret_type, regex in compiled_patterns.items():
                            matches = regex.findall(line_content)
                            for match in matches:
                                value = match if isinstance(match, str) else match[0]
                                findings.append(SecretFinding(
                                    file_path=file_path,
                                    line=line_num,
                                    secret_type=secret_type,
                                    masked_value=mask_secret(value),
                                    severity=Severity.HIGH.value,
                                ))
            except Exception:
                pass

    return findings
