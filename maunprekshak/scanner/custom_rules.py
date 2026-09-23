"""
MaunPrekshak — Custom Rule Engine
Allows defining organization-specific or project-specific secret patterns and SAST rules
via .maunprekshak-rules.yaml, .maunprekshak-rules.toml, or CLI --rules-file.
"""
import ast
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from maunprekshak.scanner.report import SASTFinding, SecretFinding, Severity
from maunprekshak.scanner.secrets import mask_secret

try:
    import tomllib
except ImportError:
    try:
        import toml as tomllib  # type: ignore
    except ImportError:
        tomllib = None  # type: ignore


@dataclass
class CustomSecretRule:
    """User-defined pattern for discovering proprietary or domain-specific secrets."""
    id: str
    name: str
    regex: str
    severity: str = Severity.HIGH.value
    compiled: Optional[re.Pattern] = None

    def __post_init__(self):
        if self.compiled is None and self.regex:
            try:
                self.compiled = re.compile(self.regex)
            except re.error:
                self.compiled = None


@dataclass
class CustomSASTRule:
    """User-defined static analysis rule for identifying banned calls, imports, or patterns."""
    id: str
    name: str
    severity: str = Severity.MEDIUM.value
    description: str = ""
    recommendation: str = ""
    banned_calls: List[str] = field(default_factory=list)
    banned_imports: List[str] = field(default_factory=list)
    regex_patterns: List[str] = field(default_factory=list)
    compiled_patterns: List[re.Pattern] = field(default_factory=list)

    def __post_init__(self):
        if not self.compiled_patterns and self.regex_patterns:
            compiled = []
            for pat in self.regex_patterns:
                try:
                    compiled.append(re.compile(pat))
                except re.error:
                    pass
            self.compiled_patterns = compiled


@dataclass
class CustomRulesConfig:
    """Container for loaded custom rules."""
    secrets: List[CustomSecretRule] = field(default_factory=list)
    sast: List[CustomSASTRule] = field(default_factory=list)

    @property
    def total_rules(self) -> int:
        return len(self.secrets) + len(self.sast)



def _is_suppressed(line: str, check_id: Optional[str] = None) -> bool:
    """Check if line contains inline suppression comment."""
    lower = line.lower()
    if "# nosec" in lower:
        return True
    if "# maunprekshak: ignore" in lower or "# maunprekshak:ignore" in lower:
        return True
    if "# maunprekshak: ignore-secret" in lower:
        return True
    if check_id and f"ignore[{check_id.lower()}]" in lower:
        return True
    return False


def load_custom_rules(
    path: Optional[str] = None, root_dir: Optional[str] = None
) -> CustomRulesConfig:
    """
    Load custom rules from an explicit file path or auto-discover in root directory:
    - .maunprekshak-rules.yaml / .yml
    - .maunprekshak-rules.toml
    - [custom_rules] table in .maunprekshak.toml
    """
    config = CustomRulesConfig()
    search_dir = Path(root_dir).resolve() if root_dir else Path.cwd().resolve()
    if search_dir.is_file():
        search_dir = search_dir.parent

    target_file: Optional[Path] = None
    if path:
        p = Path(path).resolve()
        if p.is_file():
            target_file = p
    else:
        for candidate in [
            search_dir / ".maunprekshak-rules.yaml",
            search_dir / ".maunprekshak-rules.yml",
            search_dir / ".maunprekshak-rules.toml",
            search_dir / "maunprekshak-rules.yaml",
        ]:
            if candidate.is_file():
                target_file = candidate
                break

    if target_file is None:
        # Check .maunprekshak.toml for [custom_rules]
        cfg_candidate = search_dir / ".maunprekshak.toml"
        if cfg_candidate.is_file() and tomllib:
            try:
                with open(cfg_candidate, "rb") as f:
                    data = tomllib.load(f)
                custom_section = data.get("custom_rules")
                if custom_section and isinstance(custom_section, dict):
                    return _parse_rules_dict(custom_section)
            except Exception:
                pass
        return config

    try:
        if target_file.suffix in (".yaml", ".yml"):
            with open(target_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        elif target_file.suffix == ".toml" and tomllib:
            with open(target_file, "rb") as f:
                data = tomllib.load(f)
        else:
            data = None

        if isinstance(data, dict):
            # Check if rules are nested under top-level 'custom_rules' or at root
            root_data = data.get("custom_rules", data)
            return _parse_rules_dict(root_data)
    except Exception:
        pass

    return config


def _parse_rules_dict(data: Dict[str, Any]) -> CustomRulesConfig:
    """Parse dictionary representation into CustomRulesConfig."""
    secrets_list: List[CustomSecretRule] = []
    sast_list: List[CustomSASTRule] = []

    # Parse secrets rules
    raw_secrets = data.get("secrets", [])
    if isinstance(raw_secrets, list):
        for item in raw_secrets:
            if not isinstance(item, dict):
                continue
            r_id = str(item.get("id", f"CUST-SEC-{len(secrets_list) + 1:03d}"))
            r_name = str(item.get("name", "Custom Secret"))
            r_regex = str(item.get("regex", item.get("pattern", "")))
            r_sev = str(item.get("severity", Severity.HIGH.value)).upper()
            if r_sev not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                r_sev = Severity.HIGH.value
            if r_regex:
                rule = CustomSecretRule(id=r_id, name=r_name, regex=r_regex, severity=r_sev)
                if rule.compiled is not None:
                    secrets_list.append(rule)

    # Parse SAST rules
    raw_sast = data.get("sast", [])
    if isinstance(raw_sast, list):
        for item in raw_sast:
            if not isinstance(item, dict):
                continue
            r_id = str(item.get("id", f"CUST-SAST-{len(sast_list) + 1:03d}"))
            r_name = str(item.get("name", "Custom SAST Rule"))
            r_sev = str(item.get("severity", Severity.MEDIUM.value)).upper()
            if r_sev not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                r_sev = Severity.MEDIUM.value
            desc = str(item.get("description", r_name))
            rec = str(item.get("recommendation", "Review and remediate custom pattern."))
            b_calls = [str(c) for c in item.get("banned_calls", []) if isinstance(c, (str, int))]
            b_imports = [str(i) for i in item.get("banned_imports", []) if isinstance(i, (str, int))]
            r_patterns = [str(p) for p in item.get("regex_patterns", []) if isinstance(p, (str, int))]

            rule = CustomSASTRule(
                id=r_id,
                name=r_name,
                severity=r_sev,
                description=desc,
                recommendation=rec,
                banned_calls=b_calls,
                banned_imports=b_imports,
                regex_patterns=r_patterns,
            )
            sast_list.append(rule)

    return CustomRulesConfig(secrets=secrets_list, sast=sast_list)


def evaluate_custom_secrets(
    file_path: str,
    content: str,
    rules: List[CustomSecretRule],
) -> List[SecretFinding]:
    """Scan file lines for custom secret patterns."""
    findings: List[SecretFinding] = []
    if not rules:
        return findings

    lines = content.splitlines()
    for idx, line in enumerate(lines, start=1):
        if _is_suppressed(line):
            continue

        for rule in rules:
            if rule.compiled is None:
                continue
            m = rule.compiled.search(line)
            if m:
                val = m.group(0)
                findings.append(
                    SecretFinding(
                        file_path=file_path,
                        line=idx,
                        secret_type=f"{rule.id}: {rule.name}",
                        masked_value=mask_secret(val),
                        severity=rule.severity,
                    )
                )
    return findings


def _get_call_name(node: ast.AST) -> Optional[str]:
    """Extract full qualified function name from AST Call node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _get_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def evaluate_custom_sast(
    file_path: str,
    content: str,
    rules: List[CustomSASTRule],
) -> List[SASTFinding]:
    """Evaluate custom SAST rules using AST inspection and regex matching."""
    findings: List[SASTFinding] = []
    if not rules:
        return findings

    lines = content.splitlines()

    # 1. Regex-based pattern matching across source lines
    for rule in rules:
        if rule.compiled_patterns:
            for idx, line in enumerate(lines, start=1):
                if _is_suppressed(line, rule.id):
                    continue
                for pat in rule.compiled_patterns:
                    if pat.search(line):
                        findings.append(
                            SASTFinding(
                                file_path=file_path,
                                line=idx,
                                col=1,
                                check_id=rule.id,
                                severity=rule.severity,
                                description=f"{rule.name}: {rule.description}",
                                recommendation=rule.recommendation,
                                code_snippet=line.strip()[:120],
                            )
                        )
                        break

    # 2. Python AST analysis for banned calls and imports
    if file_path.endswith(".py"):
        try:
            tree = ast.parse(content, filename=file_path)
        except Exception:
            return findings

        for node in ast.walk(tree):
            lineno = getattr(node, "lineno", 1)
            col_offset = getattr(node, "col_offset", 0)
            code_snippet = lines[lineno - 1].strip() if 0 <= lineno - 1 < len(lines) else ""

            if 0 <= lineno - 1 < len(lines) and _is_suppressed(lines[lineno - 1]):
                continue

            # Check banned function calls
            if isinstance(node, ast.Call):
                call_name = _get_call_name(node.func)
                if call_name:
                    for rule in rules:
                        if _is_suppressed(code_snippet, rule.id):
                            continue
                        for banned in rule.banned_calls:
                            if call_name == banned or call_name.endswith(f".{banned}"):
                                findings.append(
                                    SASTFinding(
                                        file_path=file_path,
                                        line=lineno,
                                        col=col_offset,
                                        check_id=rule.id,
                                        severity=rule.severity,
                                        description=f"Banned call '{call_name}' detected. {rule.description}",
                                        recommendation=rule.recommendation,
                                        code_snippet=code_snippet[:120],
                                    )
                                )
                                break

            # Check banned imports
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    imp_name = alias.name
                    for rule in rules:
                        if _is_suppressed(code_snippet, rule.id):
                            continue
                        if imp_name in rule.banned_imports:
                            findings.append(
                                SASTFinding(
                                    file_path=file_path,
                                    line=lineno,
                                    col=col_offset,
                                    check_id=rule.id,
                                    severity=rule.severity,
                                    description=f"Banned import '{imp_name}' detected. {rule.description}",
                                    recommendation=rule.recommendation,
                                    code_snippet=code_snippet[:120],
                                )
                            )
                            break
            elif isinstance(node, ast.ImportFrom):
                mod_name = node.module or ""
                for rule in rules:
                    if _is_suppressed(code_snippet, rule.id):
                        continue
                    if mod_name in rule.banned_imports:
                        findings.append(
                            SASTFinding(
                                file_path=file_path,
                                line=lineno,
                                col=col_offset,
                                check_id=rule.id,
                                severity=rule.severity,
                                description=f"Banned module import '{mod_name}' detected. {rule.description}",
                                recommendation=rule.recommendation,
                                code_snippet=code_snippet[:120],
                            )
                        )
                        break

    return findings
