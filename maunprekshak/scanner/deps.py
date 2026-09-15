"""
MaunPrekshak — Dependency Vulnerability Scanner
Parses Python dependency files and queries OSV.dev for known CVEs.
"""
import asyncio
import json
import os
import re
import tomllib
from typing import List, Dict, Optional

import httpx

from maunprekshak.scanner.report import DepVulnerability, Severity

# ─── Parsers ──────────────────────────────────────────────────────────────────

def parse_requirements_file(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a requirements.txt file into (package, version) tuples.
    Supports ==, >=, <=, ~= version specifiers.
    Skips comments, blank lines, and -r/-e includes.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # Skip blanks, comments, and options
                if not line or line.startswith(("#", "-", "git+")):
                    continue
                # Strip inline comments
                line = line.split("#")[0].strip()
                # Match: package==1.2.3 or package>=1.0
                match = re.match(
                    r"^([A-Za-z0-9_\-\.]+)\s*(?:==|>=|<=|~=|!=)\s*([\d][^\s,;]*)",
                    line,
                )
                if match:
                    packages.append((match.group(1).lower(), match.group(2)))
                else:
                    # No version pin — include package with empty version
                    bare = re.match(r"^([A-Za-z0-9_\-\.]+)\s*$", line)
                    if bare:
                        packages.append((bare.group(1).lower(), ""))
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return packages


# Alias for backwards compatibility with older API
parse_requirements_txt = parse_requirements_file


def parse_pyproject_toml(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a pyproject.toml file and extract [project.dependencies].
    Supports PEP 508 dependency specifiers.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "rb") as f:
            data = tomllib.load(f)
        deps = data.get("project", {}).get("dependencies", [])
        for dep in deps:
            dep = str(dep).strip()
            match = re.match(
                r"^([A-Za-z0-9_\-\.]+)\s*(?:==|>=|<=|~=|!=)\s*([\d][^\s,;]*)",
                dep,
            )
            if match:
                packages.append((match.group(1).lower(), match.group(2)))
            else:
                bare = re.match(r"^([A-Za-z0-9_\-\.]+)\s*$", dep)
                if bare:
                    packages.append((bare.group(1).lower(), ""))
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return packages


def parse_pipfile(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a Pipfile and extract [packages] section.
    """
    packages: List[tuple[str, str]] = []
    try:
        import toml  # optional dependency
        with open(file_path, "r", encoding="utf-8") as f:
            data = toml.load(f)
        for pkg, version_spec in data.get("packages", {}).items():
            if isinstance(version_spec, str) and version_spec != "*":
                # Strip specifier symbols
                version = re.sub(r"^[=><~!]+", "", version_spec).strip()
                packages.append((pkg.lower(), version))
            else:
                packages.append((pkg.lower(), ""))
    except Exception:
        pass
    return packages


def parse_poetry_lock(file_path: str) -> List[tuple[str, str]]:
    """
    Parse poetry.lock and extract pinned packages from [[package]].
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "rb") as f:
            data = tomllib.load(f)
        for pkg in data.get("package", []):
            name = pkg.get("name")
            version = pkg.get("version")
            if name and version:
                packages.append((str(name).lower(), str(version).strip()))
    except Exception:
        pass
    return packages


def parse_pipfile_lock(file_path: str) -> List[tuple[str, str]]:
    """
    Parse Pipfile.lock and extract packages from default and develop sections.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for section in ("default", "develop"):
            for pkg, info in data.get(section, {}).items():
                if isinstance(info, dict):
                    version_str = info.get("version", "")
                    clean_ver = re.sub(r"^[=><~!]+", "", version_str).strip()
                    if clean_ver:
                        packages.append((pkg.lower(), clean_ver))
                    else:
                        packages.append((pkg.lower(), ""))
    except Exception:
        pass
    return packages


def parse_uv_lock(file_path: str) -> List[tuple[str, str]]:
    """
    Parse uv.lock and extract pinned packages from [[package]].
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "rb") as f:
            data = tomllib.load(f)
        for pkg in data.get("package", []):
            name = pkg.get("name")
            version = pkg.get("version")
            if name and version:
                packages.append((str(name).lower(), str(version).strip()))
    except Exception:
        pass
    return packages


# ─── OSV.dev API ──────────────────────────────────────────────────────────────

def _cvss_to_severity(cvss_score: float) -> str:
    """Map a CVSS v3 score to a severity label."""
    if cvss_score >= 9.0:
        return Severity.CRITICAL.value
    elif cvss_score >= 7.0:
        return Severity.HIGH.value
    elif cvss_score >= 4.0:
        return Severity.MEDIUM.value
    return Severity.LOW.value


def _extract_cvss_score(vuln: dict) -> float:
    """Extract the highest CVSS v3 score from an OSV vulnerability object."""
    for sev in vuln.get("severity", []):
        if sev.get("type") in ("CVSS_V3", "CVSS_V3_1"):
            score_str = sev.get("score", "")
            # OSV sometimes returns a full vector string like "CVSS:3.1/AV:N/..."
            # Extract just the base score from the last part or try numeric parse
            try:
                return float(score_str)
            except ValueError:
                # Try to find a numeric score via regex
                m = re.search(r"(\d+\.\d+)", score_str)
                if m:
                    return float(m.group(1))
    return 0.0


def _extract_fix_version(vuln: dict) -> str:
    """Extract the fixed version from an OSV vulnerability's affected ranges."""
    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return "No fix available"


async def _query_osv(package: str, version: str) -> List[DepVulnerability]:
    """
    Query the OSV.dev API for a single package+version combination.
    Returns a list of DepVulnerability objects.
    Retries once on network failure with a 1-second delay.
    """
    if not version:
        return []  # Skip packages with no version pin

    url = "https://api.osv.dev/v1/query"
    payload = {
        "version": version,
        "package": {"name": package, "ecosystem": "PyPI"},
    }
    timeout = httpx.Timeout(10.0)

    async with httpx.AsyncClient(timeout=timeout) as client:
        for attempt in range(2):
            try:
                response = await client.post(url, json=payload)
                response.raise_for_status()
                data = response.json()
                break
            except (httpx.RequestError, httpx.HTTPStatusError):
                if attempt == 1:
                    return []
                await asyncio.sleep(1)
        else:
            return []

    vulns: List[DepVulnerability] = []
    for vuln in data.get("vulns", []):
        cve_id = vuln.get("id", "UNKNOWN")
        description = vuln.get("summary") or vuln.get("details", "No description available")
        cvss_score = _extract_cvss_score(vuln)
        # Fall back to HIGH if no CVSS score but aliases exist (indicates real CVE)
        if cvss_score == 0.0 and vuln.get("aliases"):
            severity = Severity.HIGH.value
        else:
            severity = _cvss_to_severity(cvss_score)
        fix_version = _extract_fix_version(vuln)

        vulns.append(DepVulnerability(
            package=package,
            version=version,
            cve_id=cve_id,
            severity=severity,
            cvss_score=cvss_score,
            description=description[:300],
            fix_version=fix_version,
        ))
    return vulns


# ─── Main Scanner ─────────────────────────────────────────────────────────────

async def scan_dependencies(
    path: str,
    target_files: Optional[List[str]] = None,
) -> List[DepVulnerability]:
    """
    Scan all dependency files in a project directory for known CVEs.

    Looks for: poetry.lock, Pipfile.lock, uv.lock, requirements.txt, pyproject.toml, Pipfile

    Args:
        path: Absolute path to the project root directory.
        target_files: Optional list of specific files to check (e.g. for git diff / staged mode).

    Returns:
        List of DepVulnerability findings, possibly empty.
    """
    all_packages: Dict[str, str] = {}

    parsers = [
        ("poetry.lock", parse_poetry_lock),
        ("Pipfile.lock", parse_pipfile_lock),
        ("uv.lock", parse_uv_lock),
        ("requirements.txt", parse_requirements_file),
        ("pyproject.toml", parse_pyproject_toml),
        ("Pipfile", parse_pipfile),
    ]

    for filename, parser in parsers:
        file_path = os.path.join(path, filename)
        if target_files is not None:
            # Only scan if this dependency file is among the target files
            target_matched = any(
                os.path.abspath(f) == os.path.abspath(file_path) or os.path.basename(f) == filename
                for f in target_files
            )
            if not target_matched:
                continue

        if os.path.exists(file_path):
            for pkg, ver in parser(file_path):
                # Prefer pinned version over empty/unpinned
                if pkg not in all_packages or (ver and not all_packages[pkg]):
                    all_packages[pkg] = ver

    if not all_packages:
        return []

    # Fan out all OSV queries concurrently
    tasks = [_query_osv(pkg, ver) for pkg, ver in all_packages.items()]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    findings: List[DepVulnerability] = []
    for result in results:
        if isinstance(result, list):
            findings.extend(result)

    return findings
