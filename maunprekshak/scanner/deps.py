"""
MaunPrekshak — Dependency Vulnerability Scanner
Parses Python dependency files and queries OSV.dev for known CVEs.
"""
import asyncio
import json
import os
import re
import tomllib
import xml.etree.ElementTree as ET
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


def parse_package_json(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a package.json file and extract dependencies and devDependencies.
    Normalizes semver ranges (^, ~, >=, <=) to baseline version strings.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for section in ("dependencies", "devDependencies"):
            for pkg, ver_spec in data.get(section, {}).items():
                if isinstance(ver_spec, str):
                    clean_ver = re.sub(r"^[=><~^v\s]+", "", ver_spec).strip()
                    if clean_ver and re.match(r"^\d", clean_ver):
                        packages.append((pkg.lower(), clean_ver))
                    else:
                        packages.append((pkg.lower(), ""))
    except Exception:
        pass
    return packages


def parse_package_lock_json(file_path: str) -> List[tuple[str, str]]:
    """
    Parse package-lock.json (supporting v1, v2, and v3 schemas) and extract pinned packages.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if "packages" in data and isinstance(data["packages"], dict):
            for key, info in data["packages"].items():
                if not key or not isinstance(info, dict):
                    continue
                if "node_modules/" in key:
                    pkg_name = key.split("node_modules/")[-1].strip()
                    version = str(info.get("version", "")).strip()
                    if pkg_name and version:
                        packages.append((pkg_name.lower(), version))
        elif "dependencies" in data and isinstance(data["dependencies"], dict):
            for pkg_name, info in data["dependencies"].items():
                if isinstance(info, dict):
                    version = str(info.get("version", "")).strip()
                    if pkg_name and version:
                        packages.append((pkg_name.lower(), version))
    except Exception:
        pass
    return packages


def parse_yarn_lock(file_path: str) -> List[tuple[str, str]]:
    """
    Parse yarn.lock (v1 and v2/Berry) and extract package names and pinned versions.
    """
    packages: List[tuple[str, str]] = []
    current_pkg: Optional[str] = None
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                if not line.startswith(" ") and not line.startswith("\t") and (stripped.endswith(":") or stripped.endswith(",")):
                    first_entry = stripped.split(",")[0].strip().rstrip(":").strip('"').strip("'")
                    if "@" in first_entry:
                        idx = first_entry.rfind("@")
                        if idx > 0:
                            current_pkg = first_entry[:idx].strip()
                        else:
                            current_pkg = None
                    else:
                        current_pkg = first_entry
                elif current_pkg and (line.startswith(" ") or line.startswith("\t")):
                    if stripped.startswith("version ") or stripped.startswith("version:"):
                        ver_str = stripped.split(None, 1)[1].strip().strip('"').strip("'")
                        if ver_str:
                            packages.append((current_pkg.lower(), ver_str))
                        current_pkg = None
    except Exception:
        pass
    return packages


def parse_pnpm_lock_yaml(file_path: str) -> List[tuple[str, str]]:
    """
    Parse pnpm-lock.yaml and extract pinned package names and versions.
    Supports pnpm lockfile schemas (v5, v6, v9).
    """
    packages: List[tuple[str, str]] = []
    in_packages_section = False
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                if line.startswith("packages:"):
                    in_packages_section = True
                    continue
                elif not line.startswith(" ") and not line.startswith("\t") and in_packages_section:
                    break

                if in_packages_section and (line.startswith("  ") or line.startswith("\t")):
                    if stripped.endswith(":"):
                        entry = stripped.rstrip(":").strip("'\"").lstrip("/")
                        if "@" in entry:
                            idx = entry.rfind("@")
                            if idx > 0:
                                name = entry[:idx]
                                ver = entry[idx + 1:]
                                ver = ver.split("(")[0].strip()
                                if name and ver and re.match(r"^\d", ver):
                                    packages.append((name.lower(), ver))
                        elif "/" in entry:
                            parts = entry.rsplit("/", 1)
                            if len(parts) == 2:
                                name, ver = parts
                                ver = ver.split("(")[0].strip()
                                if name and ver and re.match(r"^\d", ver):
                                    packages.append((name.lower(), ver))
    except Exception:
        pass
    return packages


def parse_go_mod(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a go.mod file and extract required modules and versions.
    Handles both single-line 'require mod version' and 'require ( ... )' blocks.
    """
    packages: List[tuple[str, str]] = []
    in_require_block = False
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("//"):
                    continue

                if line == "require (" or line.startswith("require ("):
                    in_require_block = True
                    continue
                elif in_require_block and line == ")":
                    in_require_block = False
                    continue

                clean_line = line.split("//")[0].strip()

                if in_require_block:
                    parts = clean_line.split()
                    if len(parts) >= 2:
                        mod_name = parts[0]
                        version = parts[1]
                        packages.append((mod_name, version))
                elif clean_line.startswith("require "):
                    parts = clean_line[len("require "):].strip().split()
                    if len(parts) >= 2:
                        mod_name = parts[0]
                        version = parts[1]
                        packages.append((mod_name, version))
    except Exception:
        pass
    return packages


def parse_go_sum(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a go.sum file and extract unique pinned modules and versions.
    Lines follow: <module> <version>[/go.mod] <hash>
    """
    packages_map: Dict[str, str] = {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("//"):
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    mod_name = parts[0]
                    ver_raw = parts[1].split("/go.mod")[0]
                    if mod_name and ver_raw:
                        packages_map[mod_name] = ver_raw
    except Exception:
        pass
    return list(packages_map.items())


def parse_cargo_toml(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a Cargo.toml file and extract crate dependencies and versions.
    Checks [dependencies], [dev-dependencies], and [build-dependencies].
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "rb") as f:
            data = tomllib.load(f)
        sections = ["dependencies", "dev-dependencies", "build-dependencies"]
        for sec in sections:
            deps = data.get(sec, {})
            if isinstance(deps, dict):
                for name, spec in deps.items():
                    name = str(name).strip()
                    ver = ""
                    if isinstance(spec, str):
                        ver = re.sub(r"^[=><~^!]+", "", spec).strip()
                    elif isinstance(spec, dict):
                        ver_raw = str(spec.get("version", "")).strip()
                        ver = re.sub(r"^[=><~^!]+", "", ver_raw).strip()
                    if name:
                        packages.append((name, ver))
    except Exception:
        pass
    return packages


def parse_cargo_lock(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a Cargo.lock file and extract pinned crate names and versions.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "rb") as f:
            data = tomllib.load(f)
        for pkg in data.get("package", []):
            name = str(pkg.get("name", "")).strip()
            version = str(pkg.get("version", "")).strip()
            if name and version:
                packages.append((name, version))
    except Exception:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                cur_name = None
                for line in f:
                    line = line.strip()
                    if line.startswith("name ="):
                        cur_name = line.split("=", 1)[1].strip().strip('"\'')
                    elif cur_name and line.startswith("version ="):
                        ver = line.split("=", 1)[1].strip().strip('"\'')
                        packages.append((cur_name, ver))
                        cur_name = None
        except Exception:
            pass
    return packages


def parse_pom_xml(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a Maven pom.xml file and extract dependencies as (group:artifact, version).
    """
    packages: List[tuple[str, str]] = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        properties: Dict[str, str] = {}
        for child in root:
            tag = child.tag.split("}")[-1]
            if tag == "properties":
                for prop in child:
                    ptag = prop.tag.split("}")[-1]
                    pval = (prop.text or "").strip()
                    if ptag and pval:
                        properties[ptag] = pval

        for elem in root.iter():
            if elem.tag.split("}")[-1] == "dependency":
                group = ""
                artifact = ""
                version = ""
                for child in elem:
                    ctag = child.tag.split("}")[-1]
                    ctext = (child.text or "").strip()
                    if ctag == "groupId":
                        group = ctext
                    elif ctag == "artifactId":
                        artifact = ctext
                    elif ctag == "version":
                        version = ctext

                if group and artifact:
                    if version.startswith("${") and version.endswith("}"):
                        prop_key = version[2:-1].strip()
                        version = properties.get(prop_key, "")
                    packages.append((f"{group}:{artifact}", version))
    except Exception:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            pattern = re.compile(
                r"<dependency>[\s\S]*?<groupId>([^<]+)</groupId>[\s\S]*?<artifactId>([^<]+)</artifactId>(?:[\s\S]*?<version>([^<]+)</version>)?[\s\S]*?</dependency>",
                re.IGNORECASE,
            )
            for m in pattern.finditer(content):
                grp = m.group(1).strip()
                art = m.group(2).strip()
                ver = (m.group(3) or "").strip()
                if not ver.startswith("${"):
                    packages.append((f"{grp}:{art}", ver))
                else:
                    packages.append((f"{grp}:{art}", ""))
        except Exception:
            pass
    return packages


def parse_gradle_file(file_path: str) -> List[tuple[str, str]]:
    """
    Parse build.gradle or build.gradle.kts and extract dependencies.
    Matches string notation ('group:name:version') and map notation (group: '...', name: '...', version: '...').
    """
    packages: List[tuple[str, str]] = []
    str_pattern = re.compile(
        r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation|classpath)\s*\(?\s*['"]([a-zA-Z0-9_\-\.]+):([a-zA-Z0-9_\-\.]+):([a-zA-Z0-9_\-\.\+]+)['"]\s*\)?""",
        re.IGNORECASE,
    )
    map_pattern = re.compile(
        r"""group:\s*['"]([^'"]+)['"],\s*name:\s*['"]([^'"]+)['"](?:,\s*version:\s*['"]([^'"]+)['"])?""",
        re.IGNORECASE,
    )
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(("//", "/*", "*")):
                    continue
                m1 = str_pattern.search(line)
                if m1:
                    packages.append((f"{m1.group(1)}:{m1.group(2)}", m1.group(3)))
                    continue
                m2 = map_pattern.search(line)
                if m2:
                    packages.append((f"{m2.group(1)}:{m2.group(2)}", m2.group(3) or ""))
    except Exception:
        pass
    return packages


def parse_gradle_lockfile(file_path: str) -> List[tuple[str, str]]:
    """
    Parse gradle.lockfile and extract pinned group:artifact:version coordinates.
    Lines follow: org.springframework:spring-core:5.3.18=compileClasspath,runtimeClasspath
    """
    packages: List[tuple[str, str]] = []
    pattern = re.compile(r"^([a-zA-Z0-9_\-\.]+):([a-zA-Z0-9_\-\.]+):([a-zA-Z0-9_\-\.\+]+)=")
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = pattern.match(line)
                if m:
                    packages.append((f"{m.group(1)}:{m.group(2)}", m.group(3)))
    except Exception:
        pass
    return packages


def parse_composer_lock(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a composer.lock file and extract pinned PHP packages and versions.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        for section in ("packages", "packages-dev"):
            for item in data.get(section, []):
                if isinstance(item, dict):
                    name = str(item.get("name", "")).strip()
                    ver = str(item.get("version", "")).strip()
                    clean_ver = ver.lstrip("v").strip()
                    if name and clean_ver:
                        packages.append((name.lower(), clean_ver))
    except Exception:
        pass
    return packages


def parse_composer_json(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a composer.json file and extract direct dependencies.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        for section in ("require", "require-dev"):
            for pkg, ver_spec in data.get(section, {}).items():
                pkg_name = str(pkg).strip()
                if pkg_name.lower() == "php" or pkg_name.startswith("ext-") or pkg_name == "composer-plugin-api":
                    continue
                ver_clean = re.sub(r"^[=><~^v\s]+", "", str(ver_spec)).strip()
                if ver_clean and re.match(r"^\d", ver_clean):
                    packages.append((pkg_name.lower(), ver_clean))
                else:
                    packages.append((pkg_name.lower(), ""))
    except Exception:
        pass
    return packages


def parse_csproj(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a .NET project file (*.csproj, *.fsproj, *.vbproj) and extract PackageReference dependencies.
    """
    packages: List[tuple[str, str]] = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        for elem in root.iter():
            tag = elem.tag.split("}")[-1]
            if tag == "PackageReference":
                pkg_name = elem.attrib.get("Include") or elem.attrib.get("Update") or ""
                version = elem.attrib.get("Version") or ""
                if not version:
                    for child in elem:
                        ctag = child.tag.split("}")[-1]
                        if ctag == "Version":
                            version = (child.text or "").strip()
                            break
                pkg_name = pkg_name.strip()
                version = version.strip()
                if pkg_name:
                    clean_ver = re.sub(r"^[=><~^v\s]+", "", version).strip()
                    packages.append((pkg_name, clean_ver))
    except Exception:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            pattern = re.compile(
                r"""<PackageReference\s+[^>]*?(?:Include|Update)=['"]([^'"]+)['"][^>]*?(?:Version=['"]([^'"]+)['"]|>[^<]*<Version>([^<]+)</Version>)""",
                re.IGNORECASE,
            )
            for m in pattern.finditer(content):
                pkg = m.group(1).strip()
                ver = (m.group(2) or m.group(3) or "").strip()
                clean_ver = re.sub(r"^[=><~^v\s]+", "", ver).strip()
                if pkg:
                    packages.append((pkg, clean_ver))
        except Exception:
            pass
    return packages


def parse_packages_config(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a legacy .NET packages.config XML file and extract package id and version.
    """
    packages: List[tuple[str, str]] = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        for elem in root.iter():
            tag = elem.tag.split("}")[-1]
            if tag == "package":
                pkg_id = elem.attrib.get("id", "").strip()
                version = elem.attrib.get("version", "").strip()
                if pkg_id:
                    clean_ver = re.sub(r"^[=><~^v\s]+", "", version).strip()
                    packages.append((pkg_id, clean_ver))
    except Exception:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            pattern = re.compile(
                r"""<package\s+[^>]*?id=['"]([^'"]+)['"][^>]*?version=['"]([^'"]+)['"]""",
                re.IGNORECASE,
            )
            for m in pattern.finditer(content):
                pkg = m.group(1).strip()
                ver = m.group(2).strip()
                clean_ver = re.sub(r"^[=><~^v\s]+", "", ver).strip()
                if pkg:
                    packages.append((pkg, clean_ver))
        except Exception:
            pass
    return packages


def parse_packages_lock_json(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a .NET packages.lock.json file and extract pinned package names and versions.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        deps = data.get("dependencies", {})
        if isinstance(deps, dict):
            for tfm, pkgs in deps.items():
                if isinstance(pkgs, dict):
                    for pkg_name, info in pkgs.items():
                        if isinstance(info, dict):
                            ver = str(info.get("resolved") or info.get("requested") or "").strip()
                            clean_ver = re.sub(r"^[=><~^v\s]+", "", ver).strip()
                            if pkg_name and clean_ver:
                                packages.append((pkg_name, clean_ver))
    except Exception:
        pass
    return packages


def parse_pubspec_yaml(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a Dart/Flutter pubspec.yaml file and extract direct dependencies.
    """
    packages: List[tuple[str, str]] = []
    in_deps_section = False
    cur_pkg = None
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                raw = line.split("#")[0].rstrip()
                if not raw:
                    continue
                if re.match(r"^(dependencies|dev_dependencies)\s*:", raw) and not raw.startswith(" "):
                    in_deps_section = True
                    cur_pkg = None
                    continue
                elif not raw.startswith(" ") and not raw.startswith("\t") and raw.endswith(":"):
                    in_deps_section = False
                    cur_pkg = None
                    continue

                if in_deps_section:
                    # Case 1: Nested version under package (e.g. 4 spaces "version: ^2.0.6")
                    if cur_pkg and re.match(r"^\s{4,8}version\s*:\s*(.+)$", raw):
                        v_val = re.match(r"^\s{4,8}version\s*:\s*(.+)$", raw).group(1).strip().strip("'\"")
                        clean_ver = re.sub(r"^[=><~^v\s]+", "", v_val).split()[0].strip()
                        if clean_ver and re.match(r"^\d", clean_ver):
                            packages.append((cur_pkg, clean_ver))
                        else:
                            packages.append((cur_pkg, ""))
                        cur_pkg = None
                        continue

                    # Case 2: Package with version on same line (e.g. 2 spaces "http: ^0.13.3")
                    m_pkg_ver = re.match(r"^\s{2}([a-zA-Z0-9_]+)\s*:\s*(.+)$", raw)
                    if m_pkg_ver:
                        pkg = m_pkg_ver.group(1).strip()
                        val = m_pkg_ver.group(2).strip().strip("'\"")
                        if pkg in ("flutter", "flutter_test") or val.startswith("sdk:"):
                            cur_pkg = None
                            continue
                        clean_ver = re.sub(r"^[=><~^v\s]+", "", val).split()[0].strip()
                        if clean_ver and re.match(r"^\d", clean_ver):
                            packages.append((pkg, clean_ver))
                        else:
                            packages.append((pkg, ""))
                        cur_pkg = None
                        continue

                    # Case 3: Package name only on line (e.g. 2 spaces "shared_preferences:")
                    m_pkg_only = re.match(r"^\s{2}([a-zA-Z0-9_]+)\s*:$", raw)
                    if m_pkg_only:
                        pkg = m_pkg_only.group(1).strip()
                        if pkg not in ("flutter", "flutter_test"):
                            cur_pkg = pkg
                        else:
                            cur_pkg = None
                        continue
    except Exception:
        pass
    return packages


def parse_pubspec_lock(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a Dart/Flutter pubspec.lock file and extract pinned package names and versions.
    """
    packages: List[tuple[str, str]] = []
    in_packages = False
    cur_pkg = None
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                raw = line.split("#")[0].rstrip()
                if not raw:
                    continue
                if re.match(r"^packages\s*:", raw) and not raw.startswith(" "):
                    in_packages = True
                    cur_pkg = None
                    continue
                elif not raw.startswith(" ") and not raw.startswith("\t") and raw.endswith(":"):
                    in_packages = False
                    cur_pkg = None
                    continue

                if in_packages:
                    m_pkg = re.match(r"^\s{2}([a-zA-Z0-9_]+)\s*:", raw)
                    if m_pkg:
                        cur_pkg = m_pkg.group(1).strip()
                    elif cur_pkg:
                        m_ver = re.match(r"^\s{4}version\s*:\s*['\"]?([^'\"\s]+)['\"]?", raw)
                        if m_ver:
                            ver = m_ver.group(1).strip()
                            if cur_pkg and ver and re.match(r"^\d", ver):
                                packages.append((cur_pkg, ver))
                            cur_pkg = None
    except Exception:
        pass
    return packages


def parse_gemfile(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a Ruby Gemfile and extract dependency gem names and version constraints.
    Supports gem 'name', '~> 1.2.3' and gem "name".
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                raw = line.split("#")[0].strip()
                if not raw:
                    continue
                match = re.match(
                    r"""^\s*gem\s+['"]([a-zA-Z0-9_\-\.]+)['"](?:\s*,\s*['"]([^'"]+)['"])?""",
                    raw,
                )
                if match:
                    pkg = match.group(1).lower()
                    ver_spec = match.group(2) or ""
                    version = re.sub(r"^[~>=<!\s]+", "", ver_spec).strip()
                    packages.append((pkg, version))
    except Exception:
        pass
    return packages


def parse_gemfile_lock(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a Ruby Gemfile.lock and extract pinned gem names and locked versions.
    """
    packages: List[tuple[str, str]] = []
    in_specs = False
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                raw = line.rstrip()
                if not raw:
                    continue
                if re.match(r"^\s{2}specs:\s*$", raw):
                    in_specs = True
                    continue
                elif in_specs and not raw.startswith(" "):
                    in_specs = False
                    continue
                elif in_specs and re.match(r"^\s{2}[A-Za-z0-9]", raw):
                    in_specs = False
                    continue

                if in_specs:
                    match = re.match(r"^\s{4}([a-zA-Z0-9_\-\.]+)\s*\(([0-9][^)]*)\)", raw)
                    if match:
                        pkg = match.group(1).lower()
                        ver = match.group(2).strip()
                        packages.append((pkg, ver))
    except Exception:
        pass
    return packages


def parse_mix_exs(file_path: str) -> List[tuple[str, str]]:
    """
    Parse an Elixir mix.exs project file and extract dependencies from deps.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        for match in re.finditer(
            r"""\{:([a-zA-Z0-9_\-]+)\s*(?:,\s*['"]([^'"]+)['"])?""",
            content,
        ):
            pkg = match.group(1).lower()
            ver_spec = match.group(2) or ""
            version = re.sub(r"^[~>=<!\s]+", "", ver_spec).strip()
            packages.append((pkg, version))
    except Exception:
        pass
    return packages


def parse_mix_lock(file_path: str) -> List[tuple[str, str]]:
    """
    Parse an Elixir mix.lock file and extract pinned package names and locked versions.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        for match in re.finditer(
            r'"([a-zA-Z0-9_\-]+)"\s*:\s*\{:hex,\s*:[a-zA-Z0-9_\-]+,\s*"([0-9][^"]*)"',
            content,
        ):
            pkg = match.group(1).lower()
            ver = match.group(2).strip()
            packages.append((pkg, ver))
    except Exception:
        pass
    return packages


def parse_package_swift(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a Swift Package.swift file and extract dependencies.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        for block in re.finditer(r"\.package\s*\(([^)]+)\)", content):
            block_text = block.group(1)
            url_match = re.search(r"""(?:url|path):\s*["']([^"']+)["']""", block_text)
            name_match = re.search(r"""name:\s*["']([^"']+)["']""", block_text)
            ver_match = re.search(r"""(?:from:\s*|exact:\s*|\.exact\s*\(\s*|["'])([0-9][0-9a-zA-Z\.\-]*)""", block_text)

            pkg = ""
            if name_match:
                pkg = name_match.group(1).lower()
            elif url_match:
                raw_url = url_match.group(1).strip()
                pkg = raw_url.rstrip("/").split("/")[-1]
                if pkg.endswith(".git"):
                    pkg = pkg[:-4]
                pkg = pkg.lower()

            ver = ver_match.group(1).strip() if ver_match else ""
            if pkg:
                packages.append((pkg, ver))
    except Exception:
        pass
    return packages


def parse_package_resolved(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a Swift Package.resolved file (V1 or V2 JSON) and extract pinned packages and versions.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)

        pins = []
        if isinstance(data, dict):
            if "pins" in data and isinstance(data["pins"], list):
                pins = data["pins"]
            elif "object" in data and isinstance(data["object"], dict) and "pins" in data["object"]:
                pins = data["object"]["pins"]

        for pin in pins:
            pkg = pin.get("identity") or pin.get("package") or ""
            if not pkg and pin.get("location"):
                pkg = pin["location"].rstrip("/").split("/")[-1]
                if pkg.endswith(".git"):
                    pkg = pkg[:-4]
            state = pin.get("state", {})
            ver = state.get("version") or ""
            if pkg:
                packages.append((str(pkg).lower(), str(ver)))
    except Exception:
        pass
    return packages


def parse_conanfile_txt(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a C/C++ conanfile.txt and extract packages in [requires] section.
    """
    packages: List[tuple[str, str]] = []
    in_requires = False
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                raw = line.strip()
                if not raw or raw.startswith("#"):
                    continue
                if raw.startswith("["):
                    in_requires = (raw.lower() == "[requires]")
                    continue
                if in_requires:
                    match = re.match(r"^([a-zA-Z0-9_\-\.]+)/([0-9a-zA-Z\.\-]+)", raw)
                    if match:
                        pkg = match.group(1).lower()
                        ver = match.group(2).strip()
                        packages.append((pkg, ver))
    except Exception:
        pass
    return packages


def parse_conan_lock(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a C/C++ conan.lock file and extract locked package names and versions.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)

        refs = []
        if isinstance(data, dict):
            graph = data.get("graph_lock", {})
            nodes = graph.get("nodes", {})
            for node in nodes.values():
                if isinstance(node, dict) and "ref" in node:
                    refs.append(node["ref"])
            if "requires" in data and isinstance(data["requires"], list):
                refs.extend(data["requires"])

        for ref in refs:
            clean_ref = ref.split("#")[0]
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)/([0-9a-zA-Z\.\-]+)", clean_ref)
            if match:
                pkg = match.group(1).lower()
                ver = match.group(2).strip()
                packages.append((pkg, ver))
    except Exception:
        pass
    return packages


def parse_vcpkg_json(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a C/C++ vcpkg.json manifest file and extract dependencies and version overrides.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)

        if isinstance(data, dict):
            # Parse "dependencies"
            deps = data.get("dependencies", [])
            if isinstance(deps, list):
                for dep in deps:
                    if isinstance(dep, str):
                        packages.append((dep.lower().strip(), ""))
                    elif isinstance(dep, dict) and "name" in dep:
                        pkg_name = str(dep["name"]).lower().strip()
                        ver = ""
                        for ver_key in ("version>=", "version", "version<=", "version="):
                            if ver_key in dep:
                                ver = str(dep[ver_key]).strip()
                                break
                        packages.append((pkg_name, ver))

            # Parse "overrides"
            overrides = data.get("overrides", [])
            if isinstance(overrides, list):
                for ov in overrides:
                    if isinstance(ov, dict) and "name" in ov:
                        pkg_name = str(ov["name"]).lower().strip()
                        ver = str(ov.get("version", "")).strip()
                        packages.append((pkg_name, ver))
    except Exception:
        pass
    return packages


def parse_stack_yaml(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a Haskell stack.yaml file and extract extra-deps dependencies.
    Example extra-deps:
      - text-1.2.5.0
      - aeson-2.1.2.1
    """
    packages: List[tuple[str, str]] = []
    in_extra_deps = False
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                raw = line.rstrip()
                stripped = raw.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if stripped.startswith("extra-deps:"):
                    in_extra_deps = True
                    continue
                if in_extra_deps:
                    if raw and not raw[0].isspace() and not stripped.startswith("-"):
                        in_extra_deps = False
                        continue
                    if stripped.startswith("-"):
                        item = stripped.lstrip("- ").strip()
                        if "-" in item and any(c.isdigit() for c in item):
                            pkg_candidate, _, ver_candidate = item.rpartition("-")
                            if pkg_candidate and ver_candidate and ver_candidate[0].isdigit():
                                packages.append((pkg_candidate.lower(), ver_candidate))
                                continue
                        m_ver = re.match(r"^([a-zA-Z0-9_\-]+)\s*(?:==|>=|<=|\^>=)\s*([0-9][^\s,]*)", item)
                        if m_ver:
                            packages.append((m_ver.group(1).lower(), m_ver.group(2)))
                        else:
                            bare = re.match(r"^([a-zA-Z0-9_\-]+)$", item)
                            if bare:
                                packages.append((bare.group(1).lower(), ""))
    except Exception:
        pass
    return packages


def parse_cabal_file(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a Haskell *.cabal file and extract packages from build-depends sections.
    """
    packages: List[tuple[str, str]] = []
    in_build_depends = False
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                raw = line.rstrip()
                stripped = raw.strip()
                if not stripped or stripped.startswith("--"):
                    continue
                lower = stripped.lower()
                if "build-depends:" in lower:
                    in_build_depends = True
                    rest = stripped.split(":", 1)[1].strip()
                    if rest:
                        tokens = [t.strip() for t in rest.split(",") if t.strip()]
                        for tok in tokens:
                            m = re.match(r"^([a-zA-Z0-9_\-]+)\s*(?:==|>=|<=|\^>=)\s*([0-9][0-9a-zA-Z\.\-]*)", tok)
                            if m:
                                packages.append((m.group(1).lower(), m.group(2)))
                            else:
                                bare = re.match(r"^([a-zA-Z0-9_\-]+)", tok)
                                if bare:
                                    packages.append((bare.group(1).lower(), ""))
                    continue
                if in_build_depends:
                    if raw and not raw[0].isspace():
                        in_build_depends = False
                        continue
                    tokens = [t.strip() for t in stripped.split(",") if t.strip()]
                    for tok in tokens:
                        m = re.match(r"^([a-zA-Z0-9_\-]+)\s*(?:==|>=|<=|\^>=)\s*([0-9][0-9a-zA-Z\.\-]*)", tok)
                        if m:
                            packages.append((m.group(1).lower(), m.group(2)))
                        else:
                            bare = re.match(r"^([a-zA-Z0-9_\-]+)", tok)
                            if bare:
                                packages.append((bare.group(1).lower(), ""))
    except Exception:
        pass
    return packages


def parse_cabal_project_freeze(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a Haskell cabal.project.freeze file and extract pinned package versions.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        matches = re.finditer(r"(?:any\.)?([a-zA-Z0-9_\-]+)\s*==\s*([0-9][0-9a-zA-Z\.\-]*)", content)
        for m in matches:
            pkg = m.group(1).lower()
            ver = m.group(2).strip()
            packages.append((pkg, ver))
    except Exception:
        pass
    return packages




def parse_podfile(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a CocoaPods Podfile and extract pod dependencies and version requirements.
    Supports: pod 'AFNetworking', '~> 4.0' or pod "SDWebImage", ">= 5.0" or pod 'SnapKit'.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                raw = line.split("#")[0].strip()
                if not raw:
                    continue
                match = re.match(
                    r"""^\s*pod\s+['"]([A-Za-z0-9_\-\.\/]+)['"](?:\s*,\s*['"]([^'"]+)['"])?""",
                    raw,
                )
                if match:
                    pkg = match.group(1).split("/")[0].strip()
                    ver_spec = match.group(2) or ""
                    version = re.sub(r"^[~>=<!\s]+", "", ver_spec).strip()
                    packages.append((pkg, version))
    except Exception:
        pass
    return packages


def parse_podfile_lock(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a CocoaPods Podfile.lock and extract pinned pod names and locked versions.
    Extracts entries from the PODS section.
    """
    packages: List[tuple[str, str]] = []
    in_pods = False
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                raw = line.rstrip()
                if not raw:
                    continue
                if re.match(r"^PODS:\s*$", raw):
                    in_pods = True
                    continue
                elif in_pods and raw and not raw[0].isspace():
                    in_pods = False
                    continue

                if in_pods:
                    match = re.match(r"^\s*-\s+([A-Za-z0-9_\-\.\/]+)\s*\(([0-9][^)]*)\)", raw)
                    if match:
                        pkg = match.group(1).split("/")[0].strip()
                        ver = re.sub(r"^[=~><!\s]+", "", match.group(2)).strip()
                        packages.append((pkg, ver))
    except Exception:
        pass
    return packages


def parse_cran_description(file_path: str) -> List[tuple[str, str]]:
    """
    Parse an R package DESCRIPTION file and extract CRAN dependencies from Imports and Depends.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        is_r_desc = any(line.startswith(("Package:", "Imports:", "Depends:")) for line in lines)
        if not is_r_desc:
            return []

        dep_sections: List[str] = []
        current_section: List[str] = []
        in_dep_field = False

        for line in lines:
            line_str = line.rstrip()
            if not line_str or line_str.startswith("#"):
                continue

            if line_str and not line_str[0].isspace():
                if in_dep_field and current_section:
                    dep_sections.append(" ".join(current_section))
                    current_section = []
                lower_field = line_str.lower()
                if lower_field.startswith("imports:") or lower_field.startswith("depends:"):
                    in_dep_field = True
                    content = line_str.split(":", 1)[1].strip()
                    if content:
                        current_section.append(content)
                else:
                    in_dep_field = False
            elif in_dep_field:
                current_section.append(line_str.strip())

        if in_dep_field and current_section:
            dep_sections.append(" ".join(current_section))

        for sec in dep_sections:
            tokens = [t.strip() for t in sec.split(",") if t.strip()]
            for tok in tokens:
                m = re.match(r"^([A-Za-z0-9_\.\-]+)(?:\s*\(([~>=<!\s]*[0-9][^)]*)\))?", tok)
                if m:
                    pkg = m.group(1).strip()
                    if pkg.lower() == "r":
                        continue
                    ver_spec = m.group(2) or ""
                    ver = re.sub(r"^[~>=<!\s]+", "", ver_spec).strip()
                    packages.append((pkg, ver))
    except Exception:
        pass
    return packages


def parse_github_actions_workflows(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a GitHub Actions workflow YAML file and extract third-party action dependencies.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        for line in lines:
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue

            m = re.search(r"""(?:^|\s)(?:-\s+)?uses:\s*['"]?([a-zA-Z0-9_\-\.\/]+@[a-zA-Z0-9_\-\.\/]+)['"]?""", line_str)
            if m:
                ref = m.group(1).strip()
                if ref.startswith(("./", "../", "docker://")):
                    continue
                action_name, version = ref.split("@", 1)
                packages.append((action_name.strip(), version.strip()))
    except Exception:
        pass
    return packages


def parse_julia_project(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a Julia Project.toml and extract dependencies and version constraints.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        in_deps = False
        in_compat = False
        deps: dict[str, str] = {}
        compat: dict[str, str] = {}

        for line in lines:
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue

            if line_str.startswith("["):
                header = line_str.strip("[]").strip().lower()
                in_deps = (header == "deps")
                in_compat = (header == "compat")
                continue

            if in_deps:
                m = re.match(r"^([A-Za-z0-9_]+)\s*=\s*[\"']?([^\"'\s]+)[\"']?", line_str)
                if m:
                    deps[m.group(1)] = ""
            elif in_compat:
                m = re.match(r"^([A-Za-z0-9_]+)\s*=\s*[\"']?([^\"'\s]+)[\"']?", line_str)
                if m:
                    compat[m.group(1)] = re.sub(r"^[~>=^<=\s]+", "", m.group(2)).strip()

        for pkg in deps:
            ver = compat.get(pkg, "")
            packages.append((pkg, ver))
    except Exception:
        pass
    return packages


def parse_julia_manifest(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a Julia Manifest.toml and extract pinned dependencies and versions.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        current_pkg = ""
        current_ver = ""

        for line in lines:
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue

            m_header = re.match(r"^\[{1,2}(?:deps\.)?([A-Za-z0-9_]+)\]{1,2}$", line_str)
            if m_header:
                if current_pkg and current_ver:
                    packages.append((current_pkg, current_ver))
                current_pkg = m_header.group(1)
                current_ver = ""
                continue

            if current_pkg and line_str.startswith("version"):
                m_ver = re.match(r'^version\s*=\s*["\']([^"\']+)["\']', line_str)
                if m_ver:
                    current_ver = m_ver.group(1)

        if current_pkg and current_ver:
            packages.append((current_pkg, current_ver))
    except Exception:
        pass
    return packages


def parse_brewfile(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a Homebrew Brewfile and extract brew packages and versions.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        for line in lines:
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue

            m = re.match(r"""^\s*brew\s+['"]([A-Za-z0-9_\.@\/\-]+)['"](?:\s*,\s*(?:.*version:\s*['"]([0-9\.]+)['"])?)?""", line_str)
            if m:
                pkg = m.group(1).strip()
                ver = m.group(2) or ""
                if not ver and "@" in pkg:
                    parts = pkg.split("@", 1)
                    ver = parts[1]
                packages.append((pkg, ver))
    except Exception:
        pass
    return packages


def parse_conda_environment(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a Conda environment.yml / environment.yaml manifest into (package, version) tuples.
    Extracts direct dependencies and nested pip dependencies.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        in_deps = False
        in_pip = False

        for line in lines:
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue

            if re.match(r"^[A-Za-z0-9_-]+:", line) and not line.startswith(" ") and not line.startswith("\t"):
                if line_str.startswith("dependencies:"):
                    in_deps = True
                    in_pip = False
                    continue
                else:
                    in_deps = False
                    in_pip = False
                    continue

            if in_deps:
                if re.match(r"^\s*-\s*pip\s*:", line):
                    in_pip = True
                    continue

                if in_pip:
                    m = re.match(r"^\s*-\s*([A-Za-z0-9_\-\.]+)\s*(?:==|>=|<=|~=|!=|=)\s*([0-9][^\s,;#]*)", line)
                    if m:
                        packages.append((m.group(1).lower(), m.group(2)))
                        continue
                    m_bare = re.match(r"^\s*-\s*([A-Za-z0-9_\-\.]+)", line)
                    if m_bare:
                        packages.append((m_bare.group(1).lower(), ""))
                        continue

                m = re.match(r"^\s*-\s*([A-Za-z0-9_\-\.]+)\s*(?:==|>=|<=|~=|!=|=)\s*([0-9][^\s,;#]*)", line)
                if m:
                    packages.append((m.group(1).lower(), m.group(2)))
                else:
                    m_bare = re.match(r"^\s*-\s*([A-Za-z0-9_\-\.]+)\s*$", line)
                    if m_bare and m_bare.group(1).lower() != "pip":
                        packages.append((m_bare.group(1).lower(), ""))
    except Exception:
        pass
    return packages


def parse_helm_chart(file_path: str) -> List[tuple[str, str]]:
    """
    Parse a Helm Chart.yaml or Chart.lock manifest and extract chart dependencies.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        in_deps = False
        current_dep: dict[str, str] = {}

        for line in lines:
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue

            if re.match(r"^[A-Za-z0-9_-]+:", line) and not line.startswith(" ") and not line.startswith("\t"):
                if line_str.startswith("dependencies:"):
                    in_deps = True
                    continue
                else:
                    if in_deps and "name" in current_dep:
                        packages.append((current_dep["name"], current_dep.get("version", "")))
                        current_dep = {}
                    in_deps = False
                    continue

            if in_deps:
                if re.match(r"^\s*-\s*", line):
                    if "name" in current_dep:
                        packages.append((current_dep["name"], current_dep.get("version", "")))
                        current_dep = {}

                m_name = re.search(r"(?:-\s+)?name:\s*['\"]?([^'\"\s]+)['\"]?", line_str)
                if m_name and "name" not in current_dep:
                    current_dep["name"] = m_name.group(1).strip()
                m_ver = re.search(r"version:\s*['\"]?([^'\"\s]+)['\"]?", line_str)
                if m_ver:
                    current_dep["version"] = m_ver.group(1).strip()

        if in_deps and "name" in current_dep:
            packages.append((current_dep["name"], current_dep.get("version", "")))
    except Exception:
        pass
    return packages


def parse_opam_file(file_path: str) -> List[tuple[str, str]]:
    """
    Parse an OCaml *.opam or opam manifest and extract package dependencies.
    """
    packages: List[tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        m_block = re.search(r"depends\s*[:=]\s*\[(.*?)\]", content, re.DOTALL)
        if not m_block:
            return packages

        block_content = m_block.group(1)
        block_content = re.sub(r"#.*", "", block_content)
        block_content = re.sub(r"\(\*.*?\*\)", "", block_content, flags=re.DOTALL)

        pattern = r"['\"]([a-zA-Z0-9_\-\.\+]+)['\"](?:\s*\{([^}]*)\})?"
        for match in re.finditer(pattern, block_content):
            pkg_name = match.group(1).strip()
            constraint = match.group(2)
            version = ""
            if constraint:
                m_ver = re.search(r"(?:>=|<=|==|=|~=|>|<)?\s*['\"]?([0-9][a-zA-Z0-9_\-\.\+]*)['\"]?", constraint)
                if m_ver:
                    version = m_ver.group(1).strip()
            packages.append((pkg_name, version))
    except Exception:
        pass
    return packages


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


async def _query_osv(package: str, version: str, ecosystem: str = "PyPI") -> List[DepVulnerability]:
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
        "package": {"name": package, "ecosystem": ecosystem},
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

    Looks for Python manifests: poetry.lock, Pipfile.lock, uv.lock, requirements.txt, pyproject.toml, Pipfile
    Looks for JavaScript/npm manifests: package-lock.json, yarn.lock, pnpm-lock.yaml, package.json
    Looks for Go manifests: go.sum, go.mod
    Looks for Rust manifests: Cargo.lock, Cargo.toml
    Looks for Java manifests: pom.xml, build.gradle, build.gradle.kts, gradle.lockfile
    Looks for PHP manifests: composer.lock, composer.json
    Looks for .NET NuGet manifests: packages.lock.json, packages.config, *.csproj, *.fsproj, *.vbproj
    Looks for Dart/Flutter Pub manifests: pubspec.lock, pubspec.yaml
    Looks for Ruby manifests: Gemfile.lock, Gemfile
    Looks for Elixir manifests: mix.lock, mix.exs
    Looks for Swift manifests: Package.resolved, Package.swift
    Looks for C/C++ manifests: conan.lock, conanfile.txt, vcpkg.json
    Looks for Haskell manifests: cabal.project.freeze, stack.yaml, *.cabal
    Looks for CocoaPods manifests: Podfile.lock, Podfile
    Looks for R CRAN manifests: DESCRIPTION
    Looks for GitHub Actions workflows: .github/workflows/*.yml, .github/workflows/*.yaml
    Looks for Julia manifests: Manifest.toml, Project.toml
    Looks for Homebrew manifests: Brewfile
    Looks for Conda manifests: environment.yml, environment.yaml
    Looks for Helm manifests: Chart.yaml, Chart.lock
    Looks for OCaml manifests: *.opam, opam

    Args:
        path: Absolute path to the project root directory.
        target_files: Optional list of specific files to check (e.g. for git diff / staged mode).

    Returns:
        List of DepVulnerability findings, possibly empty.
    """
    python_packages: Dict[str, str] = {}
    npm_packages: Dict[str, str] = {}
    go_packages: Dict[str, str] = {}
    cargo_packages: Dict[str, str] = {}
    maven_packages: Dict[str, str] = {}
    packagist_packages: Dict[str, str] = {}
    nuget_packages: Dict[str, str] = {}
    pub_packages: Dict[str, str] = {}
    rubygems_packages: Dict[str, str] = {}
    hex_packages: Dict[str, str] = {}
    swift_packages: Dict[str, str] = {}
    conan_packages: Dict[str, str] = {}
    vcpkg_packages: Dict[str, str] = {}
    hackage_packages: Dict[str, str] = {}
    cocoapods_packages: Dict[str, str] = {}
    cran_packages: Dict[str, str] = {}
    gha_packages: Dict[str, str] = {}
    julia_packages: Dict[str, str] = {}
    homebrew_packages: Dict[str, str] = {}
    conda_packages: Dict[str, str] = {}
    helm_packages: Dict[str, str] = {}
    opam_packages: Dict[str, str] = {}

    python_parsers = [
        ("poetry.lock", parse_poetry_lock),
        ("Pipfile.lock", parse_pipfile_lock),
        ("uv.lock", parse_uv_lock),
        ("requirements.txt", parse_requirements_file),
        ("pyproject.toml", parse_pyproject_toml),
        ("Pipfile", parse_pipfile),
    ]
    npm_parsers = [
        ("package-lock.json", parse_package_lock_json),
        ("yarn.lock", parse_yarn_lock),
        ("pnpm-lock.yaml", parse_pnpm_lock_yaml),
        ("package.json", parse_package_json),
    ]
    go_parsers = [
        ("go.sum", parse_go_sum),
        ("go.mod", parse_go_mod),
    ]
    cargo_parsers = [
        ("Cargo.lock", parse_cargo_lock),
        ("Cargo.toml", parse_cargo_toml),
    ]
    maven_parsers = [
        ("pom.xml", parse_pom_xml),
        ("build.gradle", parse_gradle_file),
        ("build.gradle.kts", parse_gradle_file),
        ("gradle.lockfile", parse_gradle_lockfile),
    ]
    packagist_parsers = [
        ("composer.lock", parse_composer_lock),
        ("composer.json", parse_composer_json),
    ]
    nuget_parsers = [
        ("packages.lock.json", parse_packages_lock_json),
        ("packages.config", parse_packages_config),
    ]
    pub_parsers = [
        ("pubspec.lock", parse_pubspec_lock),
        ("pubspec.yaml", parse_pubspec_yaml),
    ]
    rubygems_parsers = [
        ("Gemfile.lock", parse_gemfile_lock),
        ("Gemfile", parse_gemfile),
    ]
    hex_parsers = [
        ("mix.lock", parse_mix_lock),
        ("mix.exs", parse_mix_exs),
    ]
    swift_parsers = [
        ("Package.resolved", parse_package_resolved),
        ("Package.swift", parse_package_swift),
    ]
    conan_parsers = [
        ("conan.lock", parse_conan_lock),
        ("conanfile.txt", parse_conanfile_txt),
    ]
    vcpkg_parsers = [
        ("vcpkg.json", parse_vcpkg_json),
    ]
    hackage_parsers = [
        ("cabal.project.freeze", parse_cabal_project_freeze),
        ("stack.yaml", parse_stack_yaml),
    ]
    cocoapods_parsers = [
        ("Podfile.lock", parse_podfile_lock),
        ("Podfile", parse_podfile),
    ]
    cran_parsers = [
        ("DESCRIPTION", parse_cran_description),
    ]
    julia_parsers = [
        ("Manifest.toml", parse_julia_manifest),
        ("Project.toml", parse_julia_project),
    ]
    homebrew_parsers = [
        ("Brewfile", parse_brewfile),
    ]
    conda_parsers = [
        ("environment.yml", parse_conda_environment),
        ("environment.yaml", parse_conda_environment),
    ]
    helm_parsers = [
        ("Chart.yaml", parse_helm_chart),
        ("Chart.lock", parse_helm_chart),
    ]

    for filename, parser in python_parsers:
        file_path = os.path.join(path, filename)
        if target_files is not None:
            target_matched = any(
                os.path.abspath(f) == os.path.abspath(file_path) or os.path.basename(f) == filename
                for f in target_files
            )
            if not target_matched:
                continue

        if os.path.exists(file_path):
            for pkg, ver in parser(file_path):
                if pkg not in python_packages or (ver and not python_packages[pkg]):
                    python_packages[pkg] = ver

    for filename, parser in npm_parsers:
        file_path = os.path.join(path, filename)
        if target_files is not None:
            target_matched = any(
                os.path.abspath(f) == os.path.abspath(file_path) or os.path.basename(f) == filename
                for f in target_files
            )
            if not target_matched:
                continue

        if os.path.exists(file_path):
            for pkg, ver in parser(file_path):
                if pkg not in npm_packages or (ver and not npm_packages[pkg]):
                    npm_packages[pkg] = ver

    for filename, parser in go_parsers:
        file_path = os.path.join(path, filename)
        if target_files is not None:
            target_matched = any(
                os.path.abspath(f) == os.path.abspath(file_path) or os.path.basename(f) == filename
                for f in target_files
            )
            if not target_matched:
                continue

        if os.path.exists(file_path):
            for pkg, ver in parser(file_path):
                if pkg not in go_packages or (ver and not go_packages[pkg]):
                    go_packages[pkg] = ver

    for filename, parser in cargo_parsers:
        file_path = os.path.join(path, filename)
        if target_files is not None:
            target_matched = any(
                os.path.abspath(f) == os.path.abspath(file_path) or os.path.basename(f) == filename
                for f in target_files
            )
            if not target_matched:
                continue

        if os.path.exists(file_path):
            for pkg, ver in parser(file_path):
                if pkg not in cargo_packages or (ver and not cargo_packages[pkg]):
                    cargo_packages[pkg] = ver

    for filename, parser in maven_parsers:
        file_path = os.path.join(path, filename)
        if target_files is not None:
            target_matched = any(
                os.path.abspath(f) == os.path.abspath(file_path) or os.path.basename(f) == filename
                for f in target_files
            )
            if not target_matched:
                continue

        if os.path.exists(file_path):
            for pkg, ver in parser(file_path):
                if pkg not in maven_packages or (ver and not maven_packages[pkg]):
                    maven_packages[pkg] = ver

    for filename, parser in packagist_parsers:
        file_path = os.path.join(path, filename)
        if target_files is not None:
            target_matched = any(
                os.path.abspath(f) == os.path.abspath(file_path) or os.path.basename(f) == filename
                for f in target_files
            )
            if not target_matched:
                continue

        if os.path.exists(file_path):
            for pkg, ver in parser(file_path):
                if pkg not in packagist_packages or (ver and not packagist_packages[pkg]):
                    packagist_packages[pkg] = ver

    for filename, parser in nuget_parsers:
        file_path = os.path.join(path, filename)
        if target_files is not None:
            target_matched = any(
                os.path.abspath(f) == os.path.abspath(file_path) or os.path.basename(f) == filename
                for f in target_files
            )
            if not target_matched:
                continue

        if os.path.exists(file_path):
            for pkg, ver in parser(file_path):
                if pkg not in nuget_packages or (ver and not nuget_packages[pkg]):
                    nuget_packages[pkg] = ver

    # Scan for .NET project files (*.csproj, *.fsproj, *.vbproj)
    dotnet_files = []
    if target_files is not None:
        dotnet_files = [f for f in target_files if f.endswith((".csproj", ".fsproj", ".vbproj"))]
    else:
        try:
            for root_dir, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "bin", "obj", ".vs", "venv", ".venv")]
                for file in files:
                    if file.endswith((".csproj", ".fsproj", ".vbproj")):
                        dotnet_files.append(os.path.join(root_dir, file))
        except Exception:
            pass

    for proj_file in dotnet_files:
        if os.path.exists(proj_file):
            for pkg, ver in parse_csproj(proj_file):
                if pkg not in nuget_packages or (ver and not nuget_packages[pkg]):
                    nuget_packages[pkg] = ver

    for filename, parser in pub_parsers:
        file_path = os.path.join(path, filename)
        if target_files is not None:
            target_matched = any(
                os.path.abspath(f) == os.path.abspath(file_path) or os.path.basename(f) == filename
                for f in target_files
            )
            if not target_matched:
                continue

        if os.path.exists(file_path):
            for pkg, ver in parser(file_path):
                if pkg not in pub_packages or (ver and not pub_packages[pkg]):
                    pub_packages[pkg] = ver

    for filename, parser in rubygems_parsers:
        file_path = os.path.join(path, filename)
        if target_files is not None:
            target_matched = any(
                os.path.abspath(f) == os.path.abspath(file_path) or os.path.basename(f) == filename
                for f in target_files
            )
            if not target_matched:
                continue

        if os.path.exists(file_path):
            for pkg, ver in parser(file_path):
                if pkg not in rubygems_packages or (ver and not rubygems_packages[pkg]):
                    rubygems_packages[pkg] = ver

    for filename, parser in hex_parsers:
        file_path = os.path.join(path, filename)
        if target_files is not None:
            target_matched = any(
                os.path.abspath(f) == os.path.abspath(file_path) or os.path.basename(f) == filename
                for f in target_files
            )
            if not target_matched:
                continue

        if os.path.exists(file_path):
            for pkg, ver in parser(file_path):
                if pkg not in hex_packages or (ver and not hex_packages[pkg]):
                    hex_packages[pkg] = ver

    for filename, parser in swift_parsers:
        file_path = os.path.join(path, filename)
        if target_files is not None:
            target_matched = any(
                os.path.abspath(f) == os.path.abspath(file_path) or os.path.basename(f) == filename
                for f in target_files
            )
            if not target_matched:
                continue

        if os.path.exists(file_path):
            for pkg, ver in parser(file_path):
                if pkg not in swift_packages or (ver and not swift_packages[pkg]):
                    swift_packages[pkg] = ver

    for filename, parser in conan_parsers:
        file_path = os.path.join(path, filename)
        if target_files is not None:
            target_matched = any(
                os.path.abspath(f) == os.path.abspath(file_path) or os.path.basename(f) == filename
                for f in target_files
            )
            if not target_matched:
                continue

        if os.path.exists(file_path):
            for pkg, ver in parser(file_path):
                if pkg not in conan_packages or (ver and not conan_packages[pkg]):
                    conan_packages[pkg] = ver

    for filename, parser in vcpkg_parsers:
        file_path = os.path.join(path, filename)
        if target_files is not None:
            target_matched = any(
                os.path.abspath(f) == os.path.abspath(file_path) or os.path.basename(f) == filename
                for f in target_files
            )
            if not target_matched:
                continue

        if os.path.exists(file_path):
            for pkg, ver in parser(file_path):
                if pkg not in vcpkg_packages or (ver and not vcpkg_packages[pkg]):
                    vcpkg_packages[pkg] = ver

    for filename, parser in hackage_parsers:
        file_path = os.path.join(path, filename)
        if target_files is not None:
            target_matched = any(
                os.path.abspath(f) == os.path.abspath(file_path) or os.path.basename(f) == filename
                for f in target_files
            )
            if not target_matched:
                continue

        if os.path.exists(file_path):
            for pkg, ver in parser(file_path):
                if pkg not in hackage_packages or (ver and not hackage_packages[pkg]):
                    hackage_packages[pkg] = ver

    cabal_files = []
    if target_files is not None:
        cabal_files = [f for f in target_files if f.endswith(".cabal")]
    else:
        try:
            for root_dir, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "dist", "dist-newstyle", ".stack-work", "venv", ".venv")]
                for file in files:
                    if file.endswith(".cabal"):
                        cabal_files.append(os.path.join(root_dir, file))
        except Exception:
            pass

    for cabal_file in cabal_files:
        if os.path.exists(cabal_file):
            for pkg, ver in parse_cabal_file(cabal_file):
                if pkg not in hackage_packages or (ver and not hackage_packages[pkg]):
                    hackage_packages[pkg] = ver

    for filename, parser in cocoapods_parsers:
        file_path = os.path.join(path, filename)
        if target_files is not None:
            target_matched = any(
                os.path.abspath(f) == os.path.abspath(file_path) or os.path.basename(f) == filename
                for f in target_files
            )
            if not target_matched:
                continue

        if os.path.exists(file_path):
            for pkg, ver in parser(file_path):
                if pkg not in cocoapods_packages or (ver and not cocoapods_packages[pkg]):
                    cocoapods_packages[pkg] = ver

    for filename, parser in cran_parsers:
        file_path = os.path.join(path, filename)
        if target_files is not None:
            target_matched = any(
                os.path.abspath(f) == os.path.abspath(file_path) or os.path.basename(f) == filename
                for f in target_files
            )
            if not target_matched:
                continue

        if os.path.exists(file_path):
            for pkg, ver in parser(file_path):
                if pkg not in cran_packages or (ver and not cran_packages[pkg]):
                    cran_packages[pkg] = ver

    for filename, parser in julia_parsers:
        file_path = os.path.join(path, filename)
        if target_files is not None:
            target_matched = any(
                os.path.abspath(f) == os.path.abspath(file_path) or os.path.basename(f) == filename
                for f in target_files
            )
            if not target_matched:
                continue

        if os.path.exists(file_path):
            for pkg, ver in parser(file_path):
                if pkg not in julia_packages or (ver and not julia_packages[pkg]):
                    julia_packages[pkg] = ver

    for filename, parser in homebrew_parsers:
        file_path = os.path.join(path, filename)
        if target_files is not None:
            target_matched = any(
                os.path.abspath(f) == os.path.abspath(file_path) or os.path.basename(f) == filename
                for f in target_files
            )
            if not target_matched:
                continue

        if os.path.exists(file_path):
            for pkg, ver in parser(file_path):
                if pkg not in homebrew_packages or (ver and not homebrew_packages[pkg]):
                    homebrew_packages[pkg] = ver

    for filename, parser in conda_parsers:
        file_path = os.path.join(path, filename)
        if target_files is not None:
            target_matched = any(
                os.path.abspath(f) == os.path.abspath(file_path) or os.path.basename(f) == filename
                for f in target_files
            )
            if not target_matched:
                continue

        if os.path.exists(file_path):
            for pkg, ver in parser(file_path):
                if pkg not in conda_packages or (ver and not conda_packages[pkg]):
                    conda_packages[pkg] = ver

    for filename, parser in helm_parsers:
        file_path = os.path.join(path, filename)
        if target_files is not None:
            target_matched = any(
                os.path.abspath(f) == os.path.abspath(file_path) or os.path.basename(f) == filename
                for f in target_files
            )
            if not target_matched:
                continue

        if os.path.exists(file_path):
            for pkg, ver in parser(file_path):
                if pkg not in helm_packages or (ver and not helm_packages[pkg]):
                    helm_packages[pkg] = ver

    opam_files = []
    if target_files is not None:
        opam_files = [f for f in target_files if f.endswith(".opam") or os.path.basename(f) == "opam"]
    else:
        try:
            for root_dir, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "dist", "_build", "_opam", "venv", ".venv")]
                for file in files:
                    if file.endswith(".opam") or file == "opam":
                        opam_files.append(os.path.join(root_dir, file))
        except Exception:
            pass

    for opam_file in opam_files:
        if os.path.exists(opam_file):
            for pkg, ver in parse_opam_file(opam_file):
                if pkg not in opam_packages or (ver and not opam_packages[pkg]):
                    opam_packages[pkg] = ver

    gha_files = []
    if target_files is not None:
        gha_files = [
            f for f in target_files
            if (".github/workflows" in f or ".github\\workflows" in f) and f.endswith((".yml", ".yaml"))
        ]
    else:
        wf_dir = os.path.join(path, ".github", "workflows")
        if os.path.isdir(wf_dir):
            try:
                for f in os.listdir(wf_dir):
                    if f.endswith((".yml", ".yaml")):
                        gha_files.append(os.path.join(wf_dir, f))
            except Exception:
                pass

    for wf_file in gha_files:
        if os.path.exists(wf_file):
            for pkg, ver in parse_github_actions_workflows(wf_file):
                if pkg not in gha_packages or (ver and not gha_packages[pkg]):
                    gha_packages[pkg] = ver

    if not (python_packages or npm_packages or go_packages or cargo_packages or maven_packages or packagist_packages or nuget_packages or pub_packages or rubygems_packages or hex_packages or swift_packages or conan_packages or vcpkg_packages or hackage_packages or cocoapods_packages or cran_packages or gha_packages or julia_packages or homebrew_packages or conda_packages or helm_packages or opam_packages):
        return []

    # Fan out all OSV queries concurrently across ecosystems
    tasks = (
        [_query_osv(pkg, ver, "PyPI") for pkg, ver in python_packages.items()]
        + [_query_osv(pkg, ver, "npm") for pkg, ver in npm_packages.items()]
        + [_query_osv(pkg, ver, "Go") for pkg, ver in go_packages.items()]
        + [_query_osv(pkg, ver, "crates.io") for pkg, ver in cargo_packages.items()]
        + [_query_osv(pkg, ver, "Maven") for pkg, ver in maven_packages.items()]
        + [_query_osv(pkg, ver, "Packagist") for pkg, ver in packagist_packages.items()]
        + [_query_osv(pkg, ver, "NuGet") for pkg, ver in nuget_packages.items()]
        + [_query_osv(pkg, ver, "Pub") for pkg, ver in pub_packages.items()]
        + [_query_osv(pkg, ver, "RubyGems") for pkg, ver in rubygems_packages.items()]
        + [_query_osv(pkg, ver, "Hex") for pkg, ver in hex_packages.items()]
        + [_query_osv(pkg, ver, "SwiftURL") for pkg, ver in swift_packages.items()]
        + [_query_osv(pkg, ver, "Conan") for pkg, ver in conan_packages.items()]
        + [_query_osv(pkg, ver, "vcpkg") for pkg, ver in vcpkg_packages.items()]
        + [_query_osv(pkg, ver, "Hackage") for pkg, ver in hackage_packages.items()]
        + [_query_osv(pkg, ver, "CocoaPods") for pkg, ver in cocoapods_packages.items()]
        + [_query_osv(pkg, ver, "CRAN") for pkg, ver in cran_packages.items()]
        + [_query_osv(pkg, ver, "GitHub Actions") for pkg, ver in gha_packages.items()]
        + [_query_osv(pkg, ver, "Julia") for pkg, ver in julia_packages.items()]
        + [_query_osv(pkg, ver, "Homebrew") for pkg, ver in homebrew_packages.items()]
        + [_query_osv(pkg, ver, "PyPI") for pkg, ver in conda_packages.items()]
        + [_query_osv(pkg, ver, "Bitnami") for pkg, ver in helm_packages.items()]
        + [_query_osv(pkg, ver, "opam") for pkg, ver in opam_packages.items()]
    )
    results = await asyncio.gather(*tasks, return_exceptions=True)

    findings: List[DepVulnerability] = []
    for result in results:
        if isinstance(result, list):
            findings.extend(result)

    return findings
