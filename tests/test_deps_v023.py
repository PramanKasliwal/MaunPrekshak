"""
Tests for MaunPrekshak Core v0.23.0 — Multi-Ecosystem SCA Phase 12.
Covers Alpine Linux APKBUILD, RPM spec (*.spec), and Bazel (MODULE.bazel / WORKSPACE).
"""
import os
import tempfile
import pytest
from unittest.mock import patch, AsyncMock
from maunprekshak.scanner.deps import (
    parse_apkbuild,
    parse_rpm_spec,
    parse_bazel_dependencies,
    scan_dependencies,
    DepVulnerability,
)


def test_parse_apkbuild_basic():
    content = """# Maintainer: Alpine Team <team@alpinelinux.org>
pkgname=curl
pkgver=7.79.1
pkgrel=0
pkgdesc="command line tool for transferring data with URL syntax"
url="https://curl.se/"
arch="all"
license="MIT"
depends="openssl>=1.1.1 zlib>=1.2.11 ca-certificates"
makedepends="gcc make autoconf"
source="https://curl.se/download/$pkgname-$pkgver.tar.gz"
"""
    with tempfile.NamedTemporaryFile("w", suffix="APKBUILD", delete=False) as f:
        f.write(content)
        f.flush()
        temp_path = f.name

    try:
        packages = parse_apkbuild(temp_path)
        pkg_dict = dict(packages)
        assert "curl" in pkg_dict
        assert pkg_dict["curl"] == "7.79.1"
        assert "openssl" in pkg_dict
        assert pkg_dict["openssl"] == "1.1.1"
        assert "zlib" in pkg_dict
        assert pkg_dict["zlib"] == "1.2.11"
        assert "ca-certificates" in pkg_dict
        assert "gcc" in pkg_dict
        assert "make" in pkg_dict
    finally:
        os.remove(temp_path)


def test_parse_rpm_spec_basic():
    content = """Name:           nginx
Version:        1.20.1
Release:        1%{?dist}
Summary:        High performance web server

License:        BSD-2-Clause
URL:            https://nginx.org
Source0:        %{name}-%{version}.tar.gz

Requires:       openssl >= 1.1.1, zlib >= 1.2.11
BuildRequires:  gcc-c++ >= 8.5.0, make

%description
nginx is an HTTP and reverse proxy server.
"""
    with tempfile.NamedTemporaryFile("w", suffix=".spec", delete=False) as f:
        f.write(content)
        f.flush()
        temp_path = f.name

    try:
        packages = parse_rpm_spec(temp_path)
        pkg_dict = dict(packages)
        assert "nginx" in pkg_dict
        assert pkg_dict["nginx"] == "1.20.1"
        assert "openssl" in pkg_dict
        assert pkg_dict["openssl"] == "1.1.1"
        assert "zlib" in pkg_dict
        assert pkg_dict["zlib"] == "1.2.11"
        assert "gcc-c++" in pkg_dict
        assert pkg_dict["gcc-c++"] == "8.5.0"
        assert "make" in pkg_dict
    finally:
        os.remove(temp_path)


def test_parse_bazel_dependencies():
    content = """module(
    name = "my_project",
    version = "1.0.0",
)

bazel_dep(name = "rules_jvm_external", version = "5.3")

maven = use_extension("@rules_jvm_external//:extensions.bzl", "maven")
maven.install(
    artifacts = [
        "org.apache.logging.log4j:log4j-core:2.14.1",
        "com.google.guava:guava:31.0.1-jre",
    ],
    lock_file = "//:maven_install.json",
)
use_repo(maven, "maven")

maven.artifact("com.fasterxml.jackson.core", "jackson-databind", "2.13.0")
maven.artifact(
    group = "org.apache.commons",
    artifact = "commons-lang3",
    version = "3.12.0",
)
"""
    with tempfile.NamedTemporaryFile("w", suffix="MODULE.bazel", delete=False) as f:
        f.write(content)
        f.flush()
        temp_path = f.name

    try:
        packages = parse_bazel_dependencies(temp_path)
        pkg_dict = dict(packages)
        assert "org.apache.logging.log4j:log4j-core" in pkg_dict
        assert pkg_dict["org.apache.logging.log4j:log4j-core"] == "2.14.1"
        assert "com.google.guava:guava" in pkg_dict
        assert pkg_dict["com.google.guava:guava"] == "31.0.1-jre"
        assert "com.fasterxml.jackson.core:jackson-databind" in pkg_dict
        assert pkg_dict["com.fasterxml.jackson.core:jackson-databind"] == "2.13.0"
        assert "org.apache.commons:commons-lang3" in pkg_dict
        assert pkg_dict["org.apache.commons:commons-lang3"] == "3.12.0"
    finally:
        os.remove(temp_path)


@pytest.mark.asyncio
async def test_scan_dependencies_alpine_and_rpm_integration():
    with tempfile.TemporaryDirectory() as tmpdir:
        apk_path = os.path.join(tmpdir, "APKBUILD")
        with open(apk_path, "w") as f:
            f.write("pkgname=curl\npkgver=7.79.1\ndepends=\"openssl>=1.1.1\"\n")

        spec_path = os.path.join(tmpdir, "package.spec")
        with open(spec_path, "w") as f:
            f.write("Name: nginx\nVersion: 1.20.1\nRequires: zlib >= 1.2.11\n")

        bazel_path = os.path.join(tmpdir, "MODULE.bazel")
        with open(bazel_path, "w") as f:
            f.write('artifacts = ["org.apache.logging.log4j:log4j-core:2.14.1"]\n')

        mock_findings = [
            DepVulnerability("curl", "7.79.1", "CVE-2021-22946", "HIGH", 7.5, "FTP buffer overflow", "7.79.2"),
            DepVulnerability("nginx", "1.20.1", "CVE-2021-3618", "HIGH", 7.0, "ALPACA TLS attack", "1.20.2"),
            DepVulnerability("org.apache.logging.log4j:log4j-core", "2.14.1", "CVE-2021-44228", "CRITICAL", 10.0, "Log4Shell RCE", "2.15.0"),
        ]

        async def _mock_query(pkg, ver, eco):
            if eco == "Alpine" and pkg == "curl":
                return [mock_findings[0]]
            elif eco == "AlmaLinux" and pkg == "nginx":
                return [mock_findings[1]]
            elif eco == "Maven" and "log4j" in pkg:
                return [mock_findings[2]]
            return []

        with patch("maunprekshak.scanner.deps._query_osv", side_effect=_mock_query):
            results = await scan_dependencies(tmpdir)
            assert len(results) == 3
            cves = {r.cve_id for r in results}
            assert "CVE-2021-22946" in cves
            assert "CVE-2021-3618" in cves
            assert "CVE-2021-44228" in cves
