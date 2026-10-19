import os
import tempfile
import pytest
from maunprekshak.scanner.deps import (
    parse_podfile,
    parse_podfile_lock,
    parse_cran_description,
    scan_dependencies,
)


def test_parse_podfile():
    content = """
platform :ios, '14.0'
use_frameworks!

target 'MyApp' do
  pod 'AFNetworking', '~> 4.0'
  pod 'SDWebImage', '>= 5.12.0'
  pod 'SnapKit'
  pod 'Firebase/Analytics', '~> 8.0'
end
"""
    with tempfile.NamedTemporaryFile("w", suffix="Podfile", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        packages = parse_podfile(path)
        pkg_dict = dict(packages)
        assert "AFNetworking" in pkg_dict
        assert pkg_dict["AFNetworking"] == "4.0"
        assert "SDWebImage" in pkg_dict
        assert pkg_dict["SDWebImage"] == "5.12.0"
        assert "SnapKit" in pkg_dict
        assert pkg_dict["SnapKit"] == ""
        assert "Firebase" in pkg_dict
        assert pkg_dict["Firebase"] == "8.0"
    finally:
        os.unlink(path)


def test_parse_podfile_lock():
    content = """
PODS:
  - AFNetworking (4.0.1):
    - AFNetworking/NSURLSession (= 4.0.1)
    - AFNetworking/Reachability (= 4.0.1)
  - SDWebImage (5.12.0)
  - SnapKit (5.6.0)

DEPENDENCIES:
  - AFNetworking (~> 4.0)
  - SDWebImage (~> 5.0)

SPEC REPOS:
  trunk:
    - AFNetworking
"""
    with tempfile.NamedTemporaryFile("w", suffix="Podfile.lock", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        packages = parse_podfile_lock(path)
        pkg_dict = dict(packages)
        assert pkg_dict.get("AFNetworking") == "4.0.1"
        assert pkg_dict.get("SDWebImage") == "5.12.0"
        assert pkg_dict.get("SnapKit") == "5.6.0"
    finally:
        os.unlink(path)


def test_parse_cran_description():
    content = """
Package: testpkg
Title: A Test R Package
Version: 1.0.0
Depends:
    R (>= 4.0.0),
    MASS (>= 7.3-54)
Imports:
    ggplot2 (>= 3.3.0),
    dplyr,
    readr (>= 2.0.0)
Suggests:
    testthat
"""
    with tempfile.NamedTemporaryFile("w", suffix="DESCRIPTION", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        packages = parse_cran_description(path)
        pkg_dict = dict(packages)
        assert "R" not in pkg_dict
        assert "MASS" in pkg_dict
        assert pkg_dict["MASS"] == "7.3-54"
        assert "ggplot2" in pkg_dict
        assert pkg_dict["ggplot2"] == "3.3.0"
        assert "dplyr" in pkg_dict
        assert pkg_dict["dplyr"] == ""
        assert "readr" in pkg_dict
        assert pkg_dict["readr"] == "2.0.0"
    finally:
        os.unlink(path)


@pytest.mark.asyncio
async def test_scan_dependencies_cocoapods(monkeypatch):
    async def mock_query(pkg, ver, eco):
        assert eco in ("CocoaPods", "CRAN")
        return []

    monkeypatch.setattr("maunprekshak.scanner.deps._query_osv", mock_query)

    with tempfile.TemporaryDirectory() as tmpdir:
        podfile_path = os.path.join(tmpdir, "Podfile")
        with open(podfile_path, "w") as f:
            f.write("pod 'AFNetworking', '4.0.1'\n")

        desc_path = os.path.join(tmpdir, "DESCRIPTION")
        with open(desc_path, "w") as f:
            f.write("Package: mypkg\nImports:\n    ggplot2 (>= 3.3.0)\n")

        findings = await scan_dependencies(tmpdir)
        assert findings == []
