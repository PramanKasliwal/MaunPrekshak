import os
import tempfile
import pytest
from maunprekshak.scanner.deps import (
    parse_package_swift,
    parse_package_resolved,
    parse_conanfile_txt,
    parse_conan_lock,
    scan_dependencies,
)


def test_parse_package_swift():
    content = """// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "MyProject",
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.2.0"),
        .package(url: "https://github.com/Alamofire/Alamofire.git", exact: "5.6.4"),
        .package(name: "SnapshotTesting", url: "https://github.com/pointfreeco/swift-snapshot-testing", from: "1.10.0")
    ]
)
"""
    with tempfile.NamedTemporaryFile("w", suffix=".swift", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        deps = parse_package_swift(path)
        dep_dict = dict(deps)
        assert "swift-argument-parser" in dep_dict
        assert dep_dict["swift-argument-parser"] == "1.2.0"
        assert "alamofire" in dep_dict
        assert dep_dict["alamofire"] == "5.6.4"
        assert "snapshottesting" in dep_dict
        assert dep_dict["snapshottesting"] == "1.10.0"
    finally:
        os.unlink(path)


def test_parse_package_resolved_v1():
    content = """{
  "object": {
    "pins": [
      {
        "package": "Alamofire",
        "repositoryURL": "https://github.com/Alamofire/Alamofire.git",
        "state": {
          "branch": null,
          "revision": "784220093b4e29944218de8a5083aa05b8d927a1",
          "version": "5.6.4"
        }
      }
    ]
  },
  "version": 1
}"""
    with tempfile.NamedTemporaryFile("w", suffix=".resolved", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        deps = parse_package_resolved(path)
        assert len(deps) == 1
        assert deps[0] == ("alamofire", "5.6.4")
    finally:
        os.unlink(path)


def test_parse_package_resolved_v2():
    content = """{
  "pins": [
    {
      "identity": "swift-argument-parser",
      "location": "https://github.com/apple/swift-argument-parser",
      "state": {
        "revision": "fee699261482cf584e62b44e6b64f3322b51ffce",
        "version": "1.2.0"
      }
    }
  ],
  "version": 2
}"""
    with tempfile.NamedTemporaryFile("w", suffix=".resolved", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        deps = parse_package_resolved(path)
        assert len(deps) == 1
        assert deps[0] == ("swift-argument-parser", "1.2.0")
    finally:
        os.unlink(path)


def test_parse_conanfile_txt():
    content = """[requires]
openssl/1.1.1u
zlib/1.2.13@conan/stable
fmt/9.1.0

[generators]
cmake
"""
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        deps = parse_conanfile_txt(path)
        dep_dict = dict(deps)
        assert dep_dict.get("openssl") == "1.1.1u"
        assert dep_dict.get("zlib") == "1.2.13"
        assert dep_dict.get("fmt") == "9.1.0"
    finally:
        os.unlink(path)


def test_parse_conan_lock():
    content = """{
  "version": "0.4",
  "graph_lock": {
    "nodes": {
      "1": {
        "ref": "openssl/1.1.1u#4a2e5d",
        "package_id": "b64f007b60e86fc057c32d441237638fa157c52c"
      },
      "2": {
        "ref": "zlib/1.2.13"
      }
    }
  }
}"""
    with tempfile.NamedTemporaryFile("w", suffix=".lock", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        deps = parse_conan_lock(path)
        dep_dict = dict(deps)
        assert dep_dict.get("openssl") == "1.1.1u"
        assert dep_dict.get("zlib") == "1.2.13"
    finally:
        os.unlink(path)


@pytest.mark.asyncio
async def test_scan_dependencies_swift_and_conan(tmp_path):
    pkg_swift = tmp_path / "Package.swift"
    pkg_swift.write_text("""// swift-tools-version:5.5
import PackageDescription
let package = Package(
    name: "Demo",
    dependencies: [
        .package(url: "https://github.com/Alamofire/Alamofire.git", from: "5.6.4")
    ]
)
""")
    conan_txt = tmp_path / "conanfile.txt"
    conan_txt.write_text("""[requires]
openssl/1.1.1u
""")

    # When scanning directory without OSV network hit or with network
    findings = await scan_dependencies(str(tmp_path))
    assert isinstance(findings, list)
