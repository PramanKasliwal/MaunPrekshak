"""
Tests for MaunPrekshak Core v0.17.0 — Multi-Ecosystem SCA Phase 6.
Tests vcpkg.json, stack.yaml, *.cabal, and cabal.project.freeze parsers.
"""
import pytest
from maunprekshak.scanner.deps import (
    parse_vcpkg_json,
    parse_stack_yaml,
    parse_cabal_file,
    parse_cabal_project_freeze,
    scan_dependencies,
)


def test_parse_vcpkg_json(tmp_path):
    vcpkg_file = tmp_path / "vcpkg.json"
    vcpkg_file.write_text("""{
  "name": "super-project",
  "version-string": "1.0.0",
  "dependencies": [
    "fmt",
    "zlib",
    {
      "name": "boost-asio",
      "version>=": "1.80.0"
    },
    {
      "name": "openssl",
      "version": "3.0.7"
    }
  ],
  "overrides": [
    {
      "name": "sqlite3",
      "version": "3.40.0"
    }
  ]
}""")

    packages = parse_vcpkg_json(str(vcpkg_file))
    pkg_dict = dict(packages)
    assert "fmt" in pkg_dict
    assert "zlib" in pkg_dict
    assert pkg_dict["boost-asio"] == "1.80.0"
    assert pkg_dict["openssl"] == "3.0.7"
    assert pkg_dict["sqlite3"] == "3.40.0"


def test_parse_stack_yaml(tmp_path):
    stack_file = tmp_path / "stack.yaml"
    stack_file.write_text("""
resolver: lts-20.11
packages:
- .
extra-deps:
- text-1.2.5.0
- aeson-2.1.2.1
- acme-missiles-0.3
- http-client-tls-0.3.6.1
""")

    packages = parse_stack_yaml(str(stack_file))
    pkg_dict = dict(packages)
    assert pkg_dict["text"] == "1.2.5.0"
    assert pkg_dict["aeson"] == "2.1.2.1"
    assert pkg_dict["acme-missiles"] == "0.3"
    assert pkg_dict["http-client-tls"] == "0.3.6.1"


def test_parse_cabal_file(tmp_path):
    cabal_file = tmp_path / "myproject.cabal"
    cabal_file.write_text("""
name:                myproject
version:             0.1.0.0
build-type:          Simple
cabal-version:       >=1.10

executable myproject
  main-is:             Main.hs
  build-depends:
      base >= 4.7 && < 5,
      text == 1.2.5.0,
      aeson >= 2.1.2.1,
      bytestring
  default-language:    Haskell2010
""")

    packages = parse_cabal_file(str(cabal_file))
    pkg_dict = dict(packages)
    assert "base" in pkg_dict
    assert pkg_dict["text"] == "1.2.5.0"
    assert pkg_dict["aeson"] == "2.1.2.1"
    assert "bytestring" in pkg_dict


def test_parse_cabal_project_freeze(tmp_path):
    freeze_file = tmp_path / "cabal.project.freeze"
    freeze_file.write_text("""
active-repositories: hackage.haskell.org:merge
constraints: any.aeson ==2.1.2.1,
             any.text ==1.2.5.0,
             any.vector ==0.13.0.0,
             base ==4.17.0.0
""")

    packages = parse_cabal_project_freeze(str(freeze_file))
    pkg_dict = dict(packages)
    assert pkg_dict["aeson"] == "2.1.2.1"
    assert pkg_dict["text"] == "1.2.5.0"
    assert pkg_dict["vector"] == "0.13.0.0"
    assert pkg_dict["base"] == "4.17.0.0"


@pytest.mark.asyncio
async def test_scan_dependencies_vcpkg_and_hackage(tmp_path, monkeypatch):
    (tmp_path / "vcpkg.json").write_text("""{
  "dependencies": [
    {"name": "openssl", "version>=": "1.1.1"}
  ]
}""")
    (tmp_path / "stack.yaml").write_text("""
extra-deps:
- aeson-2.1.2.1
""")

    queried = []

    async def mock_query(pkg, ver, ecosystem):
        queried.append((pkg, ver, ecosystem))
        return []

    monkeypatch.setattr("maunprekshak.scanner.deps._query_osv", mock_query)

    res = await scan_dependencies(str(tmp_path))
    assert res == []
    ecosystems = {eco for _, _, eco in queried}
    assert "vcpkg" in ecosystems
    assert "Hackage" in ecosystems
    pkgs = {pkg for pkg, _, _ in queried}
    assert "openssl" in pkgs
    assert "aeson" in pkgs
