"""
Tests for MaunPrekshak Core v0.14.0 — Mechanical Auto-Fixing Engine Phase 3.
"""
import os
import tempfile
import pytest

from maunprekshak.scanner.fixer import fix_file_findings
from maunprekshak.scanner.report import SASTFinding, Severity


def test_fix_mp051_numpy_load():
    content = """import numpy as np

def load_data(path):
    data = np.load(path, allow_pickle=True)
    return data
"""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(content)
        fname = f.name
    try:
        finding = SASTFinding(
            file_path=fname,
            line=4,
            col=4,
            check_id="MP051",
            severity=Severity.HIGH.value,
            description="Dangerous NumPy pickle load",
            recommendation="Set allow_pickle=False",
            code_snippet="    data = np.load(path, allow_pickle=True)",
        )
        count = fix_file_findings(fname, [finding])
        assert count == 1
        with open(fname) as f:
            fixed = f.read()
        assert "allow_pickle=False" in fixed
        assert "allow_pickle=True" not in fixed
    finally:
        os.unlink(fname)


def test_fix_k8s001_privileged():
    content = """apiVersion: v1
kind: Pod
metadata:
  name: priv-pod
spec:
  containers:
    - name: app
      image: nginx
      securityContext:
        privileged: true
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(content)
        fname = f.name
    try:
        finding = SASTFinding(
            file_path=fname,
            line=10,
            col=0,
            check_id="K8S001",
            severity=Severity.HIGH.value,
            description="Privileged container",
            recommendation="Set privileged: false",
            code_snippet="        privileged: true",
        )
        count = fix_file_findings(fname, [finding])
        assert count == 1
        with open(fname) as f:
            fixed = f.read()
        assert "privileged: false" in fixed
        assert "privileged: true" not in fixed
    finally:
        os.unlink(fname)


def test_fix_k8s006_allow_privilege_escalation():
    content = """apiVersion: v1
kind: Pod
metadata:
  name: priv-esc-pod
spec:
  containers:
    - name: app
      image: nginx
      securityContext:
        allowPrivilegeEscalation: true
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(content)
        fname = f.name
    try:
        finding = SASTFinding(
            file_path=fname,
            line=10,
            col=0,
            check_id="K8S006",
            severity=Severity.MEDIUM.value,
            description="Privilege escalation allowed",
            recommendation="Set allowPrivilegeEscalation: false",
            code_snippet="        allowPrivilegeEscalation: true",
        )
        count = fix_file_findings(fname, [finding])
        assert count == 1
        with open(fname) as f:
            fixed = f.read()
        assert "allowPrivilegeEscalation: false" in fixed
        assert "allowPrivilegeEscalation: true" not in fixed
    finally:
        os.unlink(fname)


def test_fix_k8s007_readonly_root_filesystem():
    content = """apiVersion: v1
kind: Pod
metadata:
  name: ro-pod
spec:
  containers:
    - name: app
      image: nginx
      securityContext:
        readOnlyRootFilesystem: false
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(content)
        fname = f.name
    try:
        finding = SASTFinding(
            file_path=fname,
            line=10,
            col=0,
            check_id="K8S007",
            severity=Severity.LOW.value,
            description="Writable root filesystem",
            recommendation="Set readOnlyRootFilesystem: true",
            code_snippet="        readOnlyRootFilesystem: false",
        )
        count = fix_file_findings(fname, [finding])
        assert count == 1
        with open(fname) as f:
            fixed = f.read()
        assert "readOnlyRootFilesystem: true" in fixed
        assert "readOnlyRootFilesystem: false" not in fixed
    finally:
        os.unlink(fname)


def test_fix_k8s009_host_namespace():
    content = """apiVersion: v1
kind: Pod
metadata:
  name: host-ns-pod
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
    - name: app
      image: nginx
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(content)
        fname = f.name
    try:
        findings = [
            SASTFinding(
                file_path=fname,
                line=6,
                col=0,
                check_id="K8S009",
                severity=Severity.CRITICAL.value,
                description="hostNetwork true",
                recommendation="Set hostNetwork: false",
                code_snippet="  hostNetwork: true",
            ),
            SASTFinding(
                file_path=fname,
                line=7,
                col=0,
                check_id="K8S009",
                severity=Severity.CRITICAL.value,
                description="hostPID true",
                recommendation="Set hostPID: false",
                code_snippet="  hostPID: true",
            ),
            SASTFinding(
                file_path=fname,
                line=8,
                col=0,
                check_id="K8S009",
                severity=Severity.CRITICAL.value,
                description="hostIPC true",
                recommendation="Set hostIPC: false",
                code_snippet="  hostIPC: true",
            ),
        ]
        count = fix_file_findings(fname, findings)
        assert count == 3
        with open(fname) as f:
            fixed = f.read()
        assert "hostNetwork: false" in fixed
        assert "hostPID: false" in fixed
        assert "hostIPC: false" in fixed
        assert "hostNetwork: true" not in fixed
        assert "hostPID: true" not in fixed
        assert "hostIPC: true" not in fixed
    finally:
        os.unlink(fname)
