"""
Unit tests for Kubernetes manifest security scanner (K8S001-K8S008).
"""
import os
import tempfile
import pytest
from maunprekshak.scanner.k8s import scan_single_k8s_manifest, scan_k8s_manifests


SAFE_MANIFEST = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: safe-app
spec:
  template:
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
      containers:
        - name: app
          image: myimage:1.0.0
          resources:
            limits:
              cpu: "500m"
              memory: "128Mi"
            requests:
              cpu: "250m"
              memory: "64Mi"
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
"""

PRIVILEGED_MANIFEST = """
apiVersion: v1
kind: Pod
metadata:
  name: priv-pod
spec:
  containers:
    - name: app
      image: nginx
      securityContext:
        privileged: true
      resources:
        limits:
          cpu: "1"
          memory: "256Mi"
        requests:
          cpu: "100m"
          memory: "128Mi"
"""

ROOT_USER_MANIFEST = """
apiVersion: v1
kind: Pod
metadata:
  name: root-pod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myimage
      securityContext:
        runAsUser: 0
      resources:
        limits:
          cpu: "200m"
          memory: "64Mi"
        requests:
          cpu: "100m"
          memory: "32Mi"
"""

HOSTPATH_MANIFEST = """
apiVersion: v1
kind: Pod
metadata:
  name: hostpath-pod
spec:
  automountServiceAccountToken: false
  volumes:
    - name: docker-sock
      hostPath:
        path: /var/run/docker.sock
  containers:
    - name: app
      image: myimage
      resources:
        limits:
          cpu: "200m"
          memory: "64Mi"
        requests:
          cpu: "100m"
          memory: "32Mi"
"""

DANGEROUS_CAP_MANIFEST = """
apiVersion: v1
kind: Pod
metadata:
  name: cap-pod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myimage
      securityContext:
        capabilities:
          add:
            - SYS_ADMIN
      resources:
        limits:
          cpu: "200m"
          memory: "64Mi"
        requests:
          cpu: "100m"
          memory: "32Mi"
"""

PRIV_ESC_MANIFEST = """
apiVersion: v1
kind: Pod
metadata:
  name: priv-esc-pod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myimage
      securityContext:
        allowPrivilegeEscalation: true
      resources:
        limits:
          cpu: "200m"
          memory: "64Mi"
        requests:
          cpu: "100m"
          memory: "32Mi"
"""

WRITABLE_ROOTFS_MANIFEST = """
apiVersion: v1
kind: Pod
metadata:
  name: writable-pod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myimage
      securityContext:
        readOnlyRootFilesystem: false
      resources:
        limits:
          cpu: "200m"
          memory: "64Mi"
        requests:
          cpu: "100m"
          memory: "32Mi"
"""

SUPPRESSED_MANIFEST = """
apiVersion: v1
kind: Pod
metadata:
  name: suppressed-pod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myimage
      securityContext:
        privileged: true  # maunprekshak: ignore[K8S001]
      resources:
        limits:
          cpu: "200m"
          memory: "64Mi"
        requests:
          cpu: "100m"
          memory: "32Mi"
"""


def _write_and_scan(content: str):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(content)
        fname = f.name
    try:
        return scan_single_k8s_manifest(fname)
    finally:
        os.unlink(fname)


class TestK8SScanner:
    def test_safe_manifest_no_findings(self):
        findings = _write_and_scan(SAFE_MANIFEST)
        # A safe manifest should not have high/critical findings
        high_crit = [f for f in findings if f.severity in ("HIGH", "CRITICAL")]
        assert high_crit == [], f"Expected no HIGH/CRITICAL, got: {high_crit}"

    def test_k8s001_privileged_container(self):
        findings = _write_and_scan(PRIVILEGED_MANIFEST)
        ids = [f.check_id for f in findings]
        assert "K8S001" in ids

    def test_k8s001_severity_is_high(self):
        findings = _write_and_scan(PRIVILEGED_MANIFEST)
        k8s001 = [f for f in findings if f.check_id == "K8S001"]
        assert k8s001, "Expected K8S001 finding"
        assert k8s001[0].severity == "HIGH"

    def test_k8s002_missing_resource_limits(self):
        manifest_no_resources = """
apiVersion: v1
kind: Pod
metadata:
  name: no-res-pod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myimage
"""
        findings = _write_and_scan(manifest_no_resources)
        ids = [f.check_id for f in findings]
        assert "K8S002" in ids

    def test_k8s003_runasuser_zero(self):
        findings = _write_and_scan(ROOT_USER_MANIFEST)
        ids = [f.check_id for f in findings]
        assert "K8S003" in ids

    def test_k8s003_runasnoneroot_false(self):
        manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: root-pod
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myimage
      securityContext:
        runAsNonRoot: false
      resources:
        limits:
          cpu: "200m"
          memory: "64Mi"
        requests:
          cpu: "100m"
          memory: "32Mi"
"""
        findings = _write_and_scan(manifest)
        ids = [f.check_id for f in findings]
        assert "K8S003" in ids

    def test_k8s004_sensitive_hostpath(self):
        findings = _write_and_scan(HOSTPATH_MANIFEST)
        ids = [f.check_id for f in findings]
        assert "K8S004" in ids

    def test_k8s004_severity_is_critical(self):
        findings = _write_and_scan(HOSTPATH_MANIFEST)
        k8s004 = [f for f in findings if f.check_id == "K8S004"]
        assert k8s004
        assert k8s004[0].severity == "CRITICAL"

    def test_k8s005_dangerous_capability_sys_admin(self):
        findings = _write_and_scan(DANGEROUS_CAP_MANIFEST)
        ids = [f.check_id for f in findings]
        assert "K8S005" in ids

    def test_k8s006_privilege_escalation_allowed(self):
        findings = _write_and_scan(PRIV_ESC_MANIFEST)
        ids = [f.check_id for f in findings]
        assert "K8S006" in ids

    def test_k8s007_writable_root_filesystem(self):
        findings = _write_and_scan(WRITABLE_ROOTFS_MANIFEST)
        ids = [f.check_id for f in findings]
        assert "K8S007" in ids

    def test_k8s008_automount_service_account(self):
        # K8S008 is triggered when automountServiceAccountToken is NOT set to false
        manifest_no_automount = """
apiVersion: v1
kind: Pod
metadata:
  name: no-automount-pod
spec:
  containers:
    - name: app
      image: myimage
      resources:
        limits:
          cpu: "200m"
          memory: "64Mi"
        requests:
          cpu: "100m"
          memory: "32Mi"
"""
        findings = _write_and_scan(manifest_no_automount)
        ids = [f.check_id for f in findings]
        assert "K8S008" in ids

    def test_k8s001_inline_suppression(self):
        findings = _write_and_scan(SUPPRESSED_MANIFEST)
        k8s001 = [f for f in findings if f.check_id == "K8S001"]
        assert k8s001 == [], "K8S001 should be suppressed by inline comment"

    def test_non_k8s_file_ignored(self):
        regular_yaml = """
name: My Config
version: 1.0
settings:
  debug: true
  database: postgres
"""
        findings = _write_and_scan(regular_yaml)
        assert findings == [], "Non-K8s YAML should produce no findings"

    def test_scan_k8s_manifests_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = os.path.join(tmpdir, "deployment.yaml")
            with open(manifest_path, "w") as f:
                f.write(PRIVILEGED_MANIFEST)
            findings = scan_k8s_manifests(tmpdir)
            ids = [f.check_id for f in findings]
            assert "K8S001" in ids

    def test_finding_has_required_fields(self):
        findings = _write_and_scan(PRIVILEGED_MANIFEST)
        k8s001 = next((f for f in findings if f.check_id == "K8S001"), None)
        assert k8s001 is not None
        assert k8s001.file_path
        assert k8s001.line > 0
        assert k8s001.description
        assert k8s001.recommendation
