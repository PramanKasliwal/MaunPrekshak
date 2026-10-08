"""
Tests for MaunPrekshak Core v0.15.0 — Kubernetes & Cloud-Native Hardening Phase 2 (K8S015–K8S020).
"""
import os
import tempfile
import pytest
from maunprekshak.scanner.k8s import scan_single_k8s_manifest


def _write_and_scan(content: str):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(content)
        fname = f.name
    try:
        return scan_single_k8s_manifest(fname)
    finally:
        os.unlink(fname)


def test_k8s015_mutable_latest_image():
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: latest-pod
spec:
  containers:
    - name: web
      image: nginx:latest
"""
    findings = _write_and_scan(manifest)
    k8s015 = [f for f in findings if f.check_id == "K8S015"]
    assert len(k8s015) == 1
    assert k8s015[0].severity == "HIGH"
    assert "latest" in k8s015[0].description.lower()


def test_k8s015_untagged_image():
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: untagged-pod
spec:
  containers:
    - name: redis
      image: redis
"""
    findings = _write_and_scan(manifest)
    k8s015 = [f for f in findings if f.check_id == "K8S015"]
    assert len(k8s015) == 1
    assert k8s015[0].severity == "HIGH"


def test_k8s015_pinned_tag_passes():
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: pinned-pod
spec:
  containers:
    - name: web
      image: nginx:1.25.3
"""
    findings = _write_and_scan(manifest)
    k8s015 = [f for f in findings if f.check_id == "K8S015"]
    assert len(k8s015) == 0


def test_k8s016_missing_health_probes():
    manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: no-probes-deploy
spec:
  containers:
    - name: api
      image: api:1.0.0
"""
    findings = _write_and_scan(manifest)
    k8s016 = [f for f in findings if f.check_id == "K8S016"]
    assert len(k8s016) == 1
    assert k8s016[0].severity == "MEDIUM"
    assert "livenessProbe and readinessProbe" in k8s016[0].description


def test_k8s016_probes_present_passes():
    manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: probes-deploy
spec:
  containers:
    - name: api
      image: api:1.0.0
      livenessProbe:
        httpGet:
          path: /healthz
          port: 8080
      readinessProbe:
        httpGet:
          path: /ready
          port: 8080
"""
    findings = _write_and_scan(manifest)
    k8s016 = [f for f in findings if f.check_id == "K8S016"]
    assert len(k8s016) == 0


def test_k8s017_runtime_socket_mount():
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: dind-pod
spec:
  containers:
    - name: builder
      image: docker:20.10
      volumeMounts:
        - mountPath: /var/run/docker.sock
          name: docker-socket
  volumes:
    - name: docker-socket
      hostPath:
        path: /var/run/docker.sock
"""
    findings = _write_and_scan(manifest)
    k8s017 = [f for f in findings if f.check_id == "K8S017"]
    assert len(k8s017) >= 1
    assert any(f.severity == "CRITICAL" for f in k8s017)


def test_k8s018_net_raw_not_dropped():
    manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: raw-deploy
spec:
  containers:
    - name: app
      image: app:1.0.0
"""
    findings = _write_and_scan(manifest)
    k8s018 = [f for f in findings if f.check_id == "K8S018"]
    assert len(k8s018) == 1
    assert k8s018[0].severity == "MEDIUM"


def test_k8s018_net_raw_dropped_passes():
    manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dropped-raw-deploy
spec:
  containers:
    - name: app
      image: app:1.0.0
      securityContext:
        capabilities:
          drop:
            - ALL
"""
    findings = _write_and_scan(manifest)
    k8s018 = [f for f in findings if f.check_id == "K8S018"]
    assert len(k8s018) == 0


def test_k8s019_image_pull_policy_never():
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: never-pull-pod
spec:
  containers:
    - name: app
      image: app:1.0.0
      imagePullPolicy: Never
"""
    findings = _write_and_scan(manifest)
    k8s019 = [f for f in findings if f.check_id == "K8S019"]
    assert len(k8s019) == 1
    assert k8s019[0].severity == "HIGH"


def test_k8s020_default_service_account():
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: default-sa-pod
spec:
  serviceAccountName: default
  containers:
    - name: app
      image: app:1.0.0
"""
    findings = _write_and_scan(manifest)
    k8s020 = [f for f in findings if f.check_id == "K8S020"]
    assert len(k8s020) == 1
    assert k8s020[0].severity == "LOW"


def test_k8s015_suppression():
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: suppressed-latest
spec:
  containers:
    - name: web
      image: nginx:latest # maunprekshak: ignore[K8S015]
"""
    findings = _write_and_scan(manifest)
    k8s015 = [f for f in findings if f.check_id == "K8S015"]
    assert len(k8s015) == 0
