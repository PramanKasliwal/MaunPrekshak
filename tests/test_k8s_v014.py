"""
Tests for MaunPrekshak Core v0.14.0 — Kubernetes & Cloud-Native Hardening (K8S009–K8S014).
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


def test_k8s009_host_namespace_sharing():
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: host-ns-pod
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
    - name: app
      image: myapp:1.0
      resources:
        limits: {cpu: "1", memory: "256Mi"}
        requests: {cpu: "500m", memory: "128Mi"}
"""
    findings = _write_and_scan(manifest)
    k8s009 = [f for f in findings if f.check_id == "K8S009"]
    assert len(k8s009) == 3
    for f in k8s009:
        assert f.severity == "CRITICAL"


def test_k8s009_inline_suppression():
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: suppressed-host-pod
spec:
  hostNetwork: true # maunprekshak: ignore[K8S009]
  containers:
    - name: app
      image: myapp:1.0
"""
    findings = _write_and_scan(manifest)
    k8s009 = [f for f in findings if f.check_id == "K8S009"]
    assert len(k8s009) == 0


def test_k8s010_dangerous_service_exposure():
    nodeport_service = """
apiVersion: v1
kind: Service
metadata:
  name: public-nodeport
spec:
  type: NodePort
  ports:
    - port: 80
      targetPort: 8080
"""
    findings = _write_and_scan(nodeport_service)
    k8s010 = [f for f in findings if f.check_id == "K8S010"]
    assert len(k8s010) == 1
    assert k8s010[0].severity == "HIGH"
    assert "NodePort" in k8s010[0].description

    lb_service = """
apiVersion: v1
kind: Service
metadata:
  name: public-lb
spec:
  type: LoadBalancer
  ports:
    - port: 443
"""
    findings_lb = _write_and_scan(lb_service)
    k8s010_lb = [f for f in findings_lb if f.check_id == "K8S010"]
    assert len(k8s010_lb) == 1
    assert k8s010_lb[0].severity == "HIGH"
    assert "LoadBalancer" in k8s010_lb[0].description


def test_k8s010_clusterip_safe():
    clusterip_service = """
apiVersion: v1
kind: Service
metadata:
  name: internal-service
spec:
  type: ClusterIP
  ports:
    - port: 80
"""
    findings = _write_and_scan(clusterip_service)
    k8s010 = [f for f in findings if f.check_id == "K8S010"]
    assert len(k8s010) == 0


def test_k8s011_unconfined_seccomp():
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: unconfined-pod
spec:
  securityContext:
    seccompProfile:
      type: Unconfined
  containers:
    - name: app
      image: myapp:1.0
      resources:
        limits: {cpu: "1", memory: "256Mi"}
        requests: {cpu: "500m", memory: "128Mi"}
"""
    findings = _write_and_scan(manifest)
    k8s011 = [f for f in findings if f.check_id == "K8S011"]
    assert len(k8s011) >= 1
    assert k8s011[0].severity == "MEDIUM"


def test_k8s011_missing_seccomp_profile():
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: no-seccomp-pod
spec:
  containers:
    - name: app
      image: myapp:1.0
      resources:
        limits: {cpu: "1", memory: "256Mi"}
        requests: {cpu: "500m", memory: "128Mi"}
"""
    findings = _write_and_scan(manifest)
    k8s011 = [f for f in findings if f.check_id == "K8S011"]
    assert len(k8s011) == 1
    assert k8s011[0].severity == "MEDIUM"


def test_k8s012_missing_network_policy():
    manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: isolated-workload
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:1.0
          resources:
            limits: {cpu: "1", memory: "256Mi"}
            requests: {cpu: "500m", memory: "128Mi"}
"""
    findings = _write_and_scan(manifest)
    k8s012 = [f for f in findings if f.check_id == "K8S012"]
    assert len(k8s012) == 1
    assert k8s012[0].severity == "MEDIUM"


def test_k8s012_with_network_policy_safe():
    manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: protected-workload
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:1.0
          resources:
            limits: {cpu: "1", memory: "256Mi"}
            requests: {cpu: "500m", memory: "128Mi"}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
"""
    findings = _write_and_scan(manifest)
    k8s012 = [f for f in findings if f.check_id == "K8S012"]
    assert len(k8s012) == 0


def test_k8s013_plaintext_secret_in_env():
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: leaked-secret-pod
spec:
  containers:
    - name: app
      image: myapp:1.0
      env:
        - name: DATABASE_PASSWORD
          value: "SuperSecretPassword123"
        - name: API_TOKEN
          value: "abc123xyz"
      resources:
        limits: {cpu: "1", memory: "256Mi"}
        requests: {cpu: "500m", memory: "128Mi"}
"""
    findings = _write_and_scan(manifest)
    k8s013 = [f for f in findings if f.check_id == "K8S013"]
    assert len(k8s013) == 2
    assert k8s013[0].severity == "HIGH"
    assert "DATABASE_PASSWORD" in k8s013[0].description
    assert "API_TOKEN" in k8s013[1].description


def test_k8s013_secret_key_ref_safe():
    manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: secure-env-pod
spec:
  containers:
    - name: app
      image: myapp:1.0
      env:
        - name: DATABASE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: password
      resources:
        limits: {cpu: "1", memory: "256Mi"}
        requests: {cpu: "500m", memory: "128Mi"}
"""
    findings = _write_and_scan(manifest)
    k8s013 = [f for f in findings if f.check_id == "K8S013"]
    assert len(k8s013) == 0


def test_k8s014_default_namespace_usage():
    manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: default-ns-app
  namespace: default
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:1.0
          resources:
            limits: {cpu: "1", memory: "256Mi"}
            requests: {cpu: "500m", memory: "128Mi"}
"""
    findings = _write_and_scan(manifest)
    k8s014 = [f for f in findings if f.check_id == "K8S014"]
    assert len(k8s014) == 1
    assert k8s014[0].severity == "LOW"


def test_k8s014_custom_namespace_safe():
    manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prod-app
  namespace: production
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:1.0
          resources:
            limits: {cpu: "1", memory: "256Mi"}
            requests: {cpu: "500m", memory: "128Mi"}
"""
    findings = _write_and_scan(manifest)
    k8s014 = [f for f in findings if f.check_id == "K8S014"]
    assert len(k8s014) == 0
