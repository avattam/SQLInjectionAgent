import os
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)
WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SAMPLE_NODE_DIR = os.path.join(WORKSPACE_ROOT, "samples", "vulnerable-node-app")

def test_get_sample_repositories():
    response = client.get("/api/scans/samples")
    assert response.status_code == 200
    samples = response.json()
    assert len(samples) >= 2

def test_start_scan_and_fetch_findings():
    payload = {
        "local_path": SAMPLE_NODE_DIR,
        "branch": "main"
    }
    response = client.post("/api/scans", json=payload)
    assert response.status_code == 200
    scan_result = response.json()
    
    scan_id = scan_result["scan_id"]
    assert scan_result["summary"]["total_findings"] >= 3

    # Fetch findings
    findings_resp = client.get(f"/api/scans/{scan_id}/findings")
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert len(findings) == scan_result["summary"]["total_findings"]

def test_audit_logs_endpoint():
    response = client.get("/api/audit")
    assert response.status_code == 200
    logs = response.json()
    assert isinstance(logs, list)
