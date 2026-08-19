import os
import pytest
from app.services.scanner_engine import ScannerEngine
from app.services.secret_redactor import redact_secrets

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SAMPLE_NODE_DIR = os.path.join(WORKSPACE_ROOT, "samples", "vulnerable-node-app")
SAMPLE_PYTHON_DIR = os.path.join(WORKSPACE_ROOT, "samples", "vulnerable-python-app")

def test_node_vulnerabilities_detected():
    scanner = ScannerEngine(target_dir=SAMPLE_NODE_DIR, scan_id="TEST-NODE-1")
    result = scanner.scan_repository()

    assert result.summary.total_findings == 3
    
    # Check that findings have valid severities
    valid_severities = {"Critical", "High", "Medium", "Low"}
    for f in result.findings:
        assert f.severity.value in valid_severities
    
    # Verify CWE-89 classification
    for finding in result.findings:
        assert finding.cwe_id == "CWE-89"
        assert len(finding.data_flow_trace) >= 1
        assert "server.js" in finding.file_path

def test_python_vulnerabilities_detected():
    scanner = ScannerEngine(target_dir=SAMPLE_PYTHON_DIR, scan_id="TEST-PY-1")
    result = scanner.scan_repository()

    assert result.summary.total_findings == 2
    
    # Check f-string and % format findings in app.py
    for finding in result.findings:
        assert finding.cwe_id == "CWE-89"
        assert "app.py" in finding.file_path

def test_false_positive_prevention():
    scanner = ScannerEngine(target_dir=SAMPLE_NODE_DIR, scan_id="TEST-FP-1")
    result = scanner.scan_repository()

    # Verify line with safe parameterized query ($1) is not reported as vulnerable
    safe_param_findings = [f for f in result.findings if "safe-search" in f.surrounding_context]
    assert len(safe_param_findings) == 0

def test_secret_redaction():
    secret_text = "postgres://dbuser:SuperSecretPass123!@localhost:5432/mydb"
    redacted = redact_secrets(secret_text)
    
    assert "SuperSecretPass123!" not in redacted
    assert "REDACTED_SECRET" in redacted
