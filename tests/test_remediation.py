import os
import shutil
import tempfile
import pytest
from app.services.scanner_engine import ScannerEngine
from app.services.remediation_engine import RemediationEngine
from app.models.schemas import FindingStatus

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SAMPLE_NODE_DIR = os.path.join(WORKSPACE_ROOT, "samples", "vulnerable-node-app")

def test_patch_application_and_verification():
    # Copy sample app to a temp dir so we don't mutate original test samples permanently
    temp_dir = tempfile.mkdtemp(prefix="test_remediation_")
    try:
        shutil.copytree(SAMPLE_NODE_DIR, temp_dir, dirs_exist_ok=True)
        
        scanner = ScannerEngine(target_dir=temp_dir, scan_id="REMED-TEST-1")
        initial_scan = scanner.scan_repository()
        assert len(initial_scan.findings) > 0

        target_finding = initial_scan.findings[0]

        remediation = RemediationEngine(target_dir=temp_dir)
        preview = remediation.generate_diff_preview(target_finding)
        
        assert preview.diff_unified != ""
        assert target_finding.file_path in preview.file_path

        # Apply safe parameterized fix
        safe_fix = "const result = await db.query('SELECT id, username, email FROM users WHERE id = $1', [userId]);"
        response = remediation.apply_patch_and_verify(
            finding=target_finding,
            approved_patch=safe_fix,
            reviewer="Test Engineer"
        )

        assert response.success is True
        assert response.post_fix_verification == "Fixed"
        assert response.status == FindingStatus.FIXED

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
