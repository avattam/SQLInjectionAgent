import os
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from fastapi import APIRouter, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect

from app.models.schemas import (
    ScanRequest, ScanResult, Finding, FindingStatus,
    RemediationPreviewRequest, RemediationPreviewResponse,
    ApplyPatchRequest, ApplyPatchResponse
)
from app.services.repo_service import RepoService
from app.services.scanner_engine import ScannerEngine
from app.services.remediation_engine import RemediationEngine
from app.services.audit_logger import AuditLogger

router = APIRouter(prefix="/api")
ws_router = APIRouter()

# In-memory storage for active scans and findings
SCANS_DB: Dict[str, ScanResult] = {}
ACTIVE_WEBSOCKETS: List[WebSocket] = []
WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

repo_service = RepoService(WORKSPACE_ROOT)

async def notify_websockets(data: Dict[str, Any]):
    for ws in list(ACTIVE_WEBSOCKETS):
        try:
            await ws.send_json(data)
        except Exception:
            if ws in ACTIVE_WEBSOCKETS:
                ACTIVE_WEBSOCKETS.remove(ws)

@ws_router.websocket("/ws/scan")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    ACTIVE_WEBSOCKETS.append(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in ACTIVE_WEBSOCKETS:
            ACTIVE_WEBSOCKETS.remove(websocket)

@router.get("/scans/samples")
async def get_sample_repositories():
    """
    Returns pre-configured sample vulnerable repositories for quick scanning demo.
    """
    samples_dir = os.path.join(WORKSPACE_ROOT, "samples")
    return [
        {
            "id": "node-sample",
            "name": "Node.js Express SQL Injection App",
            "local_path": os.path.join(samples_dir, "vulnerable-node-app"),
            "description": "Express.js application using pg & sqlite3 drivers with string concatenation vulnerabilities."
        },
        {
            "id": "python-sample",
            "name": "Python Flask SQL Injection App",
            "local_path": os.path.join(samples_dir, "vulnerable-python-app"),
            "description": "Flask application using sqlite3 & psycopg2 with f-string and % format query flaws."
        },
        {
            "id": "workspace-sample",
            "name": "Current Workspace Repository",
            "local_path": WORKSPACE_ROOT,
            "description": "Full scan of the current SQL Injection Agent codebase."
        }
    ]

@router.post("/scans", response_model=ScanResult)
async def start_scan(request: ScanRequest):
    """
    Starts a static security scan on a local folder or Git repository.
    """
    scan_id = f"SCAN-{int(datetime.now().timestamp())}"
    
    await notify_websockets({"event": "SCAN_PROGRESS", "scan_id": scan_id, "percent": 15, "status": "Cloning & preparing repository..."})

    try:
        repo_dir, repo_name, is_temp = repo_service.prepare_repository(
            repo_url=request.repo_url,
            local_path=request.local_path,
            branch=request.branch
        )
    except Exception as e:
        await notify_websockets({"event": "SCAN_ERROR", "scan_id": scan_id, "error": str(e)})
        raise HTTPException(status_code=400, detail=str(e))

    await notify_websockets({"event": "SCAN_PROGRESS", "scan_id": scan_id, "percent": 50, "status": "Executing AST & data-flow taint analysis..."})

    scanner = ScannerEngine(target_dir=repo_dir, scan_id=scan_id)
    scan_result = scanner.scan_repository()
    scan_result.repo_name = repo_name
    scan_result.repo_url = request.repo_url

    SCANS_DB[scan_id] = scan_result

    AuditLogger.log_event(
        action="SCAN_COMPLETED",
        reviewer="System",
        scan_id=scan_id,
        details={
            "repo_name": repo_name,
            "findings_count": scan_result.summary.total_findings,
            "duration": scan_result.summary.scan_duration_seconds
        }
    )

    await notify_websockets({
        "event": "SCAN_COMPLETED",
        "scan_id": scan_id,
        "percent": 100,
        "summary": scan_result.summary.model_dump(),
        "total_findings": scan_result.summary.total_findings
    })

    return scan_result

@router.get("/scans/{scan_id}", response_model=ScanResult)
async def get_scan_result(scan_id: str):
    if scan_id not in SCANS_DB:
        raise HTTPException(status_code=404, detail=f"Scan ID `{scan_id}` not found.")
    return SCANS_DB[scan_id]

@router.get("/scans/{scan_id}/findings", response_model=List[Finding])
async def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = None,
    confidence: Optional[str] = None,
    status: Optional[str] = None
):
    if scan_id not in SCANS_DB:
        raise HTTPException(status_code=404, detail=f"Scan ID `{scan_id}` not found.")
    
    findings = SCANS_DB[scan_id].findings

    if severity:
        findings = [f for f in findings if f.severity.value.lower() == severity.lower()]
    if confidence:
        findings = [f for f in findings if f.confidence.value.lower() == confidence.lower()]
    if status:
        findings = [f for f in findings if f.status.value.lower() == status.lower()]

    return findings

@router.post("/remediate/preview", response_model=RemediationPreviewResponse)
async def preview_remediation(request: RemediationPreviewRequest):
    """
    Generates a unified diff preview for a proposed parameterized fix.
    """
    finding, scan_result = _find_finding_by_id(request.finding_id)
    target_dir = repo_service.workspace_root if not scan_result.repo_url else os.path.abspath(scan_result.repo_name)

    # Fallback to local path if target_dir doesn't exist directly
    if not os.path.exists(target_dir) and request.finding_id:
        target_dir = os.path.abspath(os.path.join(WORKSPACE_ROOT, "samples", "vulnerable-node-app" if "server.js" in finding.file_path else "vulnerable-python-app"))

    remediation = RemediationEngine(target_dir=target_dir)
    try:
        preview = remediation.generate_diff_preview(finding, custom_patch=request.custom_patch)
        
        AuditLogger.log_event(
            action="PATCH_PREVIEW",
            reviewer="User",
            finding_id=finding.id,
            scan_id=finding.scan_id,
            details={"file_path": finding.file_path, "line": finding.line_number}
        )
        return preview
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/remediate/apply", response_model=ApplyPatchResponse)
async def apply_remediation(request: ApplyPatchRequest):
    """
    Applies an approved patch to the repository, performs a post-fix re-scan, and logs the result.
    """
    finding, scan_result = _find_finding_by_id(request.finding_id)

    # Determine target directory
    if "samples/vulnerable-node-app" in finding.file_path or "server.js" in finding.file_path:
        target_dir = os.path.join(WORKSPACE_ROOT, "samples", "vulnerable-node-app")
    elif "samples/vulnerable-python-app" in finding.file_path or "app.py" in finding.file_path:
        target_dir = os.path.join(WORKSPACE_ROOT, "samples", "vulnerable-python-app")
    else:
        target_dir = WORKSPACE_ROOT

    # Optionally create security branch
    if request.target_branch:
        repo_service.create_security_branch(target_dir, request.target_branch)

    remediation = RemediationEngine(target_dir=target_dir)
    response = remediation.apply_patch_and_verify(
        finding=finding,
        approved_patch=request.approved_patch,
        reviewer=request.reviewer,
        target_branch=request.target_branch
    )

    if request.review_comment:
        finding.review_comments.append({
            "timestamp": datetime.now().isoformat(),
            "reviewer": request.reviewer,
            "comment": request.review_comment
        })

    AuditLogger.log_event(
        action="PATCH_APPLIED",
        reviewer=request.reviewer,
        finding_id=finding.id,
        scan_id=finding.scan_id,
        details={
            "file_path": finding.file_path,
            "line": finding.line_number,
            "verification": response.post_fix_verification,
            "status": response.status.value,
            "branch": request.target_branch
        }
    )

    # Update summary in scan_result
    _update_scan_summary(scan_result)

    await notify_websockets({
        "event": "FINDING_UPDATED",
        "finding_id": finding.id,
        "status": response.status.value,
        "verification": response.post_fix_verification
    })

    return response

@router.patch("/findings/{finding_id}/status")
async def update_finding_status(finding_id: str, status: FindingStatus, reviewer: str = "Security Reviewer", comment: Optional[str] = None):
    finding, scan_result = _find_finding_by_id(finding_id)
    finding.status = status
    finding.reviewer = reviewer
    finding.last_updated = datetime.now().isoformat()

    if comment:
        finding.review_comments.append({
            "timestamp": datetime.now().isoformat(),
            "reviewer": reviewer,
            "comment": comment
        })

    AuditLogger.log_event(
        action="STATUS_CHANGE",
        reviewer=reviewer,
        finding_id=finding.id,
        scan_id=finding.scan_id,
        details={"new_status": status.value, "comment": comment}
    )

    _update_scan_summary(scan_result)
    return finding

@router.get("/audit")
async def get_audit_logs(limit: int = 50):
    return AuditLogger.get_logs(limit=limit)

def _find_finding_by_id(finding_id: str) -> Tuple[Finding, ScanResult]:
    for scan in SCANS_DB.values():
        for f in scan.findings:
            if f.id == finding_id:
                return f, scan
    raise HTTPException(status_code=404, detail=f"Finding `{finding_id}` not found.")

def _update_scan_summary(scan_result: ScanResult):
    by_sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    by_conf = {"Confirmed": 0, "Likely": 0, "Suspected": 0}
    
    for f in scan_result.findings:
        if f.status not in (FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED_RISK, FindingStatus.FIXED):
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
            by_conf[f.confidence.value] = by_conf.get(f.confidence.value, 0) + 1

    scan_result.summary.by_severity = by_sev
    scan_result.summary.by_confidence = by_conf
