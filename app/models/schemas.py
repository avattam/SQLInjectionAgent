from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime

class SeverityLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"

class ConfidenceLevel(str, Enum):
    CONFIRMED = "Confirmed"
    LIKELY = "Likely"
    SUSPECTED = "Suspected"

class FindingStatus(str, Enum):
    OPEN = "Open"
    IN_REVIEW = "In Review"
    FIXED = "Fixed"
    FALSE_POSITIVE = "False Positive"
    ACCEPTED_RISK = "Accepted Risk"

class DataFlowStep(BaseModel):
    step_number: int
    file_path: str
    line_number: int
    line_end: Optional[int] = None
    step_type: str  # "source", "variable_assignment", "function_call", "string_concatenation", "sink"
    description: str
    code_excerpt: str
    variable_name: Optional[str] = None

class Finding(BaseModel):
    id: str
    scan_id: str
    title: str
    summary: str
    severity: SeverityLevel
    confidence: ConfidenceLevel
    cwe_id: str  # e.g., "CWE-89"
    cwe_title: str
    vulnerability_type: str
    file_path: str
    line_number: int
    line_end: Optional[int] = None
    function_name: Optional[str] = None
    code_excerpt: str
    surrounding_context: str
    sql_query_snippet: str
    data_flow_trace: List[DataFlowStep]
    tech_stack: str  # e.g. "Node.js (pg)", "Python (sqlite3)", "Python (SQLAlchemy)"
    status: FindingStatus = FindingStatus.OPEN
    proposed_fix: str
    expected_behavior: str
    explanation: str
    review_comments: List[Dict[str, Any]] = Field(default_factory=list)
    last_updated: str
    reviewer: Optional[str] = None
    applied_patch: Optional[str] = None
    post_fix_status: Optional[str] = None

class ScanRequest(BaseModel):
    repo_url: Optional[str] = None
    local_path: Optional[str] = None
    branch: Optional[str] = "main"
    commit_or_pr: Optional[str] = None
    framework_filter: Optional[str] = None
    custom_rules: Optional[List[str]] = None

class ScanSummary(BaseModel):
    total_findings: int = 0
    by_severity: Dict[str, int] = Field(default_factory=lambda: {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0})
    by_confidence: Dict[str, int] = Field(default_factory=lambda: {"Confirmed": 0, "Likely": 0, "Suspected": 0})
    files_scanned: int = 0
    scan_duration_seconds: float = 0.0
    status: str = "Completed"
    error_message: Optional[str] = None

class ScanResult(BaseModel):
    scan_id: str
    repo_name: str
    repo_url: Optional[str] = None
    branch: str
    commit_sha: Optional[str] = "head"
    scanned_at: str
    summary: ScanSummary
    findings: List[Finding]

class RemediationPreviewRequest(BaseModel):
    finding_id: str
    custom_patch: Optional[str] = None

class RemediationPreviewResponse(BaseModel):
    finding_id: str
    file_path: str
    original_code: str
    proposed_code: str
    diff_unified: str
    sql_query_before: str
    sql_query_after: str
    explanation: str

class ApplyPatchRequest(BaseModel):
    finding_id: str
    approved_patch: str
    reviewer: str = "Security Engineer"
    target_branch: Optional[str] = None  # None for direct or specify e.g. "security-fix/cwe-89-1"
    create_pr: bool = False
    review_comment: Optional[str] = None

class ApplyPatchResponse(BaseModel):
    finding_id: str
    success: bool
    status: FindingStatus
    post_fix_verification: str  # "Fixed", "Still Present", "Inconclusive"
    branch_name: Optional[str] = None
    diff_applied: str
    message: str

class AuditLogEntry(BaseModel):
    id: str
    timestamp: str
    action: str  # "SCAN_STARTED", "SCAN_COMPLETED", "PATCH_PREVIEW", "PATCH_APPLIED", "STATUS_CHANGE", "COMMENT_ADDED"
    scan_id: Optional[str] = None
    finding_id: Optional[str] = None
    reviewer: str
    details: Dict[str, Any]
