import os
import difflib
from typing import Tuple, Optional
from datetime import datetime

from app.models.schemas import Finding, FindingStatus, RemediationPreviewResponse, ApplyPatchResponse
from app.services.scanner_engine import ScannerEngine
from app.services.secret_redactor import redact_secrets

class RemediationEngine:
    def __init__(self, target_dir: str):
        self.target_dir = os.path.abspath(target_dir)

    def generate_diff_preview(self, finding: Finding, custom_patch: Optional[str] = None) -> RemediationPreviewResponse:
        file_full_path = os.path.join(self.target_dir, finding.file_path)
        
        if not os.path.exists(file_full_path):
            raise FileNotFoundError(f"File not found in target repo: {finding.file_path}")

        with open(file_full_path, "r", encoding="utf-8", errors="ignore") as f:
            original_lines = f.readlines()

        target_line_idx = finding.line_number - 1
        original_code_line = original_lines[target_line_idx] if 0 <= target_line_idx < len(original_lines) else finding.code_excerpt

        proposed_fix_line = (custom_patch.strip() if custom_patch else finding.proposed_fix.strip())
        
        # Ensure indent preservation
        leading_indent = original_code_line[:len(original_code_line) - len(original_code_line.lstrip())]
        proposed_code_with_indent = leading_indent + proposed_fix_line + "\n"

        modified_lines = list(original_lines)
        if 0 <= target_line_idx < len(modified_lines):
            modified_lines[target_line_idx] = proposed_code_with_indent

        # Generate unified diff
        diff = difflib.unified_diff(
            original_lines,
            modified_lines,
            fromfile=f"a/{finding.file_path}",
            tofile=f"b/{finding.file_path}",
            lineterm=""
        )
        diff_unified_str = "\n".join(diff)

        return RemediationPreviewResponse(
            finding_id=finding.id,
            file_path=finding.file_path,
            original_code=redact_secrets(original_code_line.strip()),
            proposed_code=redact_secrets(proposed_fix_line),
            diff_unified=redact_secrets(diff_unified_str),
            sql_query_before=finding.code_excerpt,
            sql_query_after=proposed_fix_line,
            explanation=finding.explanation
        )

    def apply_patch_and_verify(
        self,
        finding: Finding,
        approved_patch: str,
        reviewer: str = "Security Reviewer",
        target_branch: Optional[str] = None
    ) -> ApplyPatchResponse:
        file_full_path = os.path.join(self.target_dir, finding.file_path)
        
        if not os.path.exists(file_full_path):
            return ApplyPatchResponse(
                finding_id=finding.id,
                success=False,
                status=FindingStatus.OPEN,
                post_fix_verification="Inconclusive",
                diff_applied="",
                message=f"Target file `{finding.file_path}` does not exist in repository."
            )

        with open(file_full_path, "r", encoding="utf-8", errors="ignore") as f:
            original_lines = f.readlines()

        target_line_idx = finding.line_number - 1
        if target_line_idx < 0 or target_line_idx >= len(original_lines):
            return ApplyPatchResponse(
                finding_id=finding.id,
                success=False,
                status=FindingStatus.OPEN,
                post_fix_verification="Inconclusive",
                diff_applied="",
                message=f"Line number {finding.line_number} is out of range for file `{finding.file_path}`."
            )

        original_line = original_lines[target_line_idx]
        leading_indent = original_line[:len(original_line) - len(original_line.lstrip())]
        
        patch_clean = approved_patch.strip()
        new_line = leading_indent + patch_clean + "\n"

        modified_lines = list(original_lines)
        modified_lines[target_line_idx] = new_line

        # Generate unified diff before saving
        diff = difflib.unified_diff(
            original_lines,
            modified_lines,
            fromfile=f"a/{finding.file_path}",
            tofile=f"b/{finding.file_path}",
            lineterm=""
        )
        diff_str = "\n".join(diff)

        # Write modified content to disk
        with open(file_full_path, "w", encoding="utf-8") as f:
            f.writelines(modified_lines)

        # Perform Post-Fix Verification Re-Scan
        re_scanner = ScannerEngine(self.target_dir, scan_id=f"RE-SCAN-{finding.scan_id}")
        re_scan_result = re_scanner.scan_repository()

        # Check if finding is still reported on the target file
        vulnerability_still_present = any(
            f.file_path == finding.file_path and f.line_number == finding.line_number
            for f in re_scan_result.findings
        )

        if vulnerability_still_present:
            verification_status = "Still Present"
            new_finding_status = FindingStatus.IN_REVIEW
            msg = "Patch applied, but re-scan detected remaining unsafe query patterns in modified code."
        else:
            verification_status = "Fixed"
            new_finding_status = FindingStatus.FIXED
            msg = f"Patch successfully applied to `{finding.file_path}` at line {finding.line_number}. Re-scan confirmed resolution."

        # Update finding object status & metadata
        finding.status = new_finding_status
        finding.post_fix_status = verification_status
        finding.applied_patch = approved_patch
        finding.reviewer = reviewer
        finding.last_updated = datetime.now().isoformat()

        return ApplyPatchResponse(
            finding_id=finding.id,
            success=True,
            status=new_finding_status,
            post_fix_verification=verification_status,
            branch_name=target_branch,
            diff_applied=redact_secrets(diff_str),
            message=msg
        )
