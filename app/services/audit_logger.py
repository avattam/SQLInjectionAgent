import os
import json
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime
from app.models.schemas import AuditLogEntry

AUDIT_LOG_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "audit.log"))

class AuditLogger:
    @staticmethod
    def log_event(
        action: str,
        reviewer: str,
        details: Dict[str, Any],
        scan_id: Optional[str] = None,
        finding_id: Optional[str] = None
    ) -> AuditLogEntry:
        entry = AuditLogEntry(
            id=f"AUDIT-{uuid.uuid4().hex[:8].upper()}",
            timestamp=datetime.now().isoformat(),
            action=action,
            scan_id=scan_id,
            finding_id=finding_id,
            reviewer=reviewer,
            details=details
        )
        
        try:
            with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry.model_dump()) + "\n")
        except Exception as e:
            print(f"[AuditLogger] Failed writing to audit log: {e}")

        return entry

    @staticmethod
    def get_logs(limit: int = 50) -> List[Dict[str, Any]]:
        if not os.path.exists(AUDIT_LOG_FILE):
            return []
        
        entries = []
        try:
            with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        entries.append(json.loads(line))
        except Exception as e:
            print(f"[AuditLogger] Failed reading audit log: {e}")

        entries.reverse()
        return entries[:limit]
