"""
InjectionAgent LangChain Tools
Reusable @tool primitives that form the building blocks of the LangGraph workflow.
Each tool is independently importable and testable.
"""
import os
import re
import sys
import uuid
import shutil
import tempfile
from typing import List, Optional
from langchain_core.tools import tool

# Reuse existing scanner primitives
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app.services.rules_registry import (
    UNTRUSTED_SOURCES, SQL_SINKS, SAFE_SANITIZERS, SAFE_PARAMETERIZED_PATTERNS
)
from app.services.secret_redactor import redact_secrets
from InjectionAgent.state import CandidateSnippet

IGNORE_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
SUPPORTED_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".py"}


# ────────────────────────────────────────────────────────────────────────────────
# Tool 1: Repository Loader
# ────────────────────────────────────────────────────────────────────────────────
@tool
def load_repository(repo_path: str = "", repo_url: str = "", branch: str = "main") -> dict:
    """
    Prepares a code repository for SQL injection analysis.
    Accepts either a local directory path or a remote Git URL.
    Returns the resolved target directory path, repo name, and whether it is temporary.

    Strictly used for defensive code review purposes only.
    """
    if repo_path and os.path.isdir(repo_path):
        return {
            "target_dir": os.path.abspath(repo_path),
            "repo_name": os.path.basename(repo_path.rstrip("/")),
            "is_temp": False,
            "error": None
        }

    if repo_url:
        try:
            import git
            temp_dir = tempfile.mkdtemp(prefix="injection_agent_")
            git.Repo.clone_from(repo_url, temp_dir, branch=branch, depth=1)
            repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
            return {
                "target_dir": temp_dir,
                "repo_name": repo_name,
                "is_temp": True,
                "error": None
            }
        except Exception as e:
            return {"target_dir": "", "repo_name": "", "is_temp": False, "error": str(e)}

    return {"target_dir": "", "repo_name": "", "is_temp": False, "error": "No repo_path or repo_url provided."}


# ────────────────────────────────────────────────────────────────────────────────
# Tool 2: AST Candidate Extractor
# ────────────────────────────────────────────────────────────────────────────────
@tool
def extract_sql_candidates(target_dir: str) -> dict:
    """
    Performs fast AST/regex-based static analysis on a repository directory to extract
    candidate SQL query execution sites that exhibit dynamic query construction.
    Returns a list of candidate snippets for LLM verification.

    Strictly scoped to identifying SQL query construction patterns (CWE-89) only.
    No other vulnerability types are extracted.
    """
    candidates = []
    files_scanned = 0

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in SUPPORTED_EXTENSIONS:
                continue
            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, target_dir)
            lang = "python" if ext == ".py" else "javascript"
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                files_scanned += 1
                file_candidates = _extract_from_file(lines, rel_path, lang)
                candidates.extend(file_candidates)
            except Exception:
                pass

    return {
        "candidates": [c.model_dump() for c in candidates],
        "files_scanned": files_scanned
    }


def _extract_from_file(lines: List[str], rel_path: str, lang: str) -> List[CandidateSnippet]:
    results = []
    sink_rules = SQL_SINKS.get(lang, [])
    source_patterns = UNTRUSTED_SOURCES.get(lang, [])

    # Collect all source line indices in file
    source_lines = []
    for idx, line in enumerate(lines):
        for pat in source_patterns:
            if re.search(pat, line):
                source_lines.append((idx, line.strip()))
                break

    for sink_idx, line in enumerate(lines):
        # Detect sink
        matched_framework = None
        for rule in sink_rules:
            if re.search(rule["pattern"], line):
                matched_framework = rule["framework"]
                break
        if not matched_framework:
            continue

        # Skip if already parameterized
        if _is_safe(line, lines, sink_idx):
            continue

        # Look at 10-line window for dynamic construction
        start = max(0, sink_idx - 10)
        window = " ".join(l.strip() for l in lines[start:sink_idx + 1])
        has_concat = ("+" in window or "${" in window or "f\"" in window
                      or "f'" in window or ".format(" in window or " % " in window)

        # Check nearest source within 30 lines
        nearby_source = None
        for src_idx, src_excerpt in reversed(source_lines):
            if 0 <= (sink_idx - src_idx) <= 30:
                nearby_source = (src_idx, src_excerpt)
                break

        has_untrusted = nearby_source is not None

        if not has_concat and not has_untrusted:
            continue

        # Extract surrounding context (10 lines before/after sink — wider window
        # ensures upstream f-string/concat construction is visible to the LLM)
        ctx_start = max(0, sink_idx - 10)
        ctx_end = min(len(lines), sink_idx + 6)
        context_parts = []
        for i in range(ctx_start, ctx_end):
            prefix = "> " if i == sink_idx else "  "
            context_parts.append(f"{prefix}{i+1:4d} | {lines[i].rstrip()}")
        context = "\n".join(context_parts)

        fn_name = _find_function(lines, sink_idx, lang)

        results.append(CandidateSnippet(
            file_path=rel_path,
            line_number=sink_idx + 1,
            line_end=sink_idx + 1,
            function_name=fn_name,
            code_excerpt=redact_secrets(lines[sink_idx].strip()),
            surrounding_context=redact_secrets(context),
            sink_framework=matched_framework,
            has_dynamic_concat=has_concat,
            has_untrusted_source=has_untrusted,
            source_line=nearby_source[0] + 1 if nearby_source else None,
            source_excerpt=redact_secrets(nearby_source[1]) if nearby_source else None
        ))

    return results


def _is_safe(line: str, lines: List[str], idx: int) -> bool:
    start = max(0, idx - 5)
    window = " ".join(l.strip() for l in lines[start:idx + 1])
    for pat in SAFE_PARAMETERIZED_PATTERNS:
        if re.search(pat, line) or re.search(pat, window):
            return True
    # Variable-based parameterized call
    if re.search(r'\.\s*(query|execute|all|get|run)\s*\(\s*[a-zA-Z0-9_]+\s*,\s*[\[\(]', line):
        if any(tok in window for tok in ["$1", "?", "%s", ":user"]):
            return True
    for san in SAFE_SANITIZERS:
        if re.search(san, window):
            return True
    return False


def _find_function(lines, idx, lang):
    pat = (r'def\s+([a-zA-Z0-9_]+)' if lang == "python"
           else r'(?:async\s+)?function\s+([a-zA-Z0-9_]+)|const\s+([a-zA-Z0-9_]+)\s*=')
    for i in range(idx, -1, -1):
        m = re.search(pat, lines[i])
        if m:
            return m.group(1) or m.group(2)
    return "unknown"


# ────────────────────────────────────────────────────────────────────────────────
# Tool 3: LLM SQL Vulnerability Verifier
# ────────────────────────────────────────────────────────────────────────────────
@tool
def verify_sql_candidate_with_llm(
    candidate: dict,
    llm_model: str = "gemini-2.5-flash"
) -> dict:
    """
    Sends a candidate SQL injection snippet to the Gemini LLM for strict CWE-89
    SQL injection verification. Returns structured findings with severity, confidence,
    explanation, and a safe parameterized replacement.

    This tool ONLY identifies SQL injection (CWE-89). It ignores all other vulnerability types.
    It does NOT execute code or generate exploit payloads.
    """
    import json
    from langchain_core.messages import SystemMessage, HumanMessage
    from InjectionAgent.llm import get_llm
    from InjectionAgent.prompts import SQL_INJECTION_SYSTEM_PROMPT, VERIFICATION_PROMPT_TEMPLATE

    lang = "python" if candidate["file_path"].endswith(".py") else "javascript"
    data_flow_summary = ""
    if candidate.get("source_excerpt"):
        data_flow_summary = (
            f"Source (line {candidate.get('source_line')}): {candidate['source_excerpt']}\n"
            f"  → flows into SQL sink at line {candidate['line_number']}"
        )
    else:
        data_flow_summary = f"Dynamic query construction detected in SQL sink at line {candidate['line_number']}."

    human_msg = VERIFICATION_PROMPT_TEMPLATE.format(
        file_path=candidate["file_path"],
        line_number=candidate["line_number"],
        framework=candidate["sink_framework"],
        language=lang,
        surrounding_context=candidate["surrounding_context"],
        code_excerpt=candidate["code_excerpt"],
        data_flow_summary=data_flow_summary,
        model_name=llm_model
    )

    llm = get_llm(model_name=llm_model)
    messages = [
        SystemMessage(content=SQL_INJECTION_SYSTEM_PROMPT),
        HumanMessage(content=human_msg)
    ]

    try:
        response = llm.invoke(messages)
        raw_content = response.content if hasattr(response, "content") else str(response)

        # Extract JSON from response
        json_match = re.search(r'\{.*\}', raw_content, re.DOTALL)
        if json_match:
            result = json.loads(json_match.group(0))
        else:
            result = {"is_sql_injection": False, "error": "Could not parse LLM response"}

        result["candidate"] = candidate
        result["model"] = llm_model
        return result
    except Exception as e:
        return {
            "is_sql_injection": False,
            "error": str(e),
            "candidate": candidate,
            "model": llm_model
        }


# ────────────────────────────────────────────────────────────────────────────────
# Composite tool: Single-call scan (for use as outer agent tool)
# ────────────────────────────────────────────────────────────────────────────────
@tool
def scan_repository_sql_vulnerabilities(
    repo_path: str = "",
    repo_url: str = "",
    branch: str = "main",
    llm_model: str = "gemini-2.5-flash"
) -> dict:
    """
    Scans a code repository for SQL injection vulnerabilities (CWE-89) only.
    Combines fast AST-based candidate extraction with Gemini LLM verification.
    Returns structured JSON findings with severity, confidence, data-flow evidence,
    and safe parameterized query replacements.

    This tool is strictly defensive — it does not execute code or generate exploit payloads.
    It can be used as a standalone LangChain tool in any outer AI agent or CI pipeline.

    Args:
        repo_path: Local directory path to the repository to scan.
        repo_url: Remote Git URL to clone and scan.
        branch: Branch name to checkout (for remote repos).
        llm_model: Gemini model name (e.g., "gemini-1.5-flash", "gemini-2.5-flash").

    Returns:
        dict with keys: scan_id, repo_name, findings, summary
    """
    # Step 1: Load repository
    repo_result = load_repository.invoke({
        "repo_path": repo_path, "repo_url": repo_url, "branch": branch
    })
    if repo_result.get("error"):
        return {"error": repo_result["error"], "findings": [], "summary": {}}

    target_dir = repo_result["target_dir"]
    repo_name = repo_result["repo_name"]
    is_temp = repo_result["is_temp"]

    try:
        # Step 2: Extract AST candidates
        extraction = extract_sql_candidates.invoke({"target_dir": target_dir})
        candidates = extraction["candidates"]
        files_scanned = extraction["files_scanned"]

        # Step 3: LLM verification for each candidate
        verified_findings = []
        for candidate in candidates:
            result = verify_sql_candidate_with_llm.invoke({
                "candidate": candidate,
                "llm_model": llm_model
            })
            if result.get("is_sql_injection"):
                finding = {
                    "id": f"SQLI-{uuid.uuid4().hex[:8].upper()}",
                    "file_path": candidate["file_path"],
                    "line_number": candidate["line_number"],
                    "function_name": candidate.get("function_name"),
                    "severity": result.get("severity", "High"),
                    "confidence": result.get("confidence", "Likely"),
                    "cwe_id": "CWE-89",
                    "cwe_title": "SQL Injection",
                    "vulnerability_type": result.get("unsafe_pattern", "Dynamic SQL Construction"),
                    "code_excerpt": candidate["code_excerpt"],
                    "surrounding_context": candidate["surrounding_context"],
                    "tech_stack": candidate["sink_framework"],
                    "explanation": result.get("explanation", ""),
                    "proposed_fix": result.get("proposed_fix", ""),
                    "safe_query_example": result.get("safe_query_example", ""),
                    "llm_model_used": result.get("model", llm_model),
                    "data_flow": {
                        "source_line": candidate.get("source_line"),
                        "source_excerpt": candidate.get("source_excerpt"),
                        "sink_line": candidate["line_number"],
                        "has_dynamic_concat": candidate.get("has_dynamic_concat"),
                        "has_untrusted_source": candidate.get("has_untrusted_source")
                    }
                }
                verified_findings.append(finding)

        # Summary
        by_sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in verified_findings:
            sev = f["severity"]
            by_sev[sev] = by_sev.get(sev, 0) + 1

        return {
            "scan_id": f"SCAN-{uuid.uuid4().hex[:8].upper()}",
            "repo_name": repo_name,
            "files_scanned": files_scanned,
            "total_candidates": len(candidates),
            "total_findings": len(verified_findings),
            "findings": verified_findings,
            "summary": {
                "total": len(verified_findings),
                "by_severity": by_sev,
                "llm_model": llm_model
            }
        }
    finally:
        if is_temp and target_dir and os.path.exists(target_dir):
            shutil.rmtree(target_dir, ignore_errors=True)
