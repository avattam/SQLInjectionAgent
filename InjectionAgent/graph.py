"""
InjectionAgent LangGraph Workflow
Defines the multi-step state machine that orchestrates:
  1. Repository Checkout (load_repository)
  2. AST Candidate Extraction (extract_sql_candidates)
  3. LLM Verification per candidate (verify_sql_candidate_with_llm)
  4. Result aggregation

The graph can be invoked headlessly from any Python context.
"""
import uuid
import json
from datetime import datetime
from typing import Any

from langgraph.graph import StateGraph, END
from langchain_core.messages import SystemMessage, HumanMessage

from InjectionAgent.state import AgentState, SQLVulnerabilityFinding, DataFlowStep, SeverityLevel, ConfidenceLevel
from InjectionAgent.tools import load_repository, extract_sql_candidates, verify_sql_candidate_with_llm
from InjectionAgent.llm import get_llm
from InjectionAgent.prompts import SQL_INJECTION_SYSTEM_PROMPT


# ── Node 1: Load Repository ────────────────────────────────────────────────────
def node_load_repository(state: dict) -> dict:
    print(f"[InjectionAgent] Step 1/3: Loading repository → {state.get('repo_path') or state.get('repo_url')}")
    result = load_repository.invoke({
        "repo_path": state.get("repo_path") or "",
        "repo_url": state.get("repo_url") or "",
        "branch": state.get("branch") or "main"
    })
    if result.get("error"):
        return {**state, "status": "error", "error": result["error"]}
    return {
        **state,
        "target_dir": result["target_dir"],
        "repo_name": result["repo_name"],
        "is_temp_dir": result["is_temp"],
        "status": "scanning"
    }


# ── Node 2: AST Candidate Extraction ──────────────────────────────────────────
def node_extract_candidates(state: dict) -> dict:
    print(f"[InjectionAgent] Step 2/3: AST candidate extraction on {state['target_dir']}")
    result = extract_sql_candidates.invoke({"target_dir": state["target_dir"]})
    candidates = result["candidates"]
    print(f"[InjectionAgent]   → {len(candidates)} SQL query candidates found across {result['files_scanned']} files")
    return {
        **state,
        "candidate_snippets": candidates,
        "files_scanned": result["files_scanned"],
        "status": "verifying"
    }


# ── Node 3: LLM Verification ───────────────────────────────────────────────────
def node_llm_verify(state: dict) -> dict:
    candidates = state.get("candidate_snippets", [])
    llm_model = state.get("llm_model", "gemini-1.5-flash")
    print(f"[InjectionAgent] Step 3/3: LLM verification ({llm_model}) for {len(candidates)} candidates...")

    verified_findings = []
    for i, candidate in enumerate(candidates):
        print(f"[InjectionAgent]   Verifying {i+1}/{len(candidates)}: {candidate['file_path']}:{candidate['line_number']}")
        result = verify_sql_candidate_with_llm.invoke({
            "candidate": candidate,
            "llm_model": llm_model
        })

        if not result.get("is_sql_injection"):
            print(f"[InjectionAgent]   → NOT a SQL injection (filtered by LLM guardrail)")
            continue

        # Build DataFlowStep trace
        steps = []
        step_num = 1
        if candidate.get("source_line"):
            steps.append(DataFlowStep(
                step_number=step_num,
                file_path=candidate["file_path"],
                line_number=candidate["source_line"],
                step_type="source",
                description=f"Untrusted user input entry point",
                code_excerpt=candidate.get("source_excerpt", "")
            ))
            step_num += 1

        steps.append(DataFlowStep(
            step_number=step_num,
            file_path=candidate["file_path"],
            line_number=candidate["line_number"],
            step_type="string_concatenation",
            description="Dynamic SQL string construction via concatenation/interpolation",
            code_excerpt=candidate["code_excerpt"]
        ))
        step_num += 1

        steps.append(DataFlowStep(
            step_number=step_num,
            file_path=candidate["file_path"],
            line_number=candidate["line_number"],
            step_type="sink",
            description=f"Unsafe SQL executed at database sink ({candidate['sink_framework']})",
            code_excerpt=candidate["code_excerpt"]
        ))

        finding = SQLVulnerabilityFinding(
            id=f"SQLI-{uuid.uuid4().hex[:8].upper()}",
            file_path=candidate["file_path"],
            line_number=candidate["line_number"],
            function_name=candidate.get("function_name"),
            severity=SeverityLevel(result.get("severity", "High")),
            confidence=ConfidenceLevel(result.get("confidence", "Likely")),
            vulnerability_type=result.get("unsafe_pattern", "Dynamic SQL Construction"),
            code_excerpt=candidate["code_excerpt"],
            surrounding_context=candidate["surrounding_context"],
            sql_query_snippet=candidate["code_excerpt"],
            data_flow_trace=steps,
            tech_stack=candidate["sink_framework"],
            explanation=result.get("explanation", ""),
            proposed_fix=result.get("proposed_fix", ""),
            expected_behavior="Query executes safely using parameterized bindings.",
            llm_verified=True,
            llm_explanation=result.get("explanation"),
            llm_proposed_fix=result.get("proposed_fix"),
            llm_safe_query=result.get("safe_query_example"),
            llm_model_used=result.get("model", llm_model)
        )
        verified_findings.append(finding)
        print(f"[InjectionAgent]   → CONFIRMED: {finding.severity.value} | {finding.confidence.value}")

    return {
        **state,
        "findings": verified_findings,
        "status": "complete"
    }


# ── Router: handle errors ──────────────────────────────────────────────────────
def route_after_load(state: dict) -> str:
    return "error_end" if state.get("status") == "error" else "extract"


# ── Build the LangGraph ────────────────────────────────────────────────────────
def create_injection_agent_graph():
    """
    Compiles and returns the InjectionAgent LangGraph state machine.
    Invoke via: graph.invoke(initial_state)
    """
    workflow = StateGraph(dict)

    workflow.add_node("load", node_load_repository)
    workflow.add_node("extract", node_extract_candidates)
    workflow.add_node("verify", node_llm_verify)

    workflow.set_entry_point("load")
    workflow.add_conditional_edges("load", route_after_load, {
        "extract": "extract",
        "error_end": END
    })
    workflow.add_edge("extract", "verify")
    workflow.add_edge("verify", END)

    return workflow.compile()


# ── CLI entrypoint ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    import os

    repo_path = sys.argv[1] if len(sys.argv) > 1 else os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "samples", "vulnerable-python-app")
    )
    llm_model = sys.argv[2] if len(sys.argv) > 2 else "gemini-2.5-flash"

    print(f"\n{'='*60}")
    print(f"  InjectionAgent: Headless SQL Vulnerability Scan")
    print(f"  Repository : {repo_path}")
    print(f"  LLM Model  : {llm_model}")
    print(f"{'='*60}\n")

    graph = create_injection_agent_graph()
    initial_state = {
        "repo_path": repo_path,
        "repo_url": None,
        "branch": "main",
        "scan_id": f"SCAN-{uuid.uuid4().hex[:8].upper()}",
        "llm_model": llm_model,
        "status": "pending",
        "findings": [],
        "candidate_snippets": [],
        "files_scanned": 0,
        "target_dir": "",
        "repo_name": "",
        "is_temp_dir": False
    }

    start = datetime.now()
    final_state = graph.invoke(initial_state)
    duration = (datetime.now() - start).total_seconds()

    findings = final_state.get("findings", [])

    print(f"\n{'='*60}")
    print(f"  Scan Complete in {duration:.2f}s")
    print(f"  Files Scanned  : {final_state.get('files_scanned', 0)}")
    print(f"  SQL Findings   : {len(findings)}")
    print(f"{'='*60}\n")

    output = {
        "scan_id": final_state.get("scan_id", ""),
        "repo_name": final_state.get("repo_name", ""),
        "files_scanned": final_state.get("files_scanned", 0),
        "scan_duration_seconds": round(duration, 2),
        "total_findings": len(findings),
        "findings": [
            f.model_dump() if hasattr(f, "model_dump") else f
            for f in findings
        ]
    }

    print(json.dumps(output, indent=2, default=str))
