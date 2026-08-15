"""
InjectionAgent Test Suite
Tests for the LangGraph workflow and LangChain tool primitives.
Uses the offline mock LLM when no GEMINI_API_KEY is available.
"""
import os
import pytest

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SAMPLE_NODE_DIR = os.path.join(WORKSPACE_ROOT, "samples", "vulnerable-node-app")
SAMPLE_PYTHON_DIR = os.path.join(WORKSPACE_ROOT, "samples", "vulnerable-python-app")


# ── Tool 1: load_repository ─────────────────────────────────────────────────
class TestLoadRepository:
    def test_local_path_loads_correctly(self):
        from InjectionAgent.tools import load_repository
        result = load_repository.invoke({
            "repo_path": SAMPLE_NODE_DIR,
            "repo_url": "",
            "branch": "main"
        })
        assert result["error"] is None
        assert os.path.isdir(result["target_dir"])
        assert result["is_temp"] is False

    def test_invalid_path_returns_error(self):
        from InjectionAgent.tools import load_repository
        result = load_repository.invoke({
            "repo_path": "/nonexistent/path/to/repo",
            "repo_url": "",
            "branch": "main"
        })
        assert result["error"] is not None or result["target_dir"] == ""

    def test_no_input_returns_error(self):
        from InjectionAgent.tools import load_repository
        result = load_repository.invoke({"repo_path": "", "repo_url": "", "branch": "main"})
        assert result["error"] is not None


# ── Tool 2: extract_sql_candidates ──────────────────────────────────────────
class TestExtractSqlCandidates:
    def test_node_app_candidates_detected(self):
        from InjectionAgent.tools import extract_sql_candidates
        result = extract_sql_candidates.invoke({"target_dir": SAMPLE_NODE_DIR})
        assert result["files_scanned"] >= 1
        assert len(result["candidates"]) >= 3

    def test_python_app_candidates_detected(self):
        from InjectionAgent.tools import extract_sql_candidates
        result = extract_sql_candidates.invoke({"target_dir": SAMPLE_PYTHON_DIR})
        assert result["files_scanned"] >= 1
        assert len(result["candidates"]) >= 2

    def test_candidate_structure(self):
        from InjectionAgent.tools import extract_sql_candidates
        result = extract_sql_candidates.invoke({"target_dir": SAMPLE_PYTHON_DIR})
        candidates = result["candidates"]
        assert len(candidates) > 0
        c = candidates[0]
        assert "file_path" in c
        assert "line_number" in c
        assert "code_excerpt" in c
        assert "sink_framework" in c
        assert "surrounding_context" in c

    def test_safe_parameterized_queries_excluded(self):
        from InjectionAgent.tools import extract_sql_candidates
        result = extract_sql_candidates.invoke({"target_dir": SAMPLE_NODE_DIR})
        # The safe-search endpoint (parameterized $1) should NOT appear in candidates
        safe_candidates = [
            c for c in result["candidates"]
            if "WHERE id = $1" in c.get("code_excerpt", "")
               or "WHERE id = $1" in c.get("surrounding_context", "")
        ]
        assert len(safe_candidates) == 0


# ── Tool 3: verify_sql_candidate_with_llm (offline/mock) ────────────────────
class TestLLMVerifier:
    def _get_first_candidate(self, target_dir):
        from InjectionAgent.tools import extract_sql_candidates
        result = extract_sql_candidates.invoke({"target_dir": target_dir})
        return result["candidates"][0] if result["candidates"] else None

    def test_mock_llm_returns_finding(self):
        from InjectionAgent.tools import verify_sql_candidate_with_llm
        candidate = self._get_first_candidate(SAMPLE_PYTHON_DIR)
        assert candidate is not None
        result = verify_sql_candidate_with_llm.invoke({
            "candidate": candidate,
            "llm_model": "gemini-1.5-flash"
        })
        # Mock LLM or real LLM — must return a dict with is_sql_injection
        assert "is_sql_injection" in result

    def test_result_has_required_fields_when_positive(self):
        from InjectionAgent.tools import verify_sql_candidate_with_llm
        candidate = self._get_first_candidate(SAMPLE_PYTHON_DIR)
        result = verify_sql_candidate_with_llm.invoke({
            "candidate": candidate,
            "llm_model": "gemini-1.5-flash"
        })
        if result.get("is_sql_injection"):
            for field in ["severity", "confidence", "explanation", "proposed_fix"]:
                assert field in result, f"Missing field: {field}"


# ── LangGraph Full Workflow ──────────────────────────────────────────────────
class TestInjectionAgentGraph:
    def test_graph_compiles(self):
        from InjectionAgent.graph import create_injection_agent_graph
        graph = create_injection_agent_graph()
        assert graph is not None

    def test_graph_runs_on_python_sample(self):
        import uuid
        from InjectionAgent.graph import create_injection_agent_graph
        graph = create_injection_agent_graph()
        initial_state = {
            "repo_path": SAMPLE_PYTHON_DIR,
            "repo_url": "",
            "branch": "main",
            "scan_id": f"SCAN-{uuid.uuid4().hex[:8].upper()}",
            "llm_model": "gemini-1.5-flash",
            "status": "pending",
            "findings": [],
            "candidate_snippets": [],
            "files_scanned": 0,
            "target_dir": "",
            "repo_name": "",
            "is_temp_dir": False,
            "error": None
        }
        final_state = graph.invoke(initial_state)
        assert final_state["status"] in ("complete", "error")
        assert isinstance(final_state["findings"], list)
        assert final_state["files_scanned"] >= 1

    def test_graph_error_on_invalid_path(self):
        import uuid
        from InjectionAgent.graph import create_injection_agent_graph
        graph = create_injection_agent_graph()
        initial_state = {
            "repo_path": "/nonexistent/repo",
            "repo_url": "",
            "branch": "main",
            "scan_id": "SCAN-ERR-TEST",
            "llm_model": "gemini-1.5-flash",
            "status": "pending",
            "findings": [],
            "candidate_snippets": [],
            "files_scanned": 0,
            "target_dir": "",
            "repo_name": "",
            "is_temp_dir": False,
            "error": None
        }
        final_state = graph.invoke(initial_state)
        assert final_state["status"] == "error"


# ── Composite tool: scan_repository_sql_vulnerabilities ─────────────────────
class TestScanTool:
    def test_scan_returns_structured_output(self):
        from InjectionAgent.tools import scan_repository_sql_vulnerabilities
        result = scan_repository_sql_vulnerabilities.invoke({
            "repo_path": SAMPLE_PYTHON_DIR,
            "repo_url": "",
            "branch": "main",
            "llm_model": "gemini-1.5-flash"
        })
        assert "findings" in result
        assert "summary" in result
        assert isinstance(result["findings"], list)

    def test_scan_node_app_findings(self):
        from InjectionAgent.tools import scan_repository_sql_vulnerabilities
        result = scan_repository_sql_vulnerabilities.invoke({
            "repo_path": SAMPLE_NODE_DIR,
            "repo_url": "",
            "branch": "main",
            "llm_model": "gemini-1.5-flash"
        })
        assert result.get("total_candidates", 0) >= 3
