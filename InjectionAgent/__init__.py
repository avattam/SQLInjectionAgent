"""
InjectionAgent Package
Exports the headless LangGraph workflow and LangChain tool for use
as an agentic AI component in any outer framework or CI pipeline.
"""
from InjectionAgent.graph import create_injection_agent_graph
from InjectionAgent.tools import (
    scan_repository_sql_vulnerabilities,
    load_repository,
    extract_sql_candidates,
    verify_sql_candidate_with_llm
)
from InjectionAgent.state import AgentState, SQLVulnerabilityFinding, CandidateSnippet

__all__ = [
    "create_injection_agent_graph",
    "scan_repository_sql_vulnerabilities",
    "load_repository",
    "extract_sql_candidates",
    "verify_sql_candidate_with_llm",
    "AgentState",
    "SQLVulnerabilityFinding",
    "CandidateSnippet"
]
