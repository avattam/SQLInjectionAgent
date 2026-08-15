"""
InjectionAgent State Definitions
Defines the LangGraph AgentState used throughout the workflow.
"""
from typing import List, Optional, Dict, Any, Annotated
from pydantic import BaseModel, Field
from enum import Enum
import operator


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


class DataFlowStep(BaseModel):
    step_number: int
    file_path: str
    line_number: int
    step_type: str  # "source" | "variable_assignment" | "string_concatenation" | "sink"
    description: str
    code_excerpt: str


class SQLVulnerabilityFinding(BaseModel):
    id: str
    file_path: str
    line_number: int
    function_name: Optional[str] = None
    severity: SeverityLevel
    confidence: ConfidenceLevel
    cwe_id: str = "CWE-89"
    cwe_title: str = "SQL Injection"
    vulnerability_type: str
    code_excerpt: str
    surrounding_context: str
    sql_query_snippet: str
    data_flow_trace: List[DataFlowStep] = Field(default_factory=list)
    tech_stack: str
    explanation: str
    proposed_fix: str
    expected_behavior: str
    # LLM verification fields
    llm_verified: bool = False
    llm_explanation: Optional[str] = None
    llm_proposed_fix: Optional[str] = None
    llm_safe_query: Optional[str] = None
    llm_model_used: Optional[str] = None


class CandidateSnippet(BaseModel):
    """Raw AST-extracted candidate before LLM verification."""
    file_path: str
    line_number: int
    line_end: Optional[int] = None
    function_name: Optional[str] = None
    code_excerpt: str
    surrounding_context: str
    sink_framework: str
    has_dynamic_concat: bool
    has_untrusted_source: bool
    source_line: Optional[int] = None
    source_excerpt: Optional[str] = None


class AgentState(BaseModel):
    """
    LangGraph shared state threaded through all nodes in the InjectionAgent workflow.
    """
    # Input
    repo_path: str = ""
    repo_url: Optional[str] = None
    branch: str = "main"
    scan_id: str = ""

    # Intermediate state
    target_dir: str = ""
    repo_name: str = ""
    is_temp_dir: bool = False
    files_scanned: int = 0
    candidate_snippets: List[CandidateSnippet] = Field(default_factory=list)

    # Output findings
    findings: List[SQLVulnerabilityFinding] = Field(default_factory=list)

    # Workflow metadata
    status: str = "pending"   # pending | scanning | verifying | complete | error
    error: Optional[str] = None
    scan_duration_seconds: float = 0.0
    llm_model: str = "gemini-1.5-flash"
