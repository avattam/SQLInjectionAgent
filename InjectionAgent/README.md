# InjectionAgent

A **headless, agentic SQL injection code review tool** built with **LangChain** and **LangGraph**.  
It detects SQL injection vulnerabilities (**CWE-89 only**) in source repositories using a hybrid approach: fast AST/regex-based candidate extraction followed by Gemini LLM deep verification and safe parameterized patch generation.

> **Scope constraint**: This tool is strictly defensive. It identifies and helps fix SQL injection weaknesses in your own source code. It does not execute code, generate exploit payloads, or analyze any other vulnerability class.

---

## Package Structure

```
InjectionAgent/
├── __init__.py        # Public exports — import from here
├── state.py           # LangGraph AgentState & Pydantic schemas
├── llm.py             # Gemini LLM initializer (+ offline mock fallback)
├── prompts.py         # Strict CWE-89 SQL-only system & verification prompts
├── tools.py           # Four LangChain @tool primitives
└── graph.py           # LangGraph 3-node state machine + CLI entrypoint
```

---

## Architecture

```
Outer Agent / CLI / CI Pipeline
         │
         ▼
┌─────────────────────────────────────────────────┐
│          LangGraph State Machine                │
│  ┌─────────┐   ┌──────────┐   ┌─────────────┐ │
│  │  load   │──▶│ extract  │──▶│   verify    │ │
│  │  repo   │   │candidates│   │  (Gemini)   │ │
│  └─────────┘   └──────────┘   └─────────────┘ │
└─────────────────────────────────────────────────┘
         │
         ▼
   JSON findings output
   (severity, confidence, CWE-89, data-flow trace, safe fix)
```

**Step 1 — `load`**: Accepts a local directory path or remote Git URL, clones the repo if needed, and redacts any secrets found in paths/URLs.  
**Step 2 — `extract`**: Runs AST/regex analysis across `.py`, `.js`, `.ts` files to find SQL execution sinks with dynamic query construction (string concatenation, f-strings, `%` formatting). Safe parameterized queries are excluded automatically.  
**Step 3 — `verify`**: Sends each candidate snippet + surrounding context to Gemini via LangChain. Strict system prompts enforce **CWE-89 SQL injection only** — the LLM ignores all other issue types. Verified findings include severity, confidence, data-flow trace, and a proposed parameterized fix.

---

## Prerequisites

### 1. Install dependencies

From the project root:

```bash
pip install -r requirements.txt
```

Key packages installed:

| Package | Purpose |
|---|---|
| `langchain` | Core LangChain framework |
| `langgraph` | State graph orchestration |
| `langchain-google-genai` | Gemini LLM via Google GenAI |
| `langchain-openai` | Optional OpenAI-compatible endpoint |
| `GitPython` | Remote repository cloning |
| `pydantic` | Typed state & finding schemas |

### 2. Set your Gemini API key

```bash
export GEMINI_API_KEY=your_google_gemini_api_key_here
```

Or alternatively:

```bash
export GOOGLE_API_KEY=your_google_api_key_here
```

> **No API key?** The tool automatically falls back to an **offline mock LLM** so unit tests and candidate extraction still work without a live key. LLM-verified findings will be clearly marked as `[MOCK]`.

---

## Usage

### Option A — As a LangChain `@tool` (recommended for outer agents)

Import the composite tool directly and invoke it in any LangChain agent:

```python
from InjectionAgent import scan_repository_sql_vulnerabilities

# Scan a local repository
result = scan_repository_sql_vulnerabilities.invoke({
    "repo_path": "/path/to/your/project",
    "repo_url": "",
    "branch": "main",
    "llm_model": "gemini-1.5-flash"   # or "gemini-2.5-flash"
})

print(f"Total findings: {result['total_findings']}")
for finding in result["findings"]:
    print(f"  [{finding['severity']}] {finding['file_path']}:{finding['line_number']}")
    print(f"  → {finding['explanation']}")
    print(f"  Fix: {finding['proposed_fix']}")
```

**Scan a remote Git repository:**

```python
result = scan_repository_sql_vulnerabilities.invoke({
    "repo_path": "",
    "repo_url": "https://github.com/org/vulnerable-app.git",
    "branch": "main",
    "llm_model": "gemini-1.5-flash"
})
```

### Option B — As a LangGraph workflow

Use the compiled graph for full stateful orchestration with step-by-step progress:

```python
import uuid
from InjectionAgent import create_injection_agent_graph

graph = create_injection_agent_graph()

final_state = graph.invoke({
    "repo_path": "/path/to/your/project",
    "repo_url": None,
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
})

print(f"Status      : {final_state['status']}")
print(f"Files scanned: {final_state['files_scanned']}")
print(f"Findings    : {len(final_state['findings'])}")

for f in final_state["findings"]:
    print(f"\n  ID       : {f.id}")
    print(f"  File     : {f.file_path}:{f.line_number}")
    print(f"  Severity : {f.severity.value}  |  Confidence: {f.confidence.value}")
    print(f"  CWE      : {f.cwe_id}")
    print(f"  Explain  : {f.llm_explanation}")
    print(f"  Fix      : {f.llm_proposed_fix}")
    print(f"  SafeSQL  : {f.llm_safe_query}")
```

### Option C — CLI (headless terminal execution)

Run directly from the project root. Outputs structured JSON to stdout.

```bash
# Scan the bundled vulnerable Python sample app
python3 -m InjectionAgent.graph samples/vulnerable-python-app gemini-1.5-flash

# Scan the bundled vulnerable Node.js sample app
python3 -m InjectionAgent.graph samples/vulnerable-node-app gemini-1.5-flash

# Scan any local repository
python3 -m InjectionAgent.graph /path/to/your/repo gemini-2.5-flash
```

**Example JSON output:**

```json
{
  "scan_id": "SCAN-A3F7C20B",
  "repo_name": "vulnerable-python-app",
  "files_scanned": 1,
  "scan_duration_seconds": 2.14,
  "total_findings": 2,
  "findings": [
    {
      "id": "SQLI-4A9D12E1",
      "file_path": "app.py",
      "line_number": 23,
      "severity": "Critical",
      "confidence": "Confirmed",
      "cwe_id": "CWE-89",
      "vulnerability_type": "f-string interpolation in SQL query",
      "explanation": "User-controlled form input flows directly into an f-string SQL query...",
      "proposed_fix": "cursor.execute('SELECT * FROM users WHERE username = ?', (username,))",
      "llm_safe_query": "cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))"
    }
  ]
}
```

### Option D — Individual tools (composable primitives)

Each tool is independently importable:

```python
from InjectionAgent.tools import (
    load_repository,
    extract_sql_candidates,
    verify_sql_candidate_with_llm
)

# Step 1: Load repo
repo = load_repository.invoke({"repo_path": "/path/to/repo", "repo_url": "", "branch": "main"})

# Step 2: Extract AST candidates only (no LLM cost)
extraction = extract_sql_candidates.invoke({"target_dir": repo["target_dir"]})
print(f"Candidates found: {len(extraction['candidates'])}")

# Step 3: Verify a specific candidate with LLM
result = verify_sql_candidate_with_llm.invoke({
    "candidate": extraction["candidates"][0],
    "llm_model": "gemini-1.5-flash"
})
print(result)
```

---

## Supported Languages & Frameworks

| Language | SQL Drivers / ORMs Detected |
|---|---|
| **Python** | `sqlite3`, `psycopg2`, `SQLAlchemy` (`text()`), Django (`connection.cursor().execute`, `.raw()`) |
| **JavaScript / TypeScript** | `pg` (node-postgres), `mysql2`, `sqlite3`, `sequelize.query()`, `knex.raw()`, `prisma.$queryRawUnsafe()` |

### Unsafe Patterns Detected
- String concatenation: `"SELECT * FROM users WHERE id = " + user_id`
- F-string interpolation: `f"SELECT * FROM items WHERE name = '{name}'"`
- `%` string formatting: `"SELECT * FROM t WHERE x = '%s'" % value`
- `.format()` interpolation: `"SELECT * WHERE x = '{}'".format(value)`
- Dynamic `ORDER BY` / column name injection

### Safe Patterns Excluded (no false positives)
- Positional placeholders: `cursor.execute("... WHERE id = ?", (id,))`
- Named placeholders: `session.execute(text("... WHERE id = :id"), {"id": id})`
- Dollar-sign bindings: `db.query("... WHERE id = $1", [id])`
- Integer-casted inputs: `parseInt(req.query.id)`, `int(user_id)`

---

## Running Tests

```bash
# From the project root
python3 -m pytest tests/test_injection_agent.py -v
```

**Test categories:**

| Test Class | What It Tests |
|---|---|
| `TestLoadRepository` | Local path loading, invalid path errors, empty input handling |
| `TestExtractSqlCandidates` | AST candidate detection on Node.js & Python samples, structure validation, false-positive exclusion |
| `TestLLMVerifier` | Mock/live LLM verification returns structured response with required fields |
| `TestInjectionAgentGraph` | Graph compilation, full workflow on Python sample, error handling on invalid path |
| `TestScanTool` | Composite `scan_repository_sql_vulnerabilities` tool returns structured output |

```bash
# Run with verbose output and show print statements
python3 -m pytest tests/test_injection_agent.py -v -s

# Run only the AST extraction tests (no LLM cost)
python3 -m pytest tests/test_injection_agent.py::TestExtractSqlCandidates -v

# Run only the graph integration tests
python3 -m pytest tests/test_injection_agent.py::TestInjectionAgentGraph -v
```

---

## Configuration

| Environment Variable | Description | Default |
|---|---|---|
| `GEMINI_API_KEY` | Google Gemini API key for LLM verification | — |
| `GOOGLE_API_KEY` | Alternative Google API key | — |
| `OPENAI_API_KEY` | OpenAI-compatible API key (fallback) | — |
| `OPENAI_API_BASE` | Custom OpenAI-compatible base URL | — |

### Supported LLM Models

```python
# Fast & cost-effective (recommended)
llm_model = "gemini-1.5-flash"

# Higher accuracy for complex codebases
llm_model = "gemini-2.5-flash"

# Pro tier (maximum depth)
llm_model = "gemini-1.5-pro"
```

---

## Output Schema

Each finding in the `findings` list contains:

```python
{
    "id": "SQLI-A3F7C20B",           # Unique finding ID
    "file_path": "app/routes.py",    # Relative file path
    "line_number": 42,               # SQL sink line number
    "function_name": "get_user",     # Enclosing function (if found)
    "severity": "Critical",          # Critical | High | Medium | Low
    "confidence": "Confirmed",       # Confirmed | Likely | Suspected
    "cwe_id": "CWE-89",
    "cwe_title": "SQL Injection",
    "vulnerability_type": "f-string interpolation in SQL query",
    "code_excerpt": "cursor.execute(query)",
    "surrounding_context": "...5 lines before/after...",
    "tech_stack": "Python (sqlite3 / psycopg2)",
    "explanation": "LLM-generated explanation of the risk",
    "proposed_fix": "cursor.execute('SELECT ... WHERE id = ?', (id,))",
    "safe_query_example": "Full safe parameterized query replacement",
    "llm_verified": true,
    "llm_model_used": "gemini-1.5-flash",
    "data_flow": {
        "source_line": 38,
        "source_excerpt": "username = request.form.get('username')",
        "sink_line": 42,
        "has_dynamic_concat": true,
        "has_untrusted_source": true
    }
}
```

---

## Notes & Limitations

- **AST analysis is intra-file**: Cross-file taint tracking is heuristic (source → sink within 30 lines in the same file). Complex multi-module flows may be marked `Suspected` instead of `Confirmed`.
- **LLM verification cost**: Each candidate incurs one Gemini API call. Large repositories with many SQL query sites may incur higher token usage.
- **Mock mode**: When no API key is set, the offline mock LLM always returns `is_sql_injection: true` — useful for testing the pipeline structure, not for accurate findings.
- **Language support**: Currently covers `.py`, `.js`, `.jsx`, `.ts`, `.tsx`. Ruby, Go, Java, and PHP support can be added by extending [`app/services/rules_registry.py`](../app/services/rules_registry.py).
