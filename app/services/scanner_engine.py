import os
import re
import uuid
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime

from app.models.schemas import Finding, DataFlowStep, SeverityLevel, ConfidenceLevel, FindingStatus, ScanSummary, ScanResult
from app.services.rules_registry import UNTRUSTED_SOURCES, SQL_SINKS, SAFE_SANITIZERS, SAFE_PARAMETERIZED_PATTERNS
from app.services.secret_redactor import redact_secrets

IGNORE_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".idea", ".vscode"}
SUPPORTED_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".py"}

class ScannerEngine:
    def __init__(self, target_dir: str, scan_id: str):
        self.target_dir = os.path.abspath(target_dir)
        self.scan_id = scan_id

    def scan_repository(self) -> ScanResult:
        """
        Performs a repository security scan.
        Dynamically checks if InjectionAgent is available.
        If available, invokes InjectionAgent tool; otherwise falls back to existing AST scanner engine.
        """
        agent_result = self._try_scan_with_agent()
        if agent_result is not None:
            return agent_result

        return self._scan_repository_ast()

    def _try_scan_with_agent(self) -> Optional[ScanResult]:
        """
        Dynamically checks availability of InjectionAgent tool.
        If importable, invokes scan_repository_sql_vulnerabilities.invoke(...).
        """
        try:
            from InjectionAgent import scan_repository_sql_vulnerabilities

            llm_model = os.environ.get("AGENT_LLM_MODEL") or ("gpt-4o" if os.environ.get("OPENAI_API_KEY") else "gemini-2.5-flash")
            print(f"[ScannerEngine] InjectionAgent detected. Invoking Agent tool for '{self.target_dir}' using model '{llm_model}'...")

            agent_output = scan_repository_sql_vulnerabilities.invoke({
                "repo_path": self.target_dir,
                "repo_url": "",
                "branch": "main",
                "llm_model": llm_model
            })

            if agent_output and isinstance(agent_output, dict) and "findings" in agent_output and not agent_output.get("error"):
                print(f"[ScannerEngine] InjectionAgent scan succeeded with {len(agent_output['findings'])} findings.")
                return self._convert_agent_output(agent_output)
            else:
                print(f"[ScannerEngine] InjectionAgent returned error or empty output: {agent_output.get('error')}. Falling back to AST engine.")
                return None
        except Exception as e:
            print(f"[ScannerEngine] InjectionAgent unavailable or failed ({e}). Falling back to existing AST scanner engine.")
            return None

    def _convert_agent_output(self, agent_output: dict) -> ScanResult:
        findings: List[Finding] = []
        raw_findings = agent_output.get("findings", [])

        for f in raw_findings:
            if hasattr(f, "model_dump"):
                f = f.model_dump()

            rel_path = f.get("file_path", "")
            line_no = f.get("line_number", 1)

            # Map data flow trace
            trace_steps: List[DataFlowStep] = []
            df_list = f.get("data_flow_trace") or f.get("data_flow") or []
            if isinstance(df_list, list) and df_list:
                for item in df_list:
                    if hasattr(item, "model_dump"):
                        item = item.model_dump()
                    if isinstance(item, dict):
                        trace_steps.append(DataFlowStep(
                            step_number=item.get("step_number", len(trace_steps) + 1),
                            file_path=item.get("file_path", rel_path),
                            line_number=item.get("line_number", line_no),
                            step_type=item.get("step_type", "sink"),
                            description=item.get("description", "SQL execution step"),
                            code_excerpt=item.get("code_excerpt", f.get("code_excerpt", ""))
                        ))

            if not trace_steps:
                trace_steps = [
                    DataFlowStep(
                        step_number=1,
                        file_path=rel_path,
                        line_number=line_no,
                        step_type="sink",
                        description="Unsafe SQL execution at database sink",
                        code_excerpt=f.get("code_excerpt", "")
                    )
                ]

            sev_val = f.get("severity", "High")
            conf_val = f.get("confidence", "Likely")
            try:
                severity = SeverityLevel(sev_val)
            except Exception:
                severity = SeverityLevel.HIGH
            try:
                confidence = ConfidenceLevel(conf_val)
            except Exception:
                confidence = ConfidenceLevel.LIKELY

            finding = Finding(
                id=f.get("id") or f"FIND-{uuid.uuid4().hex[:8].upper()}",
                scan_id=self.scan_id,
                title=f"SQL Injection in {os.path.basename(rel_path)}",
                summary=f.get("explanation") or "Potential SQL Injection vulnerability detected by InjectionAgent.",
                severity=severity,
                confidence=confidence,
                cwe_id=f.get("cwe_id", "CWE-89"),
                cwe_title="SQL Injection",
                vulnerability_type=f.get("vulnerability_type", "SQL Injection"),
                file_path=rel_path,
                line_number=line_no,
                line_end=line_no,
                function_name=f.get("function_name"),
                code_excerpt=f.get("code_excerpt", ""),
                surrounding_context=f.get("surrounding_context", ""),
                sql_query_snippet=f.get("sql_query_snippet") or f.get("code_excerpt", ""),
                data_flow_trace=trace_steps,
                tech_stack=f.get("tech_stack", "Database Access Layer"),
                status=FindingStatus.OPEN,
                proposed_fix=f.get("proposed_fix") or f.get("llm_safe_query", ""),
                expected_behavior="Query executes safely using parameterized bindings.",
                explanation=f.get("explanation", ""),
                last_updated=datetime.now().isoformat()
            )
            findings.append(finding)

        by_sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        by_conf = {"Confirmed": 0, "Likely": 0, "Suspected": 0}

        for f in findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
            by_conf[f.confidence.value] = by_conf.get(f.confidence.value, 0) + 1

        summary = ScanSummary(
            total_findings=len(findings),
            by_severity=by_sev,
            by_confidence=by_conf,
            files_scanned=agent_output.get("files_scanned", 1),
            scan_duration_seconds=agent_output.get("scan_duration_seconds", 0.0),
            status="Completed"
        )

        return ScanResult(
            scan_id=self.scan_id,
            repo_name=agent_output.get("repo_name") or os.path.basename(self.target_dir),
            repo_url=None,
            branch="main",
            commit_sha="head",
            scanned_at=datetime.now().isoformat(),
            summary=summary,
            findings=findings
        )

    def _scan_repository_ast(self) -> ScanResult:
        """
        Original AST & static analysis scanner engine.
        Executed when InjectionAgent is not installed or unavailable.
        """
        start_time = datetime.now()
        files_to_scan = []

        for root, dirs, files in os.walk(self.target_dir):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in SUPPORTED_EXTENSIONS:
                    files_to_scan.append(os.path.join(root, file))

        findings: List[Finding] = []

        for file_path in files_to_scan:
            rel_path = os.path.relpath(file_path, self.target_dir)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                file_findings = self._analyze_file(rel_path, content)
                findings.extend(file_findings)
            except Exception as e:
                print(f"[ScannerEngine] Error scanning file {rel_path}: {e}")

        # Summary statistics
        duration = (datetime.now() - start_time).total_seconds()
        by_sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        by_conf = {"Confirmed": 0, "Likely": 0, "Suspected": 0}

        for f in findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
            by_conf[f.confidence.value] = by_conf.get(f.confidence.value, 0) + 1

        summary = ScanSummary(
            total_findings=len(findings),
            by_severity=by_sev,
            by_confidence=by_conf,
            files_scanned=len(files_to_scan),
            scan_duration_seconds=round(duration, 3),
            status="Completed"
        )

        return ScanResult(
            scan_id=self.scan_id,
            repo_name=os.path.basename(self.target_dir),
            repo_url=None,
            branch="main",
            commit_sha="head",
            scanned_at=datetime.now().isoformat(),
            summary=summary,
            findings=findings
        )

    def _analyze_file(self, rel_path: str, content: str) -> List[Finding]:
        lines = content.splitlines()
        ext = os.path.splitext(rel_path)[1].lower()
        lang = "python" if ext == ".py" else "javascript"

        findings: List[Finding] = []

        # Find all untrusted sources in file
        sources = self._detect_sources(lines, lang)

        # Find all SQL sinks in file
        sinks = self._detect_sinks(lines, lang)

        if not sinks:
            return []

        for sink in sinks:
            sink_line_idx = sink["line_idx"]
            sink_line_content = lines[sink_line_idx]

            # Check if this sink is already parameterized
            if self._is_parameterized(sink_line_content, lines, sink_line_idx):
                continue

            # Trace data flow back to source or dynamic concatenation
            trace_steps, var_name, has_untrusted_source = self._trace_data_flow(
                lines, sink_line_idx, sources, lang, rel_path
            )

            # Inspect window of lines up to 10 lines prior to sink for dynamic query construction
            start_window = max(0, sink_line_idx - 10)
            window_lines = lines[start_window:sink_line_idx + 1]
            window_text = " ".join(window_lines)

            # Detect dynamic construction type
            is_concat = ("+" in window_text or "${" in window_text or "f\"" in window_text or "f'" in window_text or ".format(" in window_text or " % " in window_text)

            # Check for unsafe ORDER BY or identifier interpolation
            is_order_by = "order by" in window_text.lower() or "group by" in window_text.lower()

            if not has_untrusted_source and not is_concat:
                continue

            # Assign Severity & Confidence
            if has_untrusted_source and (is_concat or is_order_by):
                sev = SeverityLevel.CRITICAL if is_concat else SeverityLevel.HIGH
                conf = ConfidenceLevel.CONFIRMED
            elif has_untrusted_source:
                sev = SeverityLevel.HIGH
                conf = ConfidenceLevel.LIKELY
            elif is_concat:
                sev = SeverityLevel.MEDIUM
                conf = ConfidenceLevel.SUSPECTED
            else:
                continue

            finding_id = f"FIND-{uuid.uuid4().hex[:8].upper()}"
            fn_name = self._find_enclosing_function(lines, sink_line_idx, lang)
            context_code = self._extract_context(lines, sink_line_idx)

            proposed_fix, expected_behavior, sql_snippet = self._generate_fix_suggestion(
                lines, sink_line_idx, sink["framework"], lang, var_name
            )

            finding = Finding(
                id=finding_id,
                scan_id=self.scan_id,
                title=f"SQL Injection via Unsafe Query Construction in {os.path.basename(rel_path)}",
                summary=f"Unsanitized user-controlled input flows directly into database execution sink ({sink['framework']}) without parameterization.",
                severity=sev,
                confidence=conf,
                cwe_id="CWE-89",
                cwe_title="Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                vulnerability_type="SQL Injection (Raw Query / Dynamic Construction)",
                file_path=rel_path,
                line_number=sink_line_idx + 1,
                line_end=sink_line_idx + 1,
                function_name=fn_name,
                code_excerpt=redact_secrets(lines[sink_line_idx].strip()),
                surrounding_context=redact_secrets(context_code),
                sql_query_snippet=redact_secrets(sql_snippet),
                data_flow_trace=trace_steps,
                tech_stack=sink["framework"],
                status=FindingStatus.OPEN,
                proposed_fix=redact_secrets(proposed_fix),
                expected_behavior=expected_behavior,
                explanation=(
                    f"In `{rel_path}` at line {sink_line_idx + 1}, dynamic query string construction "
                    f"interpolates variables directly into the SQL statement executed via {sink['framework']}. "
                    "Attacker-controlled input can alter SQL syntax, enabling arbitrary query execution or data exfiltration."
                ),
                last_updated=datetime.now().isoformat()
            )
            findings.append(finding)

        return findings

    def _detect_sources(self, lines: List[str], lang: str) -> List[Dict[str, Any]]:
        sources = []
        patterns = UNTRUSTED_SOURCES.get(lang, [])
        for line_idx, line in enumerate(lines):
            for pattern in patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    sources.append({
                        "line_idx": line_idx,
                        "content": line.strip(),
                        "match_text": match.group(0)
                    })
        return sources

    def _detect_sinks(self, lines: List[str], lang: str) -> List[Dict[str, Any]]:
        sinks = []
        sink_rules = SQL_SINKS.get(lang, [])
        for line_idx, line in enumerate(lines):
            for rule in sink_rules:
                if re.search(rule["pattern"], line):
                    sinks.append({
                        "line_idx": line_idx,
                        "content": line.strip(),
                        "framework": rule["framework"]
                    })
        return sinks

    def _is_parameterized(self, line: str, lines: List[str], line_idx: int) -> bool:
        start_window = max(0, line_idx - 5)
        window_lines = lines[start_window:line_idx + 1]
        window_text = " ".join([l.strip() for l in window_lines])

        # Check if line contains parameter array/tuple or safe binding
        for safe_pattern in SAFE_PARAMETERIZED_PATTERNS:
            if re.search(safe_pattern, line) or re.search(safe_pattern, window_text):
                return True

        # Check variable-based parameterized call e.g. client.query(sql, [userId]) where sql has $1 or ?
        if re.search(r'\.\s*(query|execute|all|get|run)\s*\(\s*[a-zA-Z0-9_]+\s*,\s*\[[^\]]+\]', line) or \
           re.search(r'\.\s*(query|execute|all|get|run)\s*\(\s*[a-zA-Z0-9_]+\s*,\s*\([^\)]+\)', line):
            if "$1" in window_text or "?" in window_text or "%s" in window_text or ":user" in window_text:
                return True

        # Check if input variable was sanitized with parseInt / int() / Number() in window
        for sanitizer in SAFE_SANITIZERS:
            if re.search(sanitizer, window_text):
                return True

        return False

    def _trace_data_flow(
        self,
        lines: List[str],
        sink_line_idx: int,
        sources: List[Dict[str, Any]],
        lang: str,
        rel_path: str
    ) -> Tuple[List[DataFlowStep], Optional[str], bool]:
        steps: List[DataFlowStep] = []
        has_untrusted_source = False
        var_name = None

        # Look backwards from sink line to find variable definitions & sources
        sink_line = lines[sink_line_idx]

        # Extract variable used in sink
        var_match = re.search(r'\+\s*([a-zA-Z0-9_\.\[\]]+)|\$\{([a-zA-Z0-9_\.]+)\}|f["\'].*?\{([a-zA-Z0-9_\.]+)\}', sink_line)
        if var_match:
            var_name = var_match.group(1) or var_match.group(2) or var_match.group(3)

        # Step 1: Identify source if present in local scope
        matching_source = None
        for src in sources:
            if src["line_idx"] <= sink_line_idx and (sink_line_idx - src["line_idx"]) < 35:
                matching_source = src
                has_untrusted_source = True
                break

        step_num = 1
        if matching_source:
            steps.append(DataFlowStep(
                step_number=step_num,
                file_path=rel_path,
                line_number=matching_source["line_idx"] + 1,
                step_type="source",
                description=f"Untrusted input entrypoint: `{matching_source['match_text']}`",
                code_excerpt=redact_secrets(matching_source["content"]),
                variable_name=var_name
            ))
            step_num += 1

            # Look for variable assignment
            for l_idx in range(matching_source["line_idx"], sink_line_idx):
                l_content = lines[l_idx]
                if "=" in l_content and not l_content.strip().startswith("//") and not l_content.strip().startswith("#"):
                    steps.append(DataFlowStep(
                        step_number=step_num,
                        file_path=rel_path,
                        line_number=l_idx + 1,
                        step_type="variable_assignment",
                        description=f"Input assigned or passed to local variable in line {l_idx + 1}",
                        code_excerpt=redact_secrets(l_content.strip()),
                        variable_name=var_name
                    ))
                    step_num += 1
                    break

        # Step: Dynamic query construction
        steps.append(DataFlowStep(
            step_number=step_num,
            file_path=rel_path,
            line_number=sink_line_idx + 1,
            step_type="string_concatenation",
            description="Dynamic SQL query string constructed via string concatenation / interpolation",
            code_excerpt=redact_secrets(lines[sink_line_idx].strip()),
            variable_name=var_name
        ))
        step_num += 1

        # Step: Execution Sink
        steps.append(DataFlowStep(
            step_number=step_num,
            file_path=rel_path,
            line_number=sink_line_idx + 1,
            step_type="sink",
            description=f"Unsafe SQL query string executed at database sink line {sink_line_idx + 1}",
            code_excerpt=redact_secrets(lines[sink_line_idx].strip()),
            variable_name=var_name
        ))

        return steps, var_name, has_untrusted_source

    def _find_enclosing_function(self, lines: List[str], line_idx: int, lang: str) -> Optional[str]:
        fn_pattern = r'def\s+([a-zA-Z0-9_]+)' if lang == "python" else r'(async\s+)?function\s+([a-zA-Z0-9_]+)|const\s+([a-zA-Z0-9_]+)\s*=\s*(async\s*)?\('
        for idx in range(line_idx, -1, -1):
            line = lines[idx]
            match = re.search(fn_pattern, line)
            if match:
                return match.group(1) or match.group(2) or match.group(3)
        return "handler"

    def _extract_context(self, lines: List[str], line_idx: int) -> str:
        start = max(0, line_idx - 5)
        end = min(len(lines), line_idx + 6)
        formatted = []
        for i in range(start, end):
            prefix = "> " if i == line_idx else "  "
            formatted.append(f"{prefix}{i+1:4d} | {lines[i]}")
        return "\n".join(formatted)

    def _generate_fix_suggestion(
        self,
        lines: List[str],
        line_idx: int,
        framework: str,
        lang: str,
        var_name: Optional[str]
    ) -> Tuple[str, str, str]:
        line = lines[line_idx].strip()
        sql_snippet = line
        var_ref = var_name if var_name else "user_input"

        if lang == "python":
            # Python parameterized query fix
            if "sqlite3" in framework.lower() or "db-api" in framework.lower():
                fixed_code = f"cursor.execute(\"SELECT * FROM users WHERE username = ?\", ({var_ref},))"
            elif "sqlalchemy" in framework.lower():
                fixed_code = f"session.execute(text(\"SELECT * FROM users WHERE username = :user\"), {{\"user\": {var_ref}}})"
            else:
                fixed_code = f"cursor.execute(\"SELECT * FROM users WHERE username = %s\", ({var_ref},))"
            expected = "Query executed safely using prepared statement parameterized binding parameters."
        else:
            # Node.js parameterized query fix
            if "sqlite3" in framework.lower():
                fixed_code = f"db.get(\"SELECT * FROM users WHERE username = ?\", [{var_ref}], (err, row) => {{ ... }});"
            elif "sequelize" in framework.lower():
                fixed_code = f"sequelize.query(\"SELECT * FROM users WHERE username = :user\", {{ replacements: {{ user: {var_ref} }}, type: QueryTypes.SELECT }});"
            else:
                fixed_code = f"const result = await db.query(\"SELECT * FROM users WHERE username = $1\", [{var_ref}]);"
            expected = "Database engine validates SQL structure independently from bound query parameters."

        return fixed_code, expected, sql_snippet
