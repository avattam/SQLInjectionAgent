"""
InjectionAgent LLM Initialization
Provides a configurable LLM via langchain-google-genai (Gemini) or langchain-openai.
Auto-routes to the correct provider based on the model name prefix:
  - "gemini-*"  → Google Gemini via langchain-google-genai
  - "gpt-*"     → OpenAI via langchain-openai
  - "o1-*"      → OpenAI o1 reasoning models via langchain-openai
  - "o3-*"      → OpenAI o3 models via langchain-openai

Falls back to an offline mock LLM when no API key is configured (for unit tests).
"""
import os


def get_llm(model_name: str = "gemini-2.5-flash", temperature: float = 0.0):
    """
    Returns a LangChain chat model auto-routed to the correct provider.

    Provider detection (by model name prefix):
      - gemini-* → Google Gemini (requires GEMINI_API_KEY or GOOGLE_API_KEY)
      - gpt-*, o1-*, o3-* → OpenAI (requires OPENAI_API_KEY)

    Args:
        model_name: Model identifier string, e.g.:
                    Gemini: "gemini-2.5-flash", "gemini-2.5-pro"
                    OpenAI: "gpt-4o", "gpt-4o-mini", "o1-mini", "o1"
        temperature: Sampling temperature. Note: OpenAI o1/o3 models do not
                     support temperature and it will be ignored automatically.

    Returns:
        A LangChain BaseChatModel instance ready for invoke().
    """
    model_lower = model_name.lower()

    # ── OpenAI provider ──────────────────────────────────────────────────────
    if any(model_lower.startswith(prefix) for prefix in ("gpt-", "o1-", "o1", "o3-", "o3")):
        return _build_openai_llm(model_name, temperature)

    # ── Gemini provider (default) ─────────────────────────────────────────────
    if model_lower.startswith("gemini-") or model_lower.startswith("models/gemini"):
        return _build_gemini_llm(model_name, temperature)

    # ── Unknown prefix: try Gemini first, then OpenAI ────────────────────────
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if api_key:
        return _build_gemini_llm(model_name, temperature)

    openai_key = os.environ.get("OPENAI_API_KEY")
    if openai_key:
        return _build_openai_llm(model_name, temperature)

    # No API key at all → offline mock
    return _MockLLM()


def _build_gemini_llm(model_name: str, temperature: float):
    """Builds a Gemini LLM via langchain-google-genai."""
    import warnings
    warnings.filterwarnings("ignore", category=UserWarning, message=".*automatic function calling.*")
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        print(f"[InjectionAgent] WARNING: No GEMINI_API_KEY set for model '{model_name}'. Using offline mock.")
        return _MockLLM()
    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
        # Gemini 1.5+ natively supports SystemMessage — no conversion needed
        return ChatGoogleGenerativeAI(
            model=model_name,
            temperature=temperature,
            google_api_key=api_key,
        )
    except ImportError:
        raise ImportError(
            "langchain-google-genai is required for Gemini models.\n"
            "Install with: pip install langchain-google-genai"
        )


def _build_openai_llm(model_name: str, temperature: float):
    """Builds an OpenAI LLM via langchain-openai."""
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print(f"[InjectionAgent] WARNING: No OPENAI_API_KEY set for model '{model_name}'. Using offline mock.")
        return _MockLLM()
    try:
        from langchain_openai import ChatOpenAI

        # o1 / o3 reasoning models do not support temperature or system messages
        is_reasoning_model = any(
            model_name.lower().startswith(p) for p in ("o1", "o3")
        )
        kwargs = {
            "model": model_name,
            "openai_api_key": api_key,
        }
        if not is_reasoning_model:
            kwargs["temperature"] = temperature

        # Allow custom base URL for proxies / Azure / local OpenAI-compat servers
        openai_base = os.environ.get("OPENAI_API_BASE") or os.environ.get("OPENAI_BASE_URL")
        if openai_base:
            kwargs["openai_api_base"] = openai_base

        llm = ChatOpenAI(**kwargs)
        return llm if not is_reasoning_model else _OpenAIReasoningWrapper(llm)
    except ImportError:
        raise ImportError(
            "langchain-openai is required for OpenAI models.\n"
            "Install with: pip install langchain-openai"
        )


class _OpenAIReasoningWrapper:
    """
    Thin wrapper for o1/o3 reasoning models that strips SystemMessage (not supported)
    and merges it into the first HumanMessage.
    """
    def __init__(self, llm):
        self._llm = llm

    def invoke(self, messages):
        from langchain_core.messages import HumanMessage, SystemMessage
        merged = []
        system_text = ""
        for msg in messages:
            if isinstance(msg, SystemMessage):
                system_text = msg.content
            else:
                merged.append(msg)
        # Prepend system context into the first human message
        if system_text and merged:
            first = merged[0]
            merged[0] = HumanMessage(content=f"[Instructions]\n{system_text}\n\n[Task]\n{first.content}")
        return self._llm.invoke(merged)


class _MockLLM:
    """
    Offline mock LLM for unit testing without a live API key.
    Dynamically tailors proposed fixes to the snippet context instead of static hardcoding.
    """
    def invoke(self, messages):
        from langchain_core.messages import AIMessage
        import re

        prompt_text = ""
        for m in messages:
            prompt_text += getattr(m, "content", str(m)) + "\n"

        is_js = "Language: javascript" in prompt_text or "server.js" in prompt_text or "Node" in prompt_text
        
        # Extract snippet or variable if possible
        var_match = re.search(r'([a-zA-Z0-9_]+)\s*(?:=|in|\+)', prompt_text)
        var_name = var_match.group(1) if var_match else "user_input"

        if is_js:
            proposed_fix = f"client.query('SELECT * FROM items WHERE id = $1', [{var_name}]);"
            safe_example = f"client.query('SELECT * FROM items WHERE id = $1', [{var_name}]);"
        else:
            proposed_fix = f"cursor.execute('SELECT * FROM items WHERE id = ?', ({var_name},))"
            safe_example = f"cursor.execute('SELECT * FROM items WHERE id = ?', ({var_name},))"

        return AIMessage(content=f"""{{
  "is_sql_injection": true,
  "severity": "High",
  "confidence": "Likely",
  "unsafe_pattern": "dynamic SQL construction with user-controlled input",
  "tainted_variable": "{var_name}",
  "explanation": "[MOCK] Dynamic query construction with user-controlled input reaches SQL execution sink without parameterization.",
  "proposed_fix": "{proposed_fix}",
  "safe_query_example": "{safe_example}",
  "model": "mock-offline"
}}""")
