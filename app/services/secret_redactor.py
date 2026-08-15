import re
from typing import List, Tuple

# Patterns for redacting sensitive tokens, passwords, database URIs, API keys
SECRET_PATTERNS: List[Tuple[str, str]] = [
    (r'(?i)(postgres|postgresql|mysql|mongodb|redis)://[^\s:@]+:([^\s@]+)@', r'\1://[REDACTED_USER]:[REDACTED_SECRET]@'),
    (r'(?i)(api[_-]?key|secret|password|passwd|token|auth[_-]?token)\s*=\s*["\']([^"\']+)["\']', r'\1 = "[REDACTED_SECRET]"'),
    (r'(?i)(api[_-]?key|secret|password|passwd|token|auth[_-]?token)\s*:\s*["\']([^"\']+)["\']', r'\1: "[REDACTED_SECRET]"'),
    (r'AKIA[0-9A-Z]{16}', '[REDACTED_AWS_KEY]'),
    (r'ghp_[a-zA-Z0-9]{36}', '[REDACTED_GITHUB_TOKEN]'),
    (r'bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*', '[REDACTED_BEARER_TOKEN]')
]

def redact_secrets(text: str) -> str:
    """
    Scans input text and replaces secret tokens, passwords, and sensitive API keys with redacted placeholders.
    """
    if not text:
        return text
    
    redacted = text
    for pattern, replacement in SECRET_PATTERNS:
        redacted = re.sub(pattern, replacement, redacted)
    return redacted
