# core/filters.py
import re

SUSPICIOUS_PATTERNS = [
    r"ignore previous instructions",
    r"ignore all previous instructions",
    r"you are now",
    r"system prompt",
    r"developer message",
    r"bypass",
    r"jailbreak",
    r"delete all",
    r"drop table",
    r"union select",
    r"or 1=1",
    r"\.\./",
]

def contains_malicious_content(params):
    text = str(params).lower()

    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, text):
            return True, pattern

    return False, None