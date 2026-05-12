# core/parser.py
import json
import re

def parse_response(response):
    if not isinstance(response, str):
        return {"action": "invalid", "params": {}}

    text = response.strip()

    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 3:
            text = "\n".join(lines[1:-1]).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass

    return {"action": "invalid", "params": {}}