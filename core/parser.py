# core/parser.py
import json

def parse_response(response):
    try:
        return json.loads(response)
    except:
        return {"action": "invalid", "params": {}}