# core/executor.py

import os
import json
import requests
import subprocess
from datetime import datetime
from core.llm_provider import LLMProvider


ALLOWED_COMMANDS = ["whoami", "hostname", "ping", "ipconfig", "ifconfig", "echo"]


class ExecutionEngine:
    def __init__(self):
        self.llm = LLMProvider()

    def execute(self, action, params):
        if action == "fetch_api":       return self.fetch_api(params)
        if action == "read_data":       return self.read_data(params)
        if action == "direct_answer":   return self.direct_answer(params)
        if action == "analyze_data":    return self.analyze_data(params)
        if action == "generate_report": return self.generate_report(params)
        if action == "write_report":    return self.write_report(params)
        if action == "format_document": return self.format_document(params)
        if action == "save_report":     return self.save_report(params)
        if action == "execute_action":  return self.run_execute_action(params)
        if action == "delete_data":     return self.delete_data(params)
        if action == "write_data":      return self.write_data(params)
        if action == "run_command":     return self.run_command(params)
        return {"status": "error", "message": f"Unknown action: {action}"}

    def direct_answer(self, params):
        user_input = params.get("original_input") or params.get("prompt")
        if not user_input:
            return {"status": "error", "message": "No input provided"}
        report_kw = ["write a report", "generate a report", "create a report", "make a report"]
        if any(kw in user_input.lower() for kw in report_kw):
            return {"status": "redirected", "action": "direct_answer",
                    "answer": "[AnalystAgent] Writing reports is not within my permissions. Please use the WriterAgent."}
        prompt = f"You are a helpful assistant. Answer clearly and concisely. Do NOT write a report.\n\nQuestion: {user_input}"
        return {"status": "success", "action": "direct_answer", "answer": self.llm.generate(prompt)}

    def analyze_data(self, params):
        data = params.get("data") or params.get("original_input")
        if not data:
            return {"status": "error", "message": "No data provided for analysis"}
        prompt = f"""You are an analyst agent.
Analyze the following input. Do NOT write a full report. Focus on findings only.

Input:
{data}

Return:
- Summary (1-3 sentences)
- Key findings (bullet points)
- Risk level: Low / Medium / High
- Recommended next action (2-3 sentences)"""
        analysis = self.llm.generate(prompt)
        return {"status": "success", "action": "analyze_data", "analysis": analysis,
                "params_for_next": {"analysis": analysis, "original_input": data}}

    def generate_report(self, params):
        analysis = params.get("analysis") or f"Report about: {params.get('original_input','')}"
        prompt = f"""You are a professional report writer.
Write a structured report based on this analysis:
{analysis}

Structure: Title, Executive Summary, Findings, Risk Assessment, Recommendations, Conclusion."""
        return {"status": "success", "action": "generate_report", "report": self.llm.generate(prompt)}

    # ── REAL: hits the actual URL ───────────────────────────────────────
    def fetch_api(self, params):
        url = params.get("url")
        if not url:
            return {"status": "error", "message": "Missing URL"}
        try:
            response = requests.get(url, timeout=10)
            print(f"[ExecutionEngine] fetch_api → {url} | HTTP {response.status_code}")
            return {"status": "success", "action": "fetch_api", "url": url,
                    "status_code": response.status_code, "content_preview": response.text[:800]}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    # ── REAL: reads from disk if path given ────────────────────────────
    def read_data(self, params):
        path = params.get("path")
        data = params.get("data")
        if path:
            if not os.path.exists(path):
                return {"status": "error", "message": f"File not found: {path}"}
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            print(f"[ExecutionEngine] read_data → {len(content)} chars from '{path}'")
            return {"status": "success", "action": "read_data", "path": path, "data": content}
        if data:
            return {"status": "success", "action": "read_data", "data": data}
        return {"status": "error", "message": "No path or data provided"}

    def write_report(self, params):
        analyst_output = params.get("analyst_output")
        if not analyst_output:
            return {"status": "error", "message": "No analyst output provided"}
        report_type = params.get("report_type", "security")
        audience_map = {"security": "a technical security team",
                        "executive": "a non-technical executive or manager",
                        "summary": "a quick 1-page briefing for any reader"}
        audience = audience_map.get(report_type, "a technical security team")
        prompt = f"""You are a professional technical writer.
Take this analyst output and write a clear professional report for: {audience}.
Do NOT re-analyze. Do NOT add new findings. Only rewrite and format clearly.

--- ANALYST OUTPUT ---
{analyst_output}
--- END ---

Format:
# [Report Title]
## Executive Summary
## Incident / Event Details
## Findings
## Risk Assessment
## Recommendations
## Conclusion
---
Report generated by: WriterAgent | Audience: {audience}"""
        return {"status": "success", "action": "write_report",
                "report_type": report_type, "report": self.llm.generate(prompt)}

    def format_document(self, params):
        content = params.get("analyst_output") or params.get("content")
        if not content:
            return {"status": "error", "message": "No content provided to format"}
        prompt = f"You are a document formatter. Clean up and structure this text without changing any facts:\n\n{content}"
        return {"status": "success", "action": "format_document", "formatted": self.llm.generate(prompt)}

    # ── REAL: writes .md file to output_reports/ ───────────────────────
    def save_report(self, params):
        report_content = params.get("analyst_output") or params.get("report")
        report_type    = params.get("report_type", "report")
        if not report_content:
            return {"status": "error", "message": "No report content to save"}
        os.makedirs("output_reports", exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename  = f"output_reports/{report_type}_{timestamp}.md"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report_content)
        print(f"[WriterAgent] Report saved → {filename}  ({len(report_content)} chars)")
        return {"status": "success", "action": "save_report", "filename": filename}

    def run_execute_action(self, params):
        instruction = params.get("original_input") or params.get("instruction")
        if not instruction:
            return {"status": "error", "message": "No instruction provided"}
        prompt = f"You are a remediation agent. Act on this instruction and confirm:\n{instruction}"
        return {"status": "success", "action": "execute_action", "result": self.llm.generate(prompt)}

    # ── REAL: deletes file — safety check enforced ─────────────────────
    def delete_data(self, params):
        target = params.get("target") or params.get("original_input")
        if not target:
            return {"status": "error", "message": "No target specified"}
        safe_prefixes = ["sandbox/", "output_reports/", "sample_logs/"]
        is_safe = (any(target.startswith(p) for p in safe_prefixes)
                   or os.path.basename(target).startswith("dummy_"))
        if not is_safe:
            print(f"[ExecutionEngine] delete_data SAFETY BLOCK — '{target}' not in safe scope")
            return {"status": "blocked", "message": f"Safety block: '{target}' outside allowed scope."}
        if not os.path.exists(target):
            return {"status": "error", "message": f"File not found: '{target}'"}
        os.remove(target)
        print(f"[ExecutionEngine] delete_data → DELETED '{target}'")
        return {"status": "success", "action": "delete_data", "target": target,
                "message": f"File '{target}' deleted."}

    # ── REAL: writes JSON to output_config/ ────────────────────────────
    def write_data(self, params):
        target  = params.get("target", "output_config/patch.json")
        content = params.get("content", {})
        raw     = params.get("original_input", "")
        if not target.startswith("output_config/"):
            target = f"output_config/{os.path.basename(target)}"
            if not target.endswith(".json"):
                target += ".json"
        os.makedirs("output_config", exist_ok=True)
        payload = content if content else {"instruction": raw, "written_at": datetime.utcnow().isoformat()}
        with open(target, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"[ExecutionEngine] write_data → WRITTEN '{target}'")
        return {"status": "success", "action": "write_data", "file": target,
                "message": f"Data written to '{target}'."}

    # ── REAL: subprocess with strict whitelist ─────────────────────────
    def run_command(self, params):
        command = params.get("command") or params.get("original_input", "")
        base    = command.strip().split()[0].lower()
        if base not in ALLOWED_COMMANDS:
            print(f"[ExecutionEngine] run_command BLOCKED — '{base}' not in whitelist")
            return {"status": "blocked", "message": f"'{base}' not in allowed list: {ALLOWED_COMMANDS}"}
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout or result.stderr or "(no output)"
            print(f"[ExecutionEngine] run_command → '{command}'")
            return {"status": "success", "action": "run_command", "command": command, "output": output.strip()}
        except subprocess.TimeoutExpired:
            return {"status": "error", "message": f"Command timed out"}
        except Exception as e:
            return {"status": "error", "message": str(e)}