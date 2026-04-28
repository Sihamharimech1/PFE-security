# core/executor.py

import requests
from core.llm_provider import LLMProvider


class ExecutionEngine:
    def __init__(self):
        self.llm = LLMProvider()

    def execute(self, action, params):
        if action == "fetch_api":
            return self.fetch_api(params)

        if action == "read_data":
            return self.read_data(params)

        if action == "direct_answer":
            return self.direct_answer(params)

        if action == "analyze_data":
            return self.analyze_data(params)

        if action == "generate_report":
            return self.generate_report(params)

        # ── Writer actions ──────────────────────────────────────────────────
        if action == "write_report":
            return self.write_report(params)

        if action == "format_document":
            return self.format_document(params)

        if action == "save_report":
            return self.save_report(params)

        # ── Executor actions ────────────────────────────────────────────────
        if action == "execute_action":
            return self.run_execute_action(params)

        if action == "delete_data":
            return self.delete_data(params)

        if action == "write_data":
            return self.write_data(params)

        if action == "run_command":
            return self.run_command(params)

        return {
            "status": "error",
            "message": f"Unknown action: {action}"
        }

    # ------------------------------------------------------------------ #
    #  direct_answer — uses the original user input, not a blank prompt   #
    # ------------------------------------------------------------------ #
    def direct_answer(self, params):
        user_input = params.get("original_input") or params.get("prompt")

        if not user_input:
            return {
                "status": "error",
                "message": "No input provided for direct answer"
            }

        # Detect report requests and redirect — don't answer them
        report_keywords = ["write a report", "generate a report", "create a report", "make a report"]
        if any(kw in user_input.lower() for kw in report_keywords):
            return {
                "status": "redirected",
                "action": "direct_answer",
                "answer": (
                    "[AnalystAgent] I can analyze data and answer questions, "
                    "but writing reports is not within my permissions. "
                    "Please use the WriterAgent for that."
                )
            }

        prompt = f"""You are a helpful assistant. Answer the following question clearly and concisely.
Do NOT write a report. Do NOT add sections or headers. Just answer directly.

Question: {user_input}"""

        answer = self.llm.generate(prompt)

        return {
            "status": "success",
            "action": "direct_answer",
            "answer": answer
        }

    # ------------------------------------------------------------------ #
    #  analyze_data — only runs when actual data was provided             #
    # ------------------------------------------------------------------ #
    def analyze_data(self, params):
        # Try "data" first, fall back to original_input
        data = params.get("data") or params.get("original_input")

        if not data:
            return {
                "status": "error",
                "message": "No data provided for analysis"
            }

        prompt = f"""You are a security analyst agent.

Analyze the following input and return a structured analysis.
Do NOT write a full report. Focus on findings only.

Input to analyze:
{data}

Return your analysis with:
- Summary (1-2 sentences)
- Key findings (bullet points)
- Risk level: Low / Medium / High
- Recommended next action (1 sentence)"""

        analysis = self.llm.generate(prompt)

        return {
            "status": "success",
            "action": "analyze_data",
            "analysis": analysis,
            # Pass analysis forward in case generate_report is called next
            "params_for_next": {"analysis": analysis, "original_input": data}
        }

    # ------------------------------------------------------------------ #
    #  generate_report — only when explicitly requested                   #
    # ------------------------------------------------------------------ #
    def generate_report(self, params):
        # Use existing analysis if provided, otherwise use raw input
        analysis = params.get("analysis")
        original_input = params.get("original_input", "")

        if not analysis and not original_input:
            return {
                "status": "error",
                "message": "No content provided for report generation"
            }

        # If no prior analysis, generate the analysis first inline
        if not analysis:
            analysis = f"User requested a report about: {original_input}"

        prompt = f"""You are a professional report writer for a cybersecurity multi-agent system.

Based on the following analysis, write a structured professional report.

Analysis:
{analysis}

Report structure:
1. Title
2. Executive Summary (2-3 sentences)
3. Findings (bullet points)
4. Risk Assessment (Low / Medium / High with justification)
5. Recommendations (numbered list)
6. Conclusion (1-2 sentences)"""

        report = self.llm.generate(prompt)

        return {
            "status": "success",
            "action": "generate_report",
            "report": report
        }

    # ------------------------------------------------------------------ #
    #  fetch_api and read_data — unchanged                                #
    # ------------------------------------------------------------------ #
    def fetch_api(self, params):
        url = params.get("url")

        if not url:
            return {"status": "error", "message": "Missing URL"}

        try:
            response = requests.get(url, timeout=10)
            return {
                "status": "success",
                "action": "fetch_api",
                "url": url,
                "status_code": response.status_code,
                "content_preview": response.text[:1000]
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def read_data(self, params):
        data = params.get("data")

        if not data:
            return {"status": "error", "message": "No data provided"}

        return {
            "status": "success",
            "action": "read_data",
            "data": data
        }

    # ------------------------------------------------------------------ #
    #  write_report — Writer's main action                                #
    #  Input  : analyst findings (risk level, summary, key findings)      #
    #  Output : a polished document for a human reader                    #
    #                                                                     #
    #  KEY DIFFERENCE from generate_report (analyst):                    #
    #    generate_report  → analyst summarises what it found              #
    #    write_report     → writer formats it for a specific audience     #
    # ------------------------------------------------------------------ #
    def write_report(self, params):
        analyst_output = params.get("analyst_output")
        report_type    = params.get("report_type", "security")

        if not analyst_output:
            return {"status": "error", "message": "No analyst output provided to write report from"}

        audience_map = {
            "security":  "a technical security team",
            "executive": "a non-technical executive or manager",
            "summary":   "a quick 1-page briefing for any reader",
        }
        audience = audience_map.get(report_type, "a technical security team")

        prompt = f"""You are a professional technical writer working for a cybersecurity company.

You have received the following analysis from the security analyst agent:

--- ANALYST OUTPUT ---
{analyst_output}
--- END ---

Your job is NOT to re-analyze. Your job is to WRITE a clear, professional report
formatted for: {audience}.

Do NOT add new findings. Do NOT change the risk level.
Only rewrite, structure, and present the analyst's content clearly.

Report format:
# [Report Title]

## Executive Summary
(2-3 sentences, plain language)

## Incident / Event Details
(What happened, when, who was affected)

## Findings
(Bullet points from the analysis)

## Risk Assessment
(Restate the risk level with a short justification)

## Recommendations
(Numbered action items)

## Conclusion
(1-2 sentences closing statement)

---
Report generated by: WriterAgent
Audience: {audience}"""

        report = self.llm.generate(prompt)

        return {
            "status":      "success",
            "action":      "write_report",
            "report_type": report_type,
            "report":      report
        }

    # ------------------------------------------------------------------ #
    #  format_document — clean up already-written text                    #
    # ------------------------------------------------------------------ #
    def format_document(self, params):
        analyst_output = params.get("analyst_output") or params.get("content")

        if not analyst_output:
            return {"status": "error", "message": "No content provided to format"}

        prompt = f"""You are a document formatter. You receive raw or poorly structured text
and return a clean, well-formatted version.

Do NOT change the meaning. Do NOT add or remove facts.
Only improve structure, readability, and presentation.

Raw content:
{analyst_output}

Return the formatted version using proper headings, bullet points, and spacing."""

        formatted = self.llm.generate(prompt)

        return {
            "status":    "success",
            "action":    "format_document",
            "formatted": formatted
        }

    # ------------------------------------------------------------------ #
    #  save_report — persist the report to a .md file                    #
    # ------------------------------------------------------------------ #
    def save_report(self, params):
        import os
        from datetime import datetime

        report_content = params.get("analyst_output") or params.get("report")
        report_type    = params.get("report_type", "report")

        if not report_content:
            return {"status": "error", "message": "No report content to save"}

        os.makedirs("output_reports", exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename  = f"output_reports/{report_type}_{timestamp}.md"

        with open(filename, "w", encoding="utf-8") as f:
            f.write(report_content)

        print(f"[WriterAgent] Report saved → {filename}")

        return {
            "status":   "success",
            "action":   "save_report",
            "filename": filename
        }

    # ------------------------------------------------------------------ #
    #  Executor agent actions                                             #
    #  These are the only actions that modify state or run commands.      #
    #  All go through RBAC + filter + detection before reaching here.     #
    # ------------------------------------------------------------------ #

    def run_execute_action(self, params):
        """General remediation — uses LLM to decide what to do."""
        instruction = params.get("original_input") or params.get("instruction")

        if not instruction:
            return {"status": "error", "message": "No instruction provided"}

        prompt = f"""You are a security remediation executor agent.
You have been cleared to act on the following instruction.
Describe concisely what action you are taking and confirm it was applied.
Do NOT ask questions. Just act and confirm.

Instruction: {instruction}"""

        result = self.llm.generate(prompt)

        return {
            "status":  "success",
            "action":  "execute_action",
            "result":  result
        }

    def delete_data(self, params):
        """
        Simulates a delete operation.
        In production this would call a real DB or file system.
        For PFE demo: logs the intent without actually deleting anything.
        """
        target = params.get("target") or params.get("original_input")

        if not target:
            return {"status": "error", "message": "No target specified for deletion"}

        print(f"[ExecutorAgent] Simulating DELETE on target: '{target}'")

        return {
            "status":  "success",
            "action":  "delete_data",
            "target":  target,
            "message": f"[SIMULATED] Data at '{target}' has been deleted."
        }

    def write_data(self, params):
        """
        Simulates writing or patching data.
        In production this would update a DB record or config file.
        """
        target  = params.get("target")  or params.get("original_input")
        content = params.get("content") or "no content provided"

        if not target:
            return {"status": "error", "message": "No target specified for write"}

        print(f"[ExecutorAgent] Simulating WRITE to target: '{target}'")

        return {
            "status":  "success",
            "action":  "write_data",
            "target":  target,
            "content": content,
            "message": f"[SIMULATED] Data written to '{target}'."
        }

    def run_command(self, params):
        """
        Simulates running a system command.
        In production this would use subprocess with strict validation.
        For PFE demo: blocked for safety, prints the command that would run.
        """
        command = params.get("command") or params.get("original_input")

        if not command:
            return {"status": "error", "message": "No command specified"}

        print(f"[ExecutorAgent] Simulating RUN COMMAND: '{command}'")

        return {
            "status":  "success",
            "action":  "run_command",
            "command": command,
            "message": f"[SIMULATED] Command '{command}' executed in sandbox."
        }