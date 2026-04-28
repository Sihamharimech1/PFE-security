from agents.base_agent import BaseAgent
from core.llm_provider import LLMProvider
from core.parser import parse_response


class WriterAgent(BaseAgent):
    """
    Agent 3 — Writer.
    Role    : writer
    Job     : Receives analysis from the Analyst and turns it into
              a clean, formatted, human-readable report.

    Key distinction from Analyst:
      - Analyst  → understands the data, finds risks, draws conclusions
      - Writer   → takes those conclusions and formats them beautifully
                   for a human reader (manager, client, auditor)

    Allowed actions: write_report, format_document, save_report
    Forbidden      : analyze_data, fetch_api, delete_data, modify_config
    """

    def __init__(self, agent_id, control):
        super().__init__(agent_id, "writer", control)
        self.llm = LLMProvider()

    def think_and_act(self, analyst_output: str, report_type: str = "security"):
        """
        Main entry point.

        analyst_output : the text produced by the AnalystAgent
        report_type    : "security" | "summary" | "executive"
        """
        prompt = f"""
You are a routing agent for a Writer. Your ONLY job is to pick the right writing action.

STRICT RULES:

1. Use "write_report" when:
   - You received a full analysis with findings, risks, recommendations
   - The content needs a structured multi-section document

2. Use "format_document" when:
   - The input is already written but needs better formatting
   - The user asks to "clean up", "restructure", or "reformat"

3. Use "save_report" ONLY when:
   - The report is already written and the user says "save" or "export"

DEFAULT: If unsure → always use "write_report".

Input received from analyst:
\"\"\"{analyst_output}\"\"\"

Report type requested: {report_type}

Return ONLY this JSON, no explanation, no markdown:
{{
  "action": "write_report" | "format_document" | "save_report",
  "params": {{
    "analyst_output": "{analyst_output[:200]}...",
    "report_type": "{report_type}"
  }}
}}
"""

        response = self.llm.generate(prompt)

        print("\n[LLM RAW RESPONSE - WRITER]")
        print(response)

        decision = parse_response(response)

        # Safety fallback
        valid_actions = ["write_report", "format_document", "save_report"]
        if decision.get("action") not in valid_actions:
            print(f"[WARNING] Invalid action '{decision.get('action')}' — falling back to write_report")
            decision["action"] = "write_report"

        # Always carry full context forward
        if "params" not in decision or not isinstance(decision["params"], dict):
            decision["params"] = {}

        decision["params"]["analyst_output"] = analyst_output
        decision["params"]["report_type"]    = report_type

        print("\n[PARSED DECISION - WRITER]")
        print(decision)

        return self.execute_action(
            decision["action"],
            decision["params"]
        )