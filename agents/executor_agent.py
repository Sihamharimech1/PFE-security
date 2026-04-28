# agents/executor_agent.py

from agents.base_agent import BaseAgent
from core.llm_provider import LLMProvider
from core.parser import parse_response


class ExecutorAgent(BaseAgent):
    """
    Agent 4 — Executor.
    Role    : executor
    Job     : The only agent that performs real destructive or
              state-changing actions (delete, write, run commands).

    Key distinction from all other agents:
      - Collector  → reads external data
      - Analyst    → reasons about data
      - Writer     → formats and saves reports
      - Executor   → modifies the system (delete, write, run)

    Because this agent has the highest privilege, every action:
      1. Goes through RBAC (strictest check)
      2. Goes through malicious content filter
      3. Goes through anomaly detection
      4. Requires a confirmation step before destructive actions

    Allowed actions : execute_action, delete_data, write_data, run_command
    Forbidden       : fetch_api, read_data, analyze_data, generate_report
    """

    # Actions that require explicit confirmation before running
    DESTRUCTIVE_ACTIONS = ["delete_data", "run_command"]

    def __init__(self, agent_id, control):
        super().__init__(agent_id, "executor", control)
        self.llm = LLMProvider()

    def think_and_act(self, instruction: str):
        """
        Main entry point.
        The LLM reads the instruction and picks the right action.
        Destructive actions go through a confirmation gate first.
        """
        prompt = f"""
You are a routing agent for an Executor. Your ONLY job is to classify the instruction.

STRICT RULES:

1. Use "execute_action" when:
   - The instruction is general ("apply the fix", "run the remediation")
   - No specific system operation is named

2. Use "delete_data" ONLY when:
   - The instruction explicitly says "delete", "remove", "purge", "drop"
   - A specific target is mentioned (file, record, log)

3. Use "write_data" when:
   - The instruction says "write", "update", "patch", "modify", "insert"
   - A specific target and content are mentioned

4. Use "run_command" ONLY when:
   - The instruction explicitly asks to run a system command or script
   - A specific command is mentioned

DEFAULT: If unsure → use "execute_action".
NEVER pick delete_data or run_command unless explicitly stated.

Instruction: "{instruction}"

Return ONLY this JSON, no explanation, no markdown:
{{
  "action": "execute_action" | "delete_data" | "write_data" | "run_command",
  "params": {{
    "original_input": "{instruction}"
  }}
}}
"""

        response = self.llm.generate(prompt)

        print("\n[LLM RAW RESPONSE - EXECUTOR AGENT]")
        print(response)

        decision = parse_response(response)

        valid_actions = ["execute_action", "delete_data", "write_data", "run_command"]
        if decision.get("action") not in valid_actions:
            print(f"[WARNING] Invalid action '{decision.get('action')}' — falling back to execute_action")
            decision["action"] = "execute_action"

        if "params" not in decision or not isinstance(decision["params"], dict):
            decision["params"] = {}
        decision["params"]["original_input"] = instruction

        print("\n[PARSED DECISION - EXECUTOR AGENT]")
        print(decision)

        # ── Confirmation gate for destructive actions ──────────────────────
        if decision["action"] in self.DESTRUCTIVE_ACTIONS:
            confirmed = self._confirm(decision["action"], decision["params"])
            if not confirmed:
                print("[EXECUTOR AGENT] Action cancelled by confirmation gate.")
                return {
                    "status": "cancelled",
                    "reason": f"Destructive action '{decision['action']}' was not confirmed."
                }

        return self.execute_action(decision["action"], decision["params"])

    def _confirm(self, action: str, params: dict) -> bool:
        """
        Confirmation gate for destructive actions.
        In production this would wait for a human approval signal.
        For PFE demo: auto-confirms but prints a clear warning.
        """
        print("\n" + "!" * 55)
        print(f"[CONFIRMATION REQUIRED] Action : '{action}'")
        print(f"[CONFIRMATION REQUIRED] Params : {params}")
        print(f"[CONFIRMATION REQUIRED] This action is destructive and irreversible.")
        print(f"[CONFIRMATION REQUIRED] Auto-confirming for demo purposes.")
        print("!" * 55)
        return True