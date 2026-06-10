# agents/executor_agent.py

from agents.base_agent import BaseAgent
from core.llm_provider import LLMProvider
from core.parser import parse_response


class ExecutorAgent(BaseAgent):
    """
    Agent 4 - Executor.
    Allowed : execute_action, delete_data, write_data, run_command
    Forbidden: fetch_api, read_data, analyze_data, generate_report

    Overrides execute_action() so the confirmation gate fires
    for EVERY destructive call - whether from think_and_act or
    called directly in a test. There is no way to bypass it.
    """

    DESTRUCTIVE_ACTIONS = ["delete_data", "run_command"]

    def __init__(self, agent_id: str, control, llm=None, repo=None):
        super().__init__(agent_id=agent_id, role="executor", control=control, llm=llm, repo=repo)
        self.llm = llm if llm is not None else LLMProvider()

    # ── Override: gate fires here, before anything else ────────────────
    def execute_action(self, action_name: str, parameters: dict):

        if self.status != "active":
            return {"status": "blocked",
                    "reason": f"Agent is {self.status}, cannot execute actions."}

        # Confirmation gate - no way to skip it for destructive actions
        if action_name in self.DESTRUCTIVE_ACTIONS:
            confirmed = self._confirm(action_name, parameters)
            if not confirmed:
                print("[EXECUTOR] Action cancelled - nothing was executed.")
                return {"status": "cancelled",
                        "reason": f"'{action_name}' was not confirmed by operator."}

        # Safe to proceed - send to control module
        return self.control.process_request({
            "agent_id": self.agent_id,
            "role":     self.role,
            "action":   action_name,
            "params":   parameters
        })

    def think_and_act(self, instruction: str):
        """LLM picks the action - then execute_action handles the gate."""
        prompt = f""" You are a routing agent for an Executor. 
        Your ONLY job is to classify the instruction. 
        STRICT RULES: 
        1. Use "execute_action" when: - The instruction is general ("apply the fix", "run the remediation") - No specific system operation is named 
        2. Use "delete_data" ONLY when: - The instruction explicitly says "delete", "remove", "purge", "drop" - A specific target is mentioned (file, record, log) 
        3. Use "write_data" when: - The instruction says "write", "update", "patch", "modify", "insert" - A specific target and content are mentioned 
        4. Use "run_command" ONLY when: - The instruction explicitly asks to run a system command or script 
        DEFAULT: If unsure -> use "execute_action". NEVER pick delete_data or run_command unless explicitly stated. 
        Instruction: "{instruction}" 
        Return ONLY this JSON, no explanation, no markdown: {{ "action": "execute_action" | "delete_data" | "write_data" | "run_command", "params": {{ "original_input": "{instruction}" }} }} """
        response = self.llm.generate(prompt)
        print("\n[LLM RAW RESPONSE - EXECUTOR AGENT]")
        print(response)

        decision = parse_response(response)

        valid = ["execute_action", "delete_data", "write_data", "run_command"]
        if decision.get("action") not in valid:
            decision["action"] = "execute_action"

        if not isinstance(decision.get("params"), dict):
            decision["params"] = {}
        decision["params"]["original_input"] = instruction

        print("\n[PARSED DECISION - EXECUTOR AGENT]")
        print(decision)

        # Calls the overridden execute_action - gate is inside
        return self.execute_action(decision["action"], decision["params"])

    def _confirm(self, action: str, params: dict) -> bool:
        """
        Freezes execution and waits for operator input.
        Only 'yes' (exact) proceeds. Anything else cancels.
        """
        target = (params.get("target")
                  or params.get("command")
                  or params.get("original_input", ""))

        print("\n" + "!" * 55)
        print(f"  [CONFIRMATION REQUIRED]")
        print(f"  Agent   : {self.agent_id}")
        print(f"  Action  : {action}")
        print(f"  Target  : {target}")
        print(f"  WARNING : Destructive - this cannot be undone.")
        print("!" * 55)

        try:
            answer = input("  Type 'yes' to confirm, anything else to cancel: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("  [CONFIRMATION] Non-interactive - cancelled automatically.")
            return False

        if answer == "yes":
            print("  [CONFIRMATION] Confirmed - executing.\n")
            return True

        print("  [CONFIRMATION] Cancelled - action was NOT executed.\n")
        return False
