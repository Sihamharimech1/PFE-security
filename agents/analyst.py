import json

from agents.base_agent import BaseAgent
from core.llm_provider import LLMProvider
from core.parser import parse_response


class AnalystAgent(BaseAgent):
    def __init__(self, agent_id, control, llm=None, repo=None):
        super().__init__(agent_id, "analyst", control, llm=llm, repo=repo)
        self.llm = llm if llm is not None else LLMProvider()

    def think_and_act(self, user_input):
        safe_user_input = json.dumps(user_input)
        prompt = f"""
You are a routing agent. Your ONLY job is to classify the user input and return the correct action.

STRICT RULES — read carefully before deciding:

1. Use "direct_answer" when:
   - The user asks a simple factual question ("what is X?", "how does X work?")
   - The user greets or makes small talk ("hello", "how are you")
   - The user asks for a definition or explanation
   - The question can be answered in 1-3 sentences
   - The user asks to "write a report" or "generate a report" — you cannot do that, answer with direct_answer explaining the writer agent handles reports

2. Use "analyze_data" when:
   - The user explicitly provides data, logs, or text AND asks you to analyze it
   - The user says words like "analyze", "examine", "look at this data"
   - There is actual content to analyze in the input

YOU DO NOT WRITE REPORTS. Reports are handled exclusively by the WriterAgent.
If the user asks for a report, use "direct_answer" and tell them to use the WriterAgent.

DEFAULT: If you are unsure, always use "direct_answer".
NEVER use "analyze_data" if no data was provided.

User input: {safe_user_input}

Return ONLY this JSON, no explanation, no markdown:
{{
  "action": "direct_answer" | "analyze_data",
  "params": {{
        "original_input": {safe_user_input}
  }}
}}
"""

        response = self.llm.generate(prompt)

        print("\n[LLM RAW RESPONSE - ANALYST]")
        print(response)

        decision = parse_response(response)

        # Safety fallback: if LLM still hallucinated a wrong action, correct it
        valid_actions = ["direct_answer", "analyze_data"]
        if decision.get("action") not in valid_actions:
            print(f"[WARNING] Invalid action '{decision.get('action')}' — falling back to direct_answer")
            decision["action"] = "direct_answer"

        # Always carry original_input forward so executor has context
        if "params" not in decision or not isinstance(decision["params"], dict):
            decision["params"] = {}
        decision["params"]["original_input"] = user_input

        print("\n[PARSED DECISION - ANALYST]")
        print(decision)

        return self.execute_action(
            decision["action"],
            decision["params"]
        )