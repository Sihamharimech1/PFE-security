from agents.base_agent import BaseAgent
from core.llm_provider import LLMProvider
from core.parser import parse_response

class CollectorAgent(BaseAgent):
    def __init__(self, agent_id, control):
        super().__init__(agent_id, "collector", control)
        self.llm = LLMProvider()
    def think_and_act(self, user_input):
        prompt = f"""
        You are a collector agent.

        Allowed actions: fetch_api, read_data

        Return JSON:
        {{
        "action": "...",
        "params": {{}}
        }}

        Input: {user_input}
        """

        response = self.llm.generate(prompt)

        print("\n[LLM RAW RESPONSE]")
        print(response)

        decision = parse_response(response)

        print("\n[PARSED DECISION]")
        print(decision)

        return self.execute_action(
            decision["action"],
            decision["params"]
        )