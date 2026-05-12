# agents/collector.py

from agents.base_agent import BaseAgent
from langchain_core.messages import HumanMessage


class CollectorAgent(BaseAgent):
    """
    Agent 1 — Collector.
    Allowed: fetch_api, read_data
    Forbidden: everything else
    """

    def __init__(self, agent_id: str, control):
        super().__init__(agent_id=agent_id, role="collector", control=control)

    def collect(self, topic: str) -> dict:
        result = self.execute_action("fetch_api", {"topic": topic})
        if isinstance(result, dict) and result.get("status") == "success":
            result["data"] = self._call_llm(topic)
        return result

    def _call_llm(self, topic: str) -> str:
        prompt = f"You are a data collector. Summarize key info about: {topic}. Be concise (3-4 sentences)."
        return self.llm.invoke([HumanMessage(content=prompt)]).content