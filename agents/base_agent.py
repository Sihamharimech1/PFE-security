# agents/base_agent.py

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

load_dotenv()

def get_llm():
    return ChatOpenAI(model="gpt-4o-mini", temperature=0.3)


class BaseAgent:
    def __init__(self, agent_id: str, role: str, control):
        self.agent_id = agent_id
        self.role     = role
        self.status   = "active"
        self.control  = control
        self.llm      = get_llm()

    def execute_action(self, action_name: str, parameters: dict):
        if self.status != "active":
            return {
                "status": "blocked",
                "reason": f"Agent is {self.status}, cannot execute actions."
            }
        return self.control.process_request({
            "agent_id": self.agent_id,
            "role":     self.role,
            "action":   action_name,
            "params":   parameters
        })

    def __repr__(self):
        return f"<Agent id={self.agent_id} role={self.role} status={self.status}>"