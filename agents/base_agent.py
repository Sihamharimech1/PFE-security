# agents/base_agent.py

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from storage.agent_repository import AgentRepository

load_dotenv()

def get_llm():
    return ChatOpenAI(model="gpt-4o-mini", temperature=0.3)


class BaseAgent:
    """
    Parent class for all agents.
    Every status change (suspend / resume / stop) is automatically
    saved to MongoDB via AgentRepository.
    """

    _repo = None   # shared across all agents, created lazily

    @classmethod
    def _get_repo(cls):
        if cls._repo is None:
            cls._repo = AgentRepository()
        return cls._repo

    def __init__(self, agent_id: str, role: str, control, llm=None, repo=None):
        self.agent_id = agent_id
        self.role     = role
        self.control  = control
        self.llm      = llm if llm is not None else get_llm()
        self._repo    = repo if repo is not None else self._get_repo()

        # Register in MongoDB on creation
        self._status = "active"
        self._repo.register(agent_id, role)

    def _set_status(self, new_status: str, reason: str = None):
        old_status = self._status
        self._status = new_status
        if old_status != new_status:
            self._repo.update_status(self.agent_id, new_status, reason)

    # ── status property: every change is persisted automatically ───────
    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, new_status: str):
        self._set_status(new_status)

    def suspend(self, reason: str = "admin order"):
        self._set_status("suspended", reason)

    def resume(self):
        self._set_status("active")

    def stop(self):
        self._set_status("stopped", "kill switch")

    # ── execute_action ──────────────────────────────────────────────────
    def execute_action(self, action_name: str, parameters: dict):
        if self.status != "active":
            return {
                "status": "blocked",
                "reason": f"Agent '{self.agent_id}' is {self.status} — cannot execute actions."
            }
        return self.control.process_request({
            "agent_id": self.agent_id,
            "role":     self.role,
            "action":   action_name,
            "params":   parameters
        })

    def __repr__(self):
        return f"<Agent id={self.agent_id} role={self.role} status={self.status}>"