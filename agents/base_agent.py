# agents/base_agent.py

class BaseAgent:
    def __init__(self, agent_id, role, control_module):
        self.agent_id = agent_id
        self.role = role
        self.control = control_module

    def execute_action(self, action, params):
        request = {
            "agent_id": self.agent_id,
            "role": self.role,
            "action": action,
            "params": params
        }

        return self.control.process_request(request)