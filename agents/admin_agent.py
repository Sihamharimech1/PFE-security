# agents/admin_agent.py

from agents.base_agent import BaseAgent
from core.llm_provider import LLMProvider
from core.parser import parse_response


class AdminAgent(BaseAgent):
    """
    Agent 5 - Admin.
    Role : admin

    The only agent that can:
      - suspend / resume other agents
      - trigger the kill switch (stops ALL agents)
      - modify system config
      - view all logs

    Has access to every action every other agent has.

    Why it's dangerous:
      If this agent is compromised, the entire system is compromised.
      That's why its anomaly threshold is lower (3 instead of 5)
      and every action it takes is logged with HIGH priority.

    Allowed  : everything
    Exclusive: suspend_agent, resume_agent, kill_switch,
               modify_config, view_logs
    """

    def __init__(self, agent_id: str, control, llm=None, repo=None):
        super().__init__(agent_id=agent_id, role="admin", control=control, llm=llm, repo=repo)
        self.llm            = llm if llm is not None else LLMProvider()
        self.managed_agents = {}   # registry: agent_id -> agent object

    def register_agents(self, agents: list):
        """
        Register all other agents so Admin can manage them.
        Call this after creating all agents in main/test.
        """
        for agent in agents:
            self.managed_agents[agent.agent_id] = agent
        print(f"[AdminAgent] Registered agents: {list(self.managed_agents.keys())}")

    # ── Core admin operations ──────────────────────────────────────────

    def suspend_agent(self, target_agent_id: str, reason: str = "admin order") -> dict:
        """
        Suspend an agent - it can no longer execute actions.
        Passes through control module for logging.
        """
        result = self.execute_action("suspend_agent", {
            "target_agent_id": target_agent_id,
            "reason": reason
        })

        # Apply the suspension directly on the agent object
        if target_agent_id in self.managed_agents:
            self.managed_agents[target_agent_id].suspend(reason)
            print(f"[AdminAgent] Agent '{target_agent_id}' is now SUSPENDED. Reason: {reason}")
        else:
            print(f"[AdminAgent] WARNING - '{target_agent_id}' not found in registry.")

        return result

    def resume_agent(self, target_agent_id: str) -> dict:
        """
        Resume a previously suspended agent.
        """
        result = self.execute_action("resume_agent", {
            "target_agent_id": target_agent_id
        })

        if target_agent_id in self.managed_agents:
            self.managed_agents[target_agent_id].resume()
            print(f"[AdminAgent] Agent '{target_agent_id}' is now ACTIVE again.")
        else:
            print(f"[AdminAgent] WARNING - '{target_agent_id}' not found in registry.")

        return result

    def kill_switch(self) -> dict:
        """
        Emergency stop - suspends ALL agents immediately.
        Used when a systemic threat is detected.
        """
        print("\n" + "[STOP] " * 20)
        print("  [KILL SWITCH ACTIVATED]")
        print("  ALL agents are being stopped.")
        print("[STOP] " * 20)

        result = self.execute_action("kill_switch", {
            "reason": "Emergency kill switch triggered by AdminAgent"
        })

        for agent_id, agent in self.managed_agents.items():
            agent.stop()
            print(f"  [KILL SWITCH] '{agent_id}' -> stopped")

        print("[AdminAgent] All agents stopped.")
        return result

    def modify_config(self, config_key: str, config_value) -> dict:
        """
        Modify a system configuration value.
        Example: change the anomaly detection threshold.
        """
        return self.execute_action("modify_config", {
            "key":   config_key,
            "value": config_value
        })

    def view_logs(self) -> dict:
        """
        Request a summary of all system logs.
        """
        return self.execute_action("view_logs", {})

    def think_and_act(self, instruction: str) -> dict:
        """
        LLM decides which admin action to take based on the instruction.
        """
        agent_ids = list(self.managed_agents.keys())

        prompt = f"""
You are a routing agent for a system Administrator. Classify the instruction.

Available actions:
- "suspend_agent"  -> instruction says suspend / block / disable a specific agent
- "resume_agent"   -> instruction says resume / reactivate / unblock a specific agent
- "kill_switch"    -> instruction says stop all / emergency / shutdown everything
- "modify_config"  -> instruction says change / update a config setting
- "view_logs"      -> instruction says show / view / read logs
- "analyze_data"   -> instruction asks to analyze something
- "fetch_api"      -> instruction asks to fetch external data

Known agents: {agent_ids}

DEFAULT: If unsure -> "view_logs"

Instruction: "{instruction}"

Return ONLY this JSON:
{{
  "action": "...",
  "params": {{
    "original_input": "{instruction}"
  }}
}}
"""
        response = self.llm.generate(prompt)

        print("\n[LLM RAW RESPONSE - ADMIN]")
        print(response)

        decision = parse_response(response)

        valid = ["suspend_agent", "resume_agent", "kill_switch",
                 "modify_config", "view_logs", "analyze_data",
                 "fetch_api", "delete_data", "write_data"]

        if decision.get("action") not in valid:
            print(f"[WARNING] Invalid action - falling back to view_logs")
            decision["action"] = "view_logs"

        if not isinstance(decision.get("params"), dict):
            decision["params"] = {}
        decision["params"]["original_input"] = instruction

        print("\n[PARSED DECISION - ADMIN]")
        print(decision)

        action = decision["action"]
        params = decision["params"]

        # Route to the right method
        if action == "suspend_agent":
            target = params.get("target_agent_id", "")
            return self.suspend_agent(target, reason=instruction)

        if action == "resume_agent":
            target = params.get("target_agent_id", "")
            return self.resume_agent(target)

        if action == "kill_switch":
            return self.kill_switch()

        if action == "modify_config":
            return self.modify_config(
                params.get("key", "unknown"),
                params.get("value", None)
            )

        # For everything else - go through normal execute_action
        return self.execute_action(action, params)
