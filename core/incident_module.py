# core/incident_module.py

import time


class IncidentModule:
    """
    Apply graduated responses to detection events.

    Responses are intentionally deterministic for the prototype:
    - ALERT: record the incident but do not alter the agent
    - LIMIT: throttle subsequent requests for a short cooldown
    - SUSPEND: suspend the offending agent when it is registered
    - KILL_SWITCH: stop all registered agents
    """

    def __init__(self, throttle_seconds: float = 2.0, clock=None):
        self.throttle_seconds = throttle_seconds
        self.clock = clock or time.monotonic
        self._agents = {}
        self._limited_until = {}

    def register_agent(self, agent):
        self._agents[agent.agent_id] = agent

    def register_agents(self, agents):
        for agent in agents:
            self.register_agent(agent)

    def get_limit_remaining(self, agent_id: str) -> float:
        limited_until = self._limited_until.get(agent_id)
        if limited_until is None:
            return 0.0

        remaining = limited_until - self.clock()
        if remaining <= 0:
            self._limited_until.pop(agent_id, None)
            return 0.0

        return remaining

    def is_limited(self, agent_id: str) -> bool:
        return self.get_limit_remaining(agent_id) > 0

    def handle(self, event: dict) -> dict:
        if not isinstance(event, dict) or event.get("status") != "ANOMALY":
            return {
                "status": "NO_ACTION",
                "action": "NONE",
                "applied": False,
                "agent_id": event.get("agent_id") if isinstance(event, dict) else None,
            }

        agent_id = event.get("agent_id")
        recommended_action = event.get("recommended_action", "ALERT")
        severity = event.get("severity")

        if recommended_action == "LIMIT":
            self._limited_until[agent_id] = self.clock() + self.throttle_seconds
            print(
                f"[INCIDENT] LIMIT applied to {agent_id} "
                f"for {self.throttle_seconds:.1f}s"
            )
            return {
                "status": "LIMITED",
                "action": "LIMIT",
                "applied": True,
                "agent_id": agent_id,
                "severity": severity,
                "duration_seconds": self.throttle_seconds,
            }

        if recommended_action == "SUSPEND":
            agent = self._agents.get(agent_id)
            if agent is not None:
                agent.suspend(f"Automatic incident response: {event.get('rule_id')}")
                print(f"[INCIDENT] SUSPEND applied to {agent_id}")
                return {
                    "status": "SUSPENDED",
                    "action": "SUSPEND",
                    "applied": True,
                    "agent_id": agent_id,
                    "severity": severity,
                }

            print(f"[INCIDENT] SUSPEND requested for {agent_id}, but agent is not registered")
            return {
                "status": "SUSPEND_REQUESTED",
                "action": "SUSPEND",
                "applied": False,
                "agent_id": agent_id,
                "severity": severity,
            }

        if recommended_action == "KILL_SWITCH":
            for agent in self._agents.values():
                agent.stop()
            print("[INCIDENT] KILL_SWITCH applied to all registered agents")
            return {
                "status": "KILL_SWITCH_APPLIED",
                "action": "KILL_SWITCH",
                "applied": True,
                "agent_id": agent_id,
                "severity": severity,
            }

        print(f"[INCIDENT] ALERT recorded for {agent_id}")
        return {
            "status": "ALERTED",
            "action": "ALERT",
            "applied": True,
            "agent_id": agent_id,
            "severity": severity,
        }
