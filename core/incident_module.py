# core/incident_module.py

import time
from core.models import IncidentResponse


class IncidentModule:
    """
    Apply graduated responses to detection events.

    Responses are intentionally deterministic for the prototype:
    - ALERT: place a known agent under WATCH
    - LIMIT: escalate to DEGRADED, then RESTRICTED on repeated anomalies
    - SUSPEND: suspend the offending agent when it is registered
    - KILL_SWITCH: stop all registered agents
    """

    LEVEL_ORDER = ("NORMAL", "WATCH", "DEGRADED", "RESTRICTED", "SUSPENDED")

    def __init__(
        self,
        throttle_seconds: float = 2.0,
        clock=None,
        incident_repository=None,
        agent_repository=None,
        recovery_seconds: float = 300.0,
    ):
        self.throttle_seconds = throttle_seconds
        self.clock = clock or time.time
        self.repository = incident_repository
        self.agent_repository = agent_repository
        self.recovery_seconds = recovery_seconds
        self._agents = {}
        self._limitation_states = {}

    def register_agent(self, agent):
        self._agents[agent.agent_id] = agent

    def register_agents(self, agents):
        for agent in agents:
            self.register_agent(agent)

    def set_agent_repository(self, repository):
        self.agent_repository = repository

    @staticmethod
    def _default_limitation():
        return {
            "level": "NORMAL",
            "reason": None,
            "next_allowed_at": None,
            "recover_at": None,
            "history": [],
        }

    def get_limitation(self, agent_id: str) -> dict:
        if self.agent_repository is not None and hasattr(
            self.agent_repository,
            "get_limitation",
        ):
            return self.agent_repository.get_limitation(agent_id)
        return dict(
            self._limitation_states.get(agent_id, self._default_limitation())
        )

    def _set_limitation(
        self,
        agent_id,
        level,
        reason,
        next_allowed_at=None,
        recover_at=None,
    ):
        state = {
            "level": level,
            "reason": reason,
            "next_allowed_at": next_allowed_at,
            "recover_at": recover_at,
        }
        self._limitation_states[agent_id] = state
        if self.agent_repository is not None and hasattr(
            self.agent_repository,
            "update_limitation",
        ):
            self.agent_repository.update_limitation(
                agent_id,
                level,
                reason,
                next_allowed_at=next_allowed_at,
                recover_at=recover_at,
            )
        return state

    def _set_next_allowed_at(self, agent_id, next_allowed_at):
        state = self.get_limitation(agent_id)
        state["next_allowed_at"] = next_allowed_at
        self._limitation_states[agent_id] = state
        if self.agent_repository is not None and hasattr(
            self.agent_repository,
            "update_next_allowed_at",
        ):
            self.agent_repository.update_next_allowed_at(agent_id, next_allowed_at)

    def _recover_if_due(self, agent_id, limitation):
        level = limitation.get("level", "NORMAL")
        recover_at = limitation.get("recover_at")
        now = self.clock()
        if (
            level not in {"WATCH", "DEGRADED", "RESTRICTED"}
            or not isinstance(recover_at, (int, float))
            or recover_at > now
        ):
            return limitation

        next_level = {
            "RESTRICTED": "DEGRADED",
            "DEGRADED": "WATCH",
            "WATCH": "NORMAL",
        }[level]
        next_recovery = (
            now + self.recovery_seconds if next_level != "NORMAL" else None
        )
        next_allowed_at = (
            now + self.throttle_seconds if next_level == "DEGRADED" else None
        )
        return self._set_limitation(
            agent_id,
            next_level,
            "Automatic recovery after quiet period",
            next_allowed_at=next_allowed_at,
            recover_at=next_recovery,
        )

    def check_request(self, agent_id: str, action_sensitivity: str) -> dict:
        limitation = self._recover_if_due(
            agent_id,
            self.get_limitation(agent_id),
        )
        level = limitation.get("level", "NORMAL")

        if level == "SUSPENDED":
            return {
                "allowed": False,
                "reason": "LIMITATION_SUSPENDED",
                "level": level,
            }

        if level == "RESTRICTED" and action_sensitivity != "low":
            return {
                "allowed": False,
                "reason": "RESTRICTED_ACTION",
                "level": level,
            }

        if level == "DEGRADED":
            now = self.clock()
            next_allowed_at = limitation.get("next_allowed_at")
            if isinstance(next_allowed_at, (int, float)) and next_allowed_at > now:
                return {
                    "allowed": False,
                    "reason": "THROTTLED",
                    "level": level,
                    "retry_after_seconds": round(next_allowed_at - now, 3),
                }
            self._set_next_allowed_at(agent_id, now + self.throttle_seconds)

        return {"allowed": True, "level": level}

    def _with_lifecycle(self, event: dict, response: dict) -> dict:
        if self.repository is None:
            return response

        try:
            incident_id = self.repository.create_incident(event, response)
            return {
                **response,
                "incident_id": incident_id,
                "lifecycle_status": "OPEN",
            }
        except Exception as exc:
            return {
                **response,
                "incident_persistence_error": f"{type(exc).__name__}: {exc}",
            }

    @staticmethod
    def _response(**kwargs):
        return IncidentResponse(**kwargs).to_dict()

    def handle(self, event: dict) -> dict:
        if not isinstance(event, dict) or event.get("status") != "ANOMALY":
            return self._response(
                status="NO_ACTION",
                action="NONE",
                applied=False,
                agent_id=event.get("agent_id") if isinstance(event, dict) else None,
            )

        agent_id = event.get("agent_id")
        recommended_action = event.get("recommended_action", "ALERT")
        severity = event.get("severity")

        if recommended_action == "LIMIT":
            previous_level = self.get_limitation(agent_id).get("level", "NORMAL")
            level = (
                "RESTRICTED"
                if previous_level in {"DEGRADED", "RESTRICTED"}
                else "DEGRADED"
            )
            next_allowed_at = (
                self.clock() + self.throttle_seconds if level == "DEGRADED" else None
            )
            recover_at = self.clock() + self.recovery_seconds
            self._set_limitation(
                agent_id,
                level,
                f"Automatic response: {event.get('rule_id')}",
                next_allowed_at=next_allowed_at,
                recover_at=recover_at,
            )
            print(
                f"[INCIDENT] LIMIT escalated {agent_id} "
                f"from {previous_level} to {level}"
            )
            return self._with_lifecycle(event, self._response(
                status=level,
                action="LIMIT",
                applied=True,
                agent_id=agent_id,
                severity=severity,
                duration_seconds=self.throttle_seconds,
                limitation_level=level,
                previous_limitation_level=previous_level,
            ))

        if recommended_action == "SUSPEND":
            previous_level = self.get_limitation(agent_id).get("level", "NORMAL")
            self._set_limitation(
                agent_id,
                "SUSPENDED",
                f"Automatic response: {event.get('rule_id')}",
                recover_at=None,
            )
            agent = self._agents.get(agent_id)
            if agent is not None:
                agent.suspend(f"Automatic incident response: {event.get('rule_id')}")
                print(f"[INCIDENT] SUSPEND applied to {agent_id}")
                return self._with_lifecycle(event, self._response(
                    status="SUSPENDED",
                    action="SUSPEND",
                    applied=True,
                    agent_id=agent_id,
                    severity=severity,
                    limitation_level="SUSPENDED",
                    previous_limitation_level=previous_level,
                ))

            print(f"[INCIDENT] SUSPEND requested for {agent_id}, but agent is not registered")
            return self._with_lifecycle(event, self._response(
                status="SUSPEND_REQUESTED",
                action="SUSPEND",
                applied=False,
                agent_id=agent_id,
                severity=severity,
                limitation_level="SUSPENDED",
                previous_limitation_level=previous_level,
            ))

        if recommended_action == "KILL_SWITCH":
            for agent in self._agents.values():
                agent.stop()
            print("[INCIDENT] KILL_SWITCH applied to all registered agents")
            return self._with_lifecycle(event, self._response(
                status="KILL_SWITCH_APPLIED",
                action="KILL_SWITCH",
                applied=True,
                agent_id=agent_id,
                severity=severity,
            ))

        current_limitation = self.get_limitation(agent_id)
        previous_level = current_limitation.get("level", "NORMAL")
        level = "WATCH" if previous_level == "NORMAL" else previous_level
        if agent_id in self._agents or self.agent_repository is not None:
            self._set_limitation(
                agent_id,
                level,
                f"Enhanced monitoring: {event.get('rule_id')}",
                next_allowed_at=(
                    current_limitation.get("next_allowed_at")
                    if level == "DEGRADED"
                    else None
                ),
                recover_at=self.clock() + self.recovery_seconds,
            )
        print(f"[INCIDENT] ALERT recorded for {agent_id}")
        return self._with_lifecycle(event, self._response(
            status="ALERTED",
            action="ALERT",
            applied=True,
            agent_id=agent_id,
            severity=severity,
            limitation_level=level,
            previous_limitation_level=previous_level,
        ))
