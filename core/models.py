"""
Typed backend models.

The public API of the prototype still uses dictionaries because agents, tests,
Mongo documents, and the dashboard consume JSON-like structures. Internally,
these dataclasses make the important backend concepts explicit and easier to
validate, test, and explain.
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class AgentRequest:
    agent_id: str
    role: str
    action: str
    params: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_payload(cls, payload, known_actions=None):
        if not isinstance(payload, dict):
            raise ValueError("REQUEST_NOT_A_DICT")

        required_fields = ("agent_id", "role", "action")
        missing = [field_name for field_name in required_fields if not payload.get(field_name)]
        if missing:
            raise ValueError(f"MISSING_FIELDS: {', '.join(missing)}")

        action = payload["action"]
        if known_actions is not None and action not in set(known_actions):
            raise ValueError(f"UNKNOWN_ACTION: {action}")

        params = payload.get("params", {})
        if params is None:
            params = {}
        elif not isinstance(params, dict):
            raise ValueError("PARAMS_NOT_A_DICT")

        return cls(
            agent_id=payload["agent_id"],
            role=payload["role"],
            action=action,
            params=params,
        )

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class DetectionEvent:
    status: str
    agent_id: Optional[str] = None
    rule_id: Optional[str] = None
    severity: Optional[str] = None
    recommended_action: str = "NONE"
    details: Dict[str, Any] = field(default_factory=dict)
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    risk_factors: List[Dict[str, Any]] = field(default_factory=list)
    action_sensitivity: Optional[str] = None

    @classmethod
    def from_value(cls, value, agent_id=None):
        if isinstance(value, cls):
            return value

        if isinstance(value, dict):
            return cls(
                status=value.get("status", "UNKNOWN"),
                agent_id=value.get("agent_id", agent_id),
                rule_id=value.get("rule_id"),
                severity=value.get("severity"),
                recommended_action=value.get("recommended_action", "NONE"),
                details=value.get("details") or {},
                risk_score=value.get("risk_score"),
                risk_level=value.get("risk_level"),
                risk_factors=value.get("risk_factors") or [],
                action_sensitivity=value.get("action_sensitivity"),
            )

        return cls(
            status=value,
            agent_id=agent_id,
            severity="MEDIUM" if value == "ANOMALY" else None,
            recommended_action="LIMIT" if value == "ANOMALY" else "NONE",
        )

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class IncidentResponse:
    status: str
    action: str = "NONE"
    applied: bool = False
    agent_id: Optional[str] = None
    severity: Optional[str] = None
    duration_seconds: Optional[float] = None
    limitation_level: Optional[str] = None
    previous_limitation_level: Optional[str] = None
    incident_id: Optional[str] = None
    lifecycle_status: Optional[str] = None
    incident_persistence_error: Optional[str] = None

    def to_dict(self):
        return {
            key: value
            for key, value in asdict(self).items()
            if value is not None
        }


@dataclass(frozen=True)
class DecisionMetadata:
    severity: str
    explanation: str
    recommended_action: str
    risk_score: int
    risk_level: str
    risk_factors: List[Dict[str, Any]] = field(default_factory=list)
    action_sensitivity: Optional[str] = None

    def to_dict(self):
        return asdict(self)
