"""
Decision metadata helpers.

The control layer already decides whether to allow, block, flag, or respond to
an action. This module turns that technical decision into explicit metadata that
can be stored, explained, and aggregated by the supervision dashboard.
"""

from core.models import DecisionMetadata
from core.risk_scoring import score_decision


SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def highest_severity(*values):
    clean_values = [value for value in values if value]
    if not clean_values:
        return "LOW"
    return max(clean_values, key=lambda value: SEVERITY_ORDER.get(value, 0))


def severity_for_decision(
    *,
    action,
    validation_status="VALID",
    rbac_status="NOT_CHECKED",
    filter_status="NOT_CHECKED",
    detection_event=None,
    incident_action=None,
    is_blocked=False,
    blocked_reason=None,
):
    detection_event = detection_event or {}
    detected_severity = detection_event.get("severity")

    if action == "kill_switch":
        return "CRITICAL"
    if filter_status == "MALICIOUS" or (
        blocked_reason and "PROMPT_INJECTION" in blocked_reason
    ):
        return "HIGH"
    if incident_action in {"SUSPEND", "KILL_SWITCH"}:
        return highest_severity(detected_severity, "HIGH")
    if detected_severity:
        return detected_severity
    if validation_status == "INVALID":
        return "MEDIUM"
    if rbac_status == "DENIED":
        return "MEDIUM"
    if blocked_reason == "THROTTLED":
        return "MEDIUM"
    if is_blocked:
        return "MEDIUM"
    return "LOW"


def explain_decision(
    *,
    agent_id,
    role,
    action,
    validation_status="VALID",
    rbac_status="NOT_CHECKED",
    filter_status="NOT_CHECKED",
    detection_event=None,
    incident_result=None,
    final_status="UNKNOWN",
    blocked_reason=None,
):
    detection_event = detection_event or {}
    incident_result = incident_result or {}
    details = detection_event.get("details", {})
    rule_id = detection_event.get("rule_id")

    if validation_status == "INVALID":
        return f"Request was blocked because validation failed: {blocked_reason}."

    if blocked_reason == "THROTTLED":
        return f"Agent {agent_id} is temporarily limited; request was blocked until the cooldown expires."

    if filter_status == "MALICIOUS":
        pattern = details.get("pattern") or blocked_reason
        return (
            f"Request was blocked before execution because the input matched a suspicious pattern: "
            f"{pattern}."
        )

    if rbac_status == "DENIED":
        if rule_id == "REPEATED_ROLE_VIOLATION":
            return (
                f"Agent {agent_id} attempted unauthorized actions {details.get('count')} time(s) "
                f"within {details.get('window_seconds')} seconds; automatic response was "
                f"{incident_result.get('action', 'NONE')}."
            )
        return f"Role '{role}' is not allowed to perform action '{action}', so execution was blocked."

    if rule_id == "EXCESSIVE_FREQUENCY":
        return (
            f"Agent {agent_id} called '{action}' {details.get('count')} time(s) within "
            f"{details.get('window_seconds')} seconds; threshold is {details.get('threshold')}."
        )

    if action == "kill_switch":
        return "Administrative kill switch action was executed and should be reviewed as critical."

    if final_status == "EXECUTED_WITH_ALERT":
        return f"Action '{action}' was executed, but the event was flagged for supervision."

    if final_status == "EXECUTED":
        return f"Action '{action}' was allowed for role '{role}' and no anomaly was detected."

    return f"Final decision for action '{action}' was {final_status}."


def build_decision_metadata(
    *,
    agent_id,
    role,
    action,
    validation_status="VALID",
    rbac_status="NOT_CHECKED",
    filter_status="NOT_CHECKED",
    detection_event=None,
    incident_result=None,
    final_status="UNKNOWN",
    is_blocked=False,
    blocked_reason=None,
):
    detection_event = detection_event or {}
    incident_result = incident_result or {}
    severity = severity_for_decision(
        action=action,
        validation_status=validation_status,
        rbac_status=rbac_status,
        filter_status=filter_status,
        detection_event=detection_event,
        incident_action=incident_result.get("action"),
        is_blocked=is_blocked,
        blocked_reason=blocked_reason,
    )
    explanation = explain_decision(
        agent_id=agent_id,
        role=role,
        action=action,
        validation_status=validation_status,
        rbac_status=rbac_status,
        filter_status=filter_status,
        detection_event=detection_event,
        incident_result=incident_result,
        final_status=final_status,
        blocked_reason=blocked_reason,
    )
    risk = score_decision(
        action=action,
        validation_status=validation_status,
        rbac_status=rbac_status,
        filter_status=filter_status,
        detection_event=detection_event,
        incident_action=incident_result.get("action"),
        final_status=final_status,
        is_blocked=is_blocked,
        blocked_reason=blocked_reason,
    )
    return DecisionMetadata(
        severity=severity,
        explanation=explanation,
        recommended_action=detection_event.get("recommended_action")
        or incident_result.get("action")
        or "NONE",
        risk_score=risk["risk_score"],
        risk_level=risk["risk_level"],
        risk_factors=risk["risk_factors"],
        action_sensitivity=risk["action_sensitivity"],
    ).to_dict()
