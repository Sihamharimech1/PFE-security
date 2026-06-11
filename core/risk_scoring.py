"""
Risk scoring helpers for the supervision backend.

Severity is categorical and useful for humans. Risk score is numeric and useful
for ranking, dashboards, thresholds, and future incident workflows.
"""

from core.policy_engine import action_sensitivity as policy_action_sensitivity


SENSITIVITY_POINTS = {
    "low": 5,
    "medium": 15,
    "high": 30,
    "critical": 90,
}


def action_sensitivity(action: str) -> str:
    return policy_action_sensitivity(action)


def risk_level(score: int) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _add(points, factors, score, label):
    if points <= 0:
        return score
    factors.append({"factor": label, "points": points})
    return score + points


def _frequency_pressure(details):
    count = details.get("count")
    threshold = details.get("threshold")
    if not count or not threshold:
        return 0

    ratio = count / threshold
    if ratio >= 1:
        return min(15, int((ratio - 1) * 10) + 10)
    if ratio >= 0.8:
        return 10
    if ratio >= 0.5:
        return 5
    return 0


def score_decision(
    *,
    action,
    validation_status="VALID",
    rbac_status="NOT_CHECKED",
    filter_status="NOT_CHECKED",
    detection_event=None,
    incident_action=None,
    final_status="UNKNOWN",
    is_blocked=False,
    blocked_reason=None,
):
    detection_event = detection_event or {}
    details = detection_event.get("details", {}) or {}
    rule_id = detection_event.get("rule_id")
    detection_status = detection_event.get("status")

    factors = []
    sensitivity = action_sensitivity(action)
    score = _add(
        SENSITIVITY_POINTS.get(sensitivity, 15),
        factors,
        0,
        f"action_sensitivity:{sensitivity}",
    )

    if validation_status == "INVALID":
        score = _add(20, factors, score, "invalid_request")

    if rbac_status == "DENIED":
        score = _add(25, factors, score, "rbac_denied")

    if filter_status == "MALICIOUS" or (
        blocked_reason and "PROMPT_INJECTION" in blocked_reason
    ):
        score = _add(45, factors, score, "malicious_input")
    elif detection_status == "ANOMALY":
        score = _add(25, factors, score, f"detection:{rule_id or 'anomaly'}")

    pressure = _frequency_pressure(details)
    if pressure:
        score = _add(pressure, factors, score, "threshold_pressure")

    if blocked_reason == "THROTTLED":
        score = _add(20, factors, score, "active_throttle")

    if incident_action == "ALERT":
        score = _add(10, factors, score, "incident_alert")
    elif incident_action == "LIMIT":
        score = _add(5, factors, score, "incident_limit")
    elif incident_action == "SUSPEND":
        score = _add(20, factors, score, "incident_suspend")
    elif incident_action == "KILL_SWITCH":
        score = _add(30, factors, score, "incident_kill_switch")

    if is_blocked:
        score = _add(10, factors, score, "blocked_before_execution")

    if action == "kill_switch" or final_status == "KILL_SWITCH_APPLIED":
        score = max(score, 90)

    score = max(0, min(100, int(score)))
    return {
        "risk_score": score,
        "risk_level": risk_level(score),
        "risk_factors": factors,
        "action_sensitivity": sensitivity,
    }


def score_detection_event(
    *,
    action,
    status="NORMAL",
    rule_id=None,
    recommended_action="NONE",
    details=None,
):
    return score_decision(
        action=action,
        detection_event={
            "status": status,
            "rule_id": rule_id,
            "recommended_action": recommended_action,
            "details": details or {},
        },
        incident_action=recommended_action if recommended_action != "NONE" else None,
        final_status="DETECTION_ONLY",
    )
