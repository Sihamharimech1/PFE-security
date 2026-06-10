"""
Aggregate metrics for the supervision dashboard and final report.
"""

from collections import Counter, defaultdict


SEVERITY_POINTS = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 4,
    "CRITICAL": 8,
}


def _nested(document, *keys, default=None):
    value = document
    for key in keys:
        if not isinstance(value, dict):
            return default
        value = value.get(key)
    return default if value is None else value


def _rate(part, total):
    return round((part / total) * 100, 2) if total else 0.0


def calculate_supervision_metrics(logs, agents):
    logs = logs or []
    agents = agents or []
    total_logs = len(logs)

    severity_counts = Counter(
        _nested(log, "security", "severity", default="LOW") for log in logs
    )
    action_counts = Counter(_nested(log, "request", "action", default="unknown") for log in logs)
    incident_counts = Counter(
        _nested(log, "security", "incident_action", default="NONE") or "NONE"
        for log in logs
    )
    detection_counts = Counter(
        _nested(log, "security", "detection_status", default="UNKNOWN") for log in logs
    )

    blocked_count = sum(1 for log in logs if _nested(log, "blocked", "is_blocked") is True)
    anomaly_count = detection_counts.get("ANOMALY", 0)

    risk_by_agent = defaultdict(int)
    events_by_agent = Counter()
    for log in logs:
        agent_id = _nested(log, "agent", "id", default="unknown")
        severity = _nested(log, "security", "severity", default="LOW")
        events_by_agent[agent_id] += 1
        risk_by_agent[agent_id] += SEVERITY_POINTS.get(severity, 1)
        if _nested(log, "blocked", "is_blocked") is True:
            risk_by_agent[agent_id] += 1
        if _nested(log, "security", "detection_status") == "ANOMALY":
            risk_by_agent[agent_id] += 2

    top_risky_agent = None
    if risk_by_agent:
        agent_id, score = max(risk_by_agent.items(), key=lambda item: item[1])
        top_risky_agent = {
            "agent_id": agent_id,
            "risk_score": score,
            "events": events_by_agent[agent_id],
        }

    return {
        "total_logs": total_logs,
        "total_agents": len(agents),
        "blocked_count": blocked_count,
        "anomaly_count": anomaly_count,
        "blocked_rate": _rate(blocked_count, total_logs),
        "anomaly_rate": _rate(anomaly_count, total_logs),
        "severity_counts": dict(severity_counts),
        "incident_counts": dict(incident_counts),
        "detection_counts": dict(detection_counts),
        "top_actions": [
            {"action": action, "count": count}
            for action, count in action_counts.most_common(8)
        ],
        "top_risky_agent": top_risky_agent,
        "latest_event_at": _nested(logs[0], "timestamp") if logs else None,
    }
