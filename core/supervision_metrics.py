"""
Aggregate metrics for the supervision dashboard and final report.
"""

from collections import Counter, defaultdict
from datetime import datetime, timezone


SEVERITY_POINTS = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 4,
    "CRITICAL": 8,
}


RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def _nested(document, *keys, default=None):
    value = document
    for key in keys:
        if not isinstance(value, dict):
            return default
        value = value.get(key)
    return default if value is None else value


def _rate(part, total):
    return round((part / total) * 100, 2) if total else 0.0


def _fallback_risk_score(log):
    severity = _nested(log, "security", "severity", default="LOW")
    return SEVERITY_POINTS.get(severity, 1) * 10


def _parse_timestamp(value):
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def calculate_agent_activity(logs, agents, bucket_minutes=5, max_buckets=24):
    """Build compact server-side activity and risk series for each agent."""
    logs = logs or []
    agents = agents or []
    agent_ids = {
        agent.get("agent_id")
        for agent in agents
        if isinstance(agent, dict) and agent.get("agent_id")
    }
    agent_ids.update(
        _nested(log, "agent", "id")
        for log in logs
        if _nested(log, "agent", "id")
    )

    buckets_by_agent = defaultdict(dict)
    summaries = defaultdict(
        lambda: {
            "total_events": 0,
            "approved": 0,
            "blocked": 0,
            "anomalies": 0,
            "risk_total": 0.0,
            "risk_samples": 0,
            "max_risk": 0,
        }
    )

    for log in logs:
        agent_id = _nested(log, "agent", "id")
        timestamp = _parse_timestamp(log.get("timestamp"))
        if not agent_id or not timestamp:
            continue

        minute = timestamp.minute - (timestamp.minute % bucket_minutes)
        bucket_at = timestamp.replace(minute=minute, second=0, microsecond=0)
        bucket_key = bucket_at.isoformat()
        bucket = buckets_by_agent[agent_id].setdefault(
            bucket_key,
            {
                "time": bucket_key,
                "approved": 0,
                "blocked": 0,
                "anomalies": 0,
                "risk_total": 0.0,
                "risk_samples": 0,
                "max_risk": 0,
            },
        )
        summary = summaries[agent_id]
        blocked = _nested(log, "blocked", "is_blocked") is True
        anomaly = _nested(log, "security", "detection_status") == "ANOMALY"
        risk_score = _nested(
            log,
            "security",
            "risk_score",
            default=_fallback_risk_score(log),
        )
        risk_score = risk_score if isinstance(risk_score, (int, float)) else 0

        bucket["blocked" if blocked else "approved"] += 1
        bucket["anomalies"] += int(anomaly)
        bucket["risk_total"] += risk_score
        bucket["risk_samples"] += 1
        bucket["max_risk"] = max(bucket["max_risk"], risk_score)

        summary["total_events"] += 1
        summary["blocked" if blocked else "approved"] += 1
        summary["anomalies"] += int(anomaly)
        summary["risk_total"] += risk_score
        summary["risk_samples"] += 1
        summary["max_risk"] = max(summary["max_risk"], risk_score)

    result = {}
    for agent_id in sorted(agent_ids):
        series = []
        for bucket in sorted(buckets_by_agent[agent_id].values(), key=lambda item: item["time"]):
            samples = bucket.pop("risk_samples")
            risk_total = bucket.pop("risk_total")
            bucket["average_risk"] = round(risk_total / samples, 2) if samples else 0
            series.append(bucket)

        summary = summaries[agent_id]
        samples = summary.pop("risk_samples")
        risk_total = summary.pop("risk_total")
        summary["average_risk"] = round(risk_total / samples, 2) if samples else 0
        result[agent_id] = {
            "summary": dict(summary),
            "series": series[-max_buckets:],
        }

    return result


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
    risk_level_counts = Counter(
        _nested(log, "security", "risk_level", default="LOW") for log in logs
    )
    for level in RISK_LEVELS:
        risk_level_counts.setdefault(level, 0)

    risk_scores = [
        _nested(log, "security", "risk_score", default=_fallback_risk_score(log))
        for log in logs
    ]
    risk_scores = [score for score in risk_scores if isinstance(score, (int, float))]

    blocked_count = sum(1 for log in logs if _nested(log, "blocked", "is_blocked") is True)
    anomaly_count = detection_counts.get("ANOMALY", 0)

    risk_by_agent = defaultdict(int)
    events_by_agent = Counter()
    for log in logs:
        agent_id = _nested(log, "agent", "id", default="unknown")
        severity = _nested(log, "security", "severity", default="LOW")
        risk_score = _nested(log, "security", "risk_score", default=None)
        events_by_agent[agent_id] += 1
        if isinstance(risk_score, (int, float)):
            risk_by_agent[agent_id] += risk_score
        else:
            risk_by_agent[agent_id] += SEVERITY_POINTS.get(severity, 1) * 10
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
        "risk_level_counts": dict(risk_level_counts),
        "average_risk_score": round(sum(risk_scores) / len(risk_scores), 2)
        if risk_scores
        else 0.0,
        "max_risk_score": max(risk_scores) if risk_scores else 0,
        "high_risk_events": sum(1 for score in risk_scores if score >= 60),
        "incident_counts": dict(incident_counts),
        "detection_counts": dict(detection_counts),
        "top_actions": [
            {"action": action, "count": count}
            for action, count in action_counts.most_common(8)
        ],
        "top_risky_agent": top_risky_agent,
        "latest_event_at": _nested(logs[0], "timestamp") if logs else None,
    }
