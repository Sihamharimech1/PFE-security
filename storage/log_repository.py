# storage/log_repository.py

from datetime import datetime, timezone
from storage.mongo_client import MongoDBClient


class LogRepository:
    def __init__(self, mongo_timeout_ms=5000, connect_timeout_ms=None, socket_timeout_ms=None):
        self.mongo = MongoDBClient(
            server_selection_timeout_ms=mongo_timeout_ms,
            connect_timeout_ms=connect_timeout_ms,
            socket_timeout_ms=socket_timeout_ms,
        )
        self.collection = self.mongo.get_collection("audit_logs")
        self._ensure_indexes()

    def _ensure_indexes(self):
        self.collection.create_index("timestamp")
        self.collection.create_index([("timestamp", -1)])
        self.collection.create_index([("agent.id", 1), ("timestamp", -1)])
        self.collection.create_index([("request.action", 1), ("timestamp", -1)])
        self.collection.create_index([("security.severity", 1), ("timestamp", -1)])
        self.collection.create_index([("security.risk_level", 1), ("timestamp", -1)])
        self.collection.create_index([("security.risk_score", -1), ("timestamp", -1)])
        self.collection.create_index([("security.detection_status", 1), ("timestamp", -1)])
        self.collection.create_index([("security.incident_id", 1), ("timestamp", -1)])
        self.collection.create_index([("blocked.is_blocked", 1), ("timestamp", -1)])

    @staticmethod
    def _limit(limit):
        try:
            return max(1, min(int(limit), 500))
        except (TypeError, ValueError):
            return 50

    @staticmethod
    def _build_query(
        *,
        agent_id=None,
        action=None,
        severity=None,
        risk_level=None,
        blocked=None,
        detection_status=None,
        incident_id=None,
        since=None,
        until=None,
    ):
        query = {}
        if agent_id:
            query["agent.id"] = agent_id
        if action:
            query["request.action"] = action
        if severity:
            query["security.severity"] = severity
        if risk_level:
            query["security.risk_level"] = risk_level
        if blocked is not None:
            query["blocked.is_blocked"] = bool(blocked)
        if detection_status:
            query["security.detection_status"] = detection_status
        if incident_id:
            query["security.incident_id"] = incident_id

        timestamp_filter = {}
        if since:
            timestamp_filter["$gte"] = since
        if until:
            timestamp_filter["$lte"] = until
        if timestamp_filter:
            query["timestamp"] = timestamp_filter

        return query

    def create_log(
        self,
        agent_id,
        agent_role,
        action,
        params,
        validation_status="NOT_CHECKED",
        rbac_status="NOT_CHECKED",
        filter_status="NOT_CHECKED",
        detection_status="NOT_CHECKED",
        detection_rule=None,
        severity=None,
        risk_score=None,
        risk_level=None,
        risk_factors=None,
        action_sensitivity=None,
        decision_explanation=None,
        recommended_action=None,
        detection_details=None,
        incident_status="NOT_TRIGGERED",
        incident_action=None,
        incident_id=None,
        incident_lifecycle_status=None,
        execution_status="NOT_EXECUTED",
        final_status="UNKNOWN",
        result_preview=None,
        is_blocked=False,
        blocked_reason=None,
    ):
        log_document = {
            "timestamp": datetime.now(timezone.utc),

            "agent": {
                "id": agent_id,
                "role": agent_role
            },

            "request": {
                "action": action,
                "params": params
            },

            "security": {
                "validation_status": validation_status,
                "rbac_status": rbac_status,
                "filter_status": filter_status,
                "detection_status": detection_status,
                "detection_rule": detection_rule,
                "severity": severity,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "risk_factors": risk_factors or [],
                "action_sensitivity": action_sensitivity,
                "decision_explanation": decision_explanation,
                "recommended_action": recommended_action,
                "detection_details": detection_details or {},
                "incident_status": incident_status,
                "incident_action": incident_action,
                "incident_id": incident_id,
                "incident_lifecycle_status": incident_lifecycle_status,
            },

            "execution": {
                "status": execution_status,
                "result_preview": result_preview
            },

            "final_status": final_status,

            "blocked": {
                "is_blocked": is_blocked,
                "reason": blocked_reason
            }
        }

        result = self.collection.insert_one(log_document)
        return result.inserted_id

    def get_recent(self, limit: int = 50) -> list:
        return list(
            self.collection
            .find({}, {"_id": 0})
            .sort("timestamp", -1)
            .limit(self._limit(limit))
        )

    def get_filtered(
        self,
        *,
        limit=50,
        agent_id=None,
        action=None,
        severity=None,
        risk_level=None,
        blocked=None,
        detection_status=None,
        incident_id=None,
        since=None,
        until=None,
    ) -> list:
        query = self._build_query(
            agent_id=agent_id,
            action=action,
            severity=severity,
            risk_level=risk_level,
            blocked=blocked,
            detection_status=detection_status,
            incident_id=incident_id,
            since=since,
            until=until,
        )
        return list(
            self.collection
            .find(query, {"_id": 0})
            .sort("timestamp", -1)
            .limit(self._limit(limit))
        )

    def get_blocked(self, limit=100) -> list:
        return list(
            self.collection
            .find({"blocked.is_blocked": True}, {"_id": 0})
            .sort("timestamp", -1)
            .limit(self._limit(limit))
        )

    def get_alerts(self, limit=100) -> list:
        return list(
            self.collection
            .find(
                {
                    "$or": [
                        {"security.detection_status": "ANOMALY"},
                        {"security.incident_action": {"$nin": [None, "NONE"]}},
                        {"blocked.is_blocked": True},
                    ]
                },
                {"_id": 0},
            )
            .sort("timestamp", -1)
            .limit(self._limit(limit))
        )
