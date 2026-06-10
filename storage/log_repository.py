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
        decision_explanation=None,
        recommended_action=None,
        detection_details=None,
        incident_status="NOT_TRIGGERED",
        incident_action=None,
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
                "decision_explanation": decision_explanation,
                "recommended_action": recommended_action,
                "detection_details": detection_details or {},
                "incident_status": incident_status,
                "incident_action": incident_action,
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
            .limit(limit)
        )

    def get_blocked(self) -> list:
        return list(
            self.collection.find(
                {"blocked.is_blocked": True},
                {"_id": 0}
            )
        )
