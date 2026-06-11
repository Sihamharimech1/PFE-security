from datetime import datetime, timezone
from uuid import uuid4

from storage.mongo_client import MongoDBClient


VALID_INCIDENT_STATUSES = {
    "OPEN",
    "ACKNOWLEDGED",
    "RESOLVED",
    "FALSE_POSITIVE",
}


class IncidentRepository:
    def __init__(self, mongo_timeout_ms=5000, connect_timeout_ms=None, socket_timeout_ms=None):
        self.mongo = MongoDBClient(
            server_selection_timeout_ms=mongo_timeout_ms,
            connect_timeout_ms=connect_timeout_ms,
            socket_timeout_ms=socket_timeout_ms,
        )
        self.collection = self.mongo.get_collection("incidents")
        self.collection.create_index("incident_id", unique=True)
        self.collection.create_index([("status", 1), ("created_at", -1)])
        self.collection.create_index([("agent_id", 1), ("created_at", -1)])
        self.collection.create_index([("severity", 1), ("created_at", -1)])
        self.collection.create_index([("risk_level", 1), ("created_at", -1)])
        self.collection.create_index([("risk_score", -1), ("created_at", -1)])
        self.collection.create_index([("rule_id", 1), ("created_at", -1)])
        self.collection.create_index([("created_at", -1)])

    @staticmethod
    def _limit(limit):
        try:
            return max(1, min(int(limit), 500))
        except (TypeError, ValueError):
            return 50

    @staticmethod
    def _build_query(
        *,
        status=None,
        agent_id=None,
        severity=None,
        risk_level=None,
        rule_id=None,
        since=None,
        until=None,
    ):
        query = {}
        if status:
            if isinstance(status, (list, tuple, set)):
                query["status"] = {"$in": list(status)}
            else:
                query["status"] = status
        if agent_id:
            query["agent_id"] = agent_id
        if severity:
            query["severity"] = severity
        if risk_level:
            query["risk_level"] = risk_level
        if rule_id:
            query["rule_id"] = rule_id

        created_filter = {}
        if since:
            created_filter["$gte"] = since
        if until:
            created_filter["$lte"] = until
        if created_filter:
            query["created_at"] = created_filter

        return query

    @staticmethod
    def _now():
        return datetime.now(timezone.utc)

    def create_incident(self, detection_event, response):
        now = self._now()
        incident_id = f"INC-{now.strftime('%Y%m%d')}-{uuid4().hex[:8].upper()}"
        details = detection_event.get("details", {}) if isinstance(detection_event, dict) else {}

        document = {
            "incident_id": incident_id,
            "status": "OPEN",
            "agent_id": detection_event.get("agent_id") if isinstance(detection_event, dict) else None,
            "rule_id": detection_event.get("rule_id") if isinstance(detection_event, dict) else None,
            "severity": detection_event.get("severity") if isinstance(detection_event, dict) else None,
            "risk_score": detection_event.get("risk_score") if isinstance(detection_event, dict) else None,
            "risk_level": detection_event.get("risk_level") if isinstance(detection_event, dict) else None,
            "recommended_action": detection_event.get("recommended_action") if isinstance(detection_event, dict) else None,
            "response_action": response.get("action"),
            "response_status": response.get("status"),
            "response_applied": response.get("applied", False),
            "details": details,
            "created_at": now,
            "updated_at": now,
            "history": [
                {
                    "status": "OPEN",
                    "changed_at": now,
                    "reason": "Incident created from detection event",
                }
            ],
            "notes": [],
        }

        self.collection.insert_one(document)
        return incident_id

    def update_status(self, incident_id, status, note=None, actor="system"):
        if status not in VALID_INCIDENT_STATUSES:
            raise ValueError(f"status must be one of {sorted(VALID_INCIDENT_STATUSES)}")

        now = self._now()
        history_entry = {
            "status": status,
            "changed_at": now,
            "actor": actor,
        }
        if note:
            history_entry["note"] = note

        update = {
            "$set": {
                "status": status,
                "updated_at": now,
            },
            "$push": {
                "history": history_entry,
            },
        }
        if note:
            update["$push"]["notes"] = {
                "note": note,
                "actor": actor,
                "created_at": now,
            }

        result = self.collection.update_one({"incident_id": incident_id}, update)
        return result.modified_count > 0

    def get_by_id(self, incident_id):
        return self.collection.find_one({"incident_id": incident_id}, {"_id": 0}) or {}

    def get_recent(self, limit=50):
        return list(
            self.collection
            .find({}, {"_id": 0})
            .sort("created_at", -1)
            .limit(self._limit(limit))
        )

    def get_filtered(
        self,
        *,
        limit=50,
        status=None,
        agent_id=None,
        severity=None,
        risk_level=None,
        rule_id=None,
        since=None,
        until=None,
    ):
        query = self._build_query(
            status=status,
            agent_id=agent_id,
            severity=severity,
            risk_level=risk_level,
            rule_id=rule_id,
            since=since,
            until=until,
        )
        return list(
            self.collection
            .find(query, {"_id": 0})
            .sort("created_at", -1)
            .limit(self._limit(limit))
        )

    def get_open(self, limit=50):
        return self.get_filtered(status=["OPEN", "ACKNOWLEDGED"], limit=limit)

    def count_by_status(self):
        counts = {status: 0 for status in VALID_INCIDENT_STATUSES}
        for row in self.collection.aggregate(
            [{"$group": {"_id": "$status", "count": {"$sum": 1}}}]
        ):
            counts[row["_id"] or "UNKNOWN"] = row["count"]
        return counts

    def count_open(self):
        return self.collection.count_documents(
            {"status": {"$in": ["OPEN", "ACKNOWLEDGED"]}}
        )
