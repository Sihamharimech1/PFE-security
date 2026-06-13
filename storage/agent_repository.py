# storage/agent_repository.py

from datetime import datetime, timezone
from storage.mongo_client import MongoDBClient

VALID_LIMITATION_LEVELS = {
    "NORMAL",
    "WATCH",
    "DEGRADED",
    "RESTRICTED",
    "SUSPENDED",
}


class AgentRepository:

    def __init__(self, mongo_timeout_ms=5000, connect_timeout_ms=None, socket_timeout_ms=None):
        client = MongoDBClient(
            server_selection_timeout_ms=mongo_timeout_ms,
            connect_timeout_ms=connect_timeout_ms,
            socket_timeout_ms=socket_timeout_ms,
        )
        self.col = client.get_collection("agent_states")
        self.col.create_index("agent_id", unique=True)
        self.col.create_index("status")
        self.col.create_index("role")
        self.col.create_index("limitation.level")
        self.col.create_index([("status", 1), ("updated_at", -1)])

    def register(self, agent_id: str, role: str):
        now = datetime.now(timezone.utc).isoformat()
        self.col.update_one(
            {"agent_id": agent_id},
            {
                "$setOnInsert": {
                    "status":     "active",
                    "created_at": now,
                    "history":    [{"status": "active", "changed_at": now}],
                    "limitation": {
                        "level": "NORMAL",
                        "reason": "Agent registered",
                        "changed_at": now,
                        "next_allowed_at": None,
                        "recover_at": None,
                        "history": [
                            {
                                "level": "NORMAL",
                                "reason": "Agent registered",
                                "changed_at": now,
                            }
                        ],
                    },
                },
                "$set": {
                    "agent_id": agent_id,
                    "role": role,
                    "updated_at": now,
                    "last_seen": now,
                },
            },
            upsert=True
        )
        current = self.get_state(agent_id)
        initial_level = (
            "SUSPENDED"
            if current.get("status") in {"suspended", "stopped"}
            else "NORMAL"
        )
        self.col.update_one(
            {
                "agent_id": agent_id,
                "limitation.level": {"$exists": False},
            },
            {
                "$set": {
                    "limitation": {
                        "level": initial_level,
                        "reason": "Limitation controls initialized",
                        "changed_at": now,
                        "next_allowed_at": None,
                        "recover_at": None,
                        "history": [
                            {
                                "level": initial_level,
                                "reason": "Limitation controls initialized",
                                "changed_at": now,
                            }
                        ],
                    }
                }
            },
        )
        print(f"[AgentRepository] Registered '{agent_id}' ({role})")

    def update_status(self, agent_id: str, new_status: str, reason: str = None):
        now = datetime.now(timezone.utc).isoformat()
        current = self.get_state(agent_id)
        current_status = current.get("status") if current else None
        current_level = current.get("limitation", {}).get("level", "NORMAL")
        target_level = (
            "NORMAL" if new_status == "active" else "SUSPENDED"
        )
        limitation_reason = reason or (
            "Agent resumed"
            if new_status == "active"
            else f"Agent status changed to {new_status}"
        )

        update = {
            "$set": {
                "status": new_status,
                "updated_at": now,
                "last_seen": now,
                "limitation.level": target_level,
                "limitation.reason": limitation_reason,
                "limitation.changed_at": now,
                "limitation.next_allowed_at": None,
                "limitation.recover_at": None,
            }
        }
        pushes = {}
        if current_status != new_status:
            history_entry = {"status": new_status, "changed_at": now}
            if reason:
                history_entry["reason"] = reason
            pushes["history"] = history_entry
        if current_level != target_level:
            pushes["limitation.history"] = {
                "level": target_level,
                "reason": limitation_reason,
                "changed_at": now,
            }
        if pushes:
            update["$push"] = pushes

        result = self.col.update_one({"agent_id": agent_id}, update)
        if result.matched_count == 0:
            return False

        if current_status == new_status and current_level == target_level:
            print(f"[AgentRepository] '{agent_id}' already {new_status}")
            return False

        print(f"[AgentRepository] '{agent_id}' -> {new_status}")
        return True

    def get_limitation(self, agent_id: str) -> dict:
        document = self.col.find_one(
            {"agent_id": agent_id},
            {"_id": 0, "limitation": 1},
        )
        limitation = document.get("limitation", {}) if document else {}
        return {
            "level": limitation.get("level", "NORMAL"),
            "reason": limitation.get("reason"),
            "changed_at": limitation.get("changed_at"),
            "next_allowed_at": limitation.get("next_allowed_at"),
            "recover_at": limitation.get("recover_at"),
            "history": limitation.get("history", []),
        }

    def update_limitation(
        self,
        agent_id: str,
        level: str,
        reason: str,
        next_allowed_at=None,
        recover_at=None,
    ) -> bool:
        if level not in VALID_LIMITATION_LEVELS:
            raise ValueError(
                f"limitation level must be one of {sorted(VALID_LIMITATION_LEVELS)}"
            )

        now = datetime.now(timezone.utc).isoformat()
        current = self.get_limitation(agent_id)
        changed = current.get("level") != level
        update = {
            "$set": {
                "limitation.level": level,
                "limitation.reason": reason,
                "limitation.changed_at": now,
                "limitation.next_allowed_at": next_allowed_at,
                "limitation.recover_at": recover_at,
                "updated_at": now,
            }
        }
        if changed:
            update["$push"] = {
                "limitation.history": {
                    "level": level,
                    "reason": reason,
                    "changed_at": now,
                }
            }

        result = self.col.update_one({"agent_id": agent_id}, update)
        return result.matched_count > 0

    def update_next_allowed_at(self, agent_id: str, next_allowed_at) -> bool:
        result = self.col.update_one(
            {"agent_id": agent_id},
            {
                "$set": {
                    "limitation.next_allowed_at": next_allowed_at,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            },
        )
        return result.matched_count > 0

    def get_state(self, agent_id: str) -> dict:
        return self.col.find_one({"agent_id": agent_id}, {"_id": 0}) or {}

    def get_all_states(self) -> list:
        return list(self.col.find({}, {"_id": 0}).sort("agent_id", 1))

    def get_by_status(self, status: str) -> list:
        return list(self.col.find({"status": status}, {"_id": 0}).sort("agent_id", 1))

    def get_history(self, agent_id: str) -> list:
        doc = self.col.find_one({"agent_id": agent_id}, {"_id": 0, "history": 1})
        return doc.get("history", []) if doc else []
