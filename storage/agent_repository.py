# storage/agent_repository.py

from datetime import datetime
from storage.mongo_client import MongoDBClient

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
        self.col.create_index([("status", 1), ("updated_at", -1)])

    def register(self, agent_id: str, role: str):
        now = datetime.utcnow().isoformat()
        self.col.update_one(
            {"agent_id": agent_id},
            {
                "$setOnInsert": {
                    "agent_id":   agent_id,
                    "role":       role,
                    "status":     "active",
                    "created_at": now,
                    "history":    [{"status": "active", "changed_at": now}]
                },
                "$set": {
                    "role": role,
                    "updated_at": now,
                    "last_seen": now,
                },
            },
            upsert=True
        )
        print(f"[AgentRepository] Registered '{agent_id}' ({role})")

    def update_status(self, agent_id: str, new_status: str, reason: str = None):
        now = datetime.utcnow().isoformat()
        current = self.get_state(agent_id)
        if current and current.get("status") == new_status:
            self.col.update_one(
                {"agent_id": agent_id},
                {"$set": {"updated_at": now, "last_seen": now}},
            )
            print(f"[AgentRepository] '{agent_id}' already {new_status}")
            return False

        history_entry = {"status": new_status, "changed_at": now}
        if reason:
            history_entry["reason"] = reason
        self.col.update_one(
            {"agent_id": agent_id},
            {
                "$set":  {"status": new_status, "updated_at": now, "last_seen": now},
                "$push": {"history": history_entry}
            }
        )
        print(f"[AgentRepository] '{agent_id}' -> {new_status}")
        return True

    def get_state(self, agent_id: str) -> dict:
        return self.col.find_one({"agent_id": agent_id}, {"_id": 0}) or {}

    def get_all_states(self) -> list:
        return list(self.col.find({}, {"_id": 0}).sort("agent_id", 1))

    def get_by_status(self, status: str) -> list:
        return list(self.col.find({"status": status}, {"_id": 0}).sort("agent_id", 1))

    def get_history(self, agent_id: str) -> list:
        doc = self.col.find_one({"agent_id": agent_id}, {"_id": 0, "history": 1})
        return doc.get("history", []) if doc else []
