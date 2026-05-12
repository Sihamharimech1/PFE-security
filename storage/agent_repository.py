# storage/agent_repository.py

from datetime import datetime
from storage.mongo_client import MongoDBClient

class AgentRepository:

    def __init__(self):
        client = MongoDBClient()
        self.col = client.get_collection("agent_states")
        self.col.create_index("agent_id", unique=True)

    def register(self, agent_id: str, role: str):
        now = datetime.utcnow().isoformat()
        self.col.update_one(
            {"agent_id": agent_id},
            {"$setOnInsert": {
                "agent_id":   agent_id,
                "role":       role,
                "status":     "active",
                "created_at": now,
                "updated_at": now,
                "history":    [{"status": "active", "changed_at": now}]
            }},
            upsert=True
        )
        print(f"[AgentRepository] Registered '{agent_id}' ({role})")

    def update_status(self, agent_id: str, new_status: str, reason: str = None):
        now = datetime.utcnow().isoformat()
        history_entry = {"status": new_status, "changed_at": now}
        if reason:
            history_entry["reason"] = reason
        self.col.update_one(
            {"agent_id": agent_id},
            {
                "$set":  {"status": new_status, "updated_at": now},
                "$push": {"history": history_entry}
            }
        )
        print(f"[AgentRepository] '{agent_id}' → {new_status}")

    def get_state(self, agent_id: str) -> dict:
        return self.col.find_one({"agent_id": agent_id}, {"_id": 0}) or {}

    def get_all_states(self) -> list:
        return list(self.col.find({}, {"_id": 0}))

    def get_history(self, agent_id: str) -> list:
        doc = self.col.find_one({"agent_id": agent_id}, {"_id": 0, "history": 1})
        return doc.get("history", []) if doc else []