import hashlib
import json
from datetime import datetime, timezone

from pymongo.errors import DuplicateKeyError

from storage.mongo_client import MongoDBClient


class PolicyRepository:
    """Private, versioned persistence for security policies."""

    COLLECTION_NAME = "security_policies"

    def __init__(self, mongo_timeout_ms=1500, connect_timeout_ms=None, socket_timeout_ms=None):
        self.mongo = MongoDBClient(
            server_selection_timeout_ms=mongo_timeout_ms,
            connect_timeout_ms=connect_timeout_ms,
            socket_timeout_ms=socket_timeout_ms,
        )
        self.collection = self.mongo.get_collection(self.COLLECTION_NAME)
        self.collection.create_index("policy_id", unique=True)
        self.collection.create_index("version", unique=True)
        self.collection.create_index(
            "status",
            unique=True,
            partialFilterExpression={"status": "active"},
        )
        self.collection.create_index([("created_at", -1)])

    @staticmethod
    def _checksum(policy):
        canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def get_active(self):
        document = self.collection.find_one(
            {"status": "active"},
            {"_id": 0},
        )
        return document or {}

    def bootstrap(self, policy):
        """
        Insert the first active policy only when no active version exists.

        This method never edits an existing policy document.
        """
        current = self.get_active()
        if current:
            return current

        now = datetime.now(timezone.utc)
        version = str(policy.get("version") or "1")
        checksum = self._checksum(policy)
        document = {
            "policy_id": f"rbac-{version}-{checksum[:12]}",
            "version": version,
            "status": "active",
            "policy": policy,
            "checksum_sha256": checksum,
            "source": "bootstrap",
            "created_at": now,
            "activated_at": now,
        }

        try:
            self.collection.insert_one(document)
        except DuplicateKeyError:
            current = self.get_active()
            if current:
                return current
            raise

        return {key: value for key, value in document.items() if key != "_id"}
