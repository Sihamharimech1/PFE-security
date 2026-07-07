from datetime import datetime, timezone
import base64
import hashlib
import hmac
import os
import secrets

from storage.mongo_client import MongoDBClient


HASH_ALGORITHM = "pbkdf2_sha256"
HASH_ITERATIONS = 260000


def _b64encode(raw):
    return base64.b64encode(raw).decode("ascii")


def _b64decode(value):
    return base64.b64decode(value.encode("ascii"))


def _hash_password(password, salt=None, iterations=HASH_ITERATIONS):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return {
        "algorithm": HASH_ALGORITHM,
        "iterations": iterations,
        "salt": _b64encode(salt),
        "hash": _b64encode(digest),
    }


def verify_password(password, stored_password):
    if not isinstance(password, str) or not isinstance(stored_password, dict):
        return False
    if stored_password.get("algorithm") != HASH_ALGORITHM:
        return False
    try:
        iterations = int(stored_password["iterations"])
        salt = _b64decode(stored_password["salt"])
        expected = _b64decode(stored_password["hash"])
    except Exception:
        return False
    candidate = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return hmac.compare_digest(candidate, expected)


class AuthRepository:
    COLLECTION_NAME = "dashboard_users"

    def __init__(self, mongo_timeout_ms=5000, connect_timeout_ms=None, socket_timeout_ms=None):
        client = MongoDBClient(
            server_selection_timeout_ms=mongo_timeout_ms,
            connect_timeout_ms=connect_timeout_ms,
            socket_timeout_ms=socket_timeout_ms,
        )
        self.collection = client.get_collection(self.COLLECTION_NAME)
        self.collection.create_index("username", unique=True)
        self.collection.create_index("enabled")

    def upsert_env_user(self, username, password):
        now = datetime.now(timezone.utc).isoformat()
        document = {
            "username": username,
            "password": _hash_password(password),
            "enabled": True,
            "source": "env_bootstrap",
            "updated_at": now,
        }
        self.collection.update_one(
            {"username": username},
            {
                "$set": document,
                "$setOnInsert": {"created_at": now},
            },
            upsert=True,
        )
        return self.get_user(username)

    def get_user(self, username):
        return self.collection.find_one({"username": username}, {"_id": 0}) or {}

    def verify_credentials(self, username, password):
        user = self.get_user(username)
        if not user or not user.get("enabled", False):
            return False
        return verify_password(password, user.get("password"))


def bootstrap_dashboard_user_from_env(
    repository=None,
    username_var="DASHBOARD_USERNAME",
    password_var="DASHBOARD_PASSWORD",
):
    username = os.getenv(username_var)
    password = os.getenv(password_var)
    if not username or not password:
        return {"bootstrapped": False, "reason": "missing_env_credentials"}
    repository = repository or AuthRepository()
    repository.upsert_env_user(username, password)
    return {"bootstrapped": True, "username": username}
