"""
Private policy engine for roles, actions, and action sensitivity.

MongoDB is the authoritative runtime source. The validated JSON policy is used
only to bootstrap an empty policy collection or as an emergency fallback when
MongoDB is unavailable.
"""

from functools import lru_cache
import json
import os
from pathlib import Path

from storage.policy_repository import PolicyRepository


POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "policies.json"
VALID_SENSITIVITIES = {"low", "medium", "high", "critical"}


FALLBACK_POLICY = {
    "version": "fallback",
    "roles": {
        "collector": {"allowed_actions": ["fetch_api", "read_data"]},
        "analyst": {"allowed_actions": ["read_data", "direct_answer", "analyze_data"]},
        "writer": {"allowed_actions": ["read_data", "write_report", "format_document", "save_report"]},
        "executor": {"allowed_actions": ["execute_action", "delete_data", "write_data", "run_command"]},
        "admin": {
            "inherits": ["collector", "analyst", "writer", "executor"],
            "allowed_actions": ["suspend_agent", "resume_agent", "kill_switch", "modify_config", "view_logs"],
        },
    },
    "actions": {
        "fetch_api": {"sensitivity": "medium"},
        "read_data": {"sensitivity": "low"},
        "direct_answer": {"sensitivity": "low"},
        "analyze_data": {"sensitivity": "low"},
        "generate_report": {"sensitivity": "low"},
        "write_report": {"sensitivity": "low"},
        "format_document": {"sensitivity": "low"},
        "save_report": {"sensitivity": "medium"},
        "execute_action": {"sensitivity": "medium"},
        "delete_data": {"sensitivity": "high"},
        "write_data": {"sensitivity": "medium"},
        "run_command": {"sensitivity": "high"},
        "suspend_agent": {"sensitivity": "high", "admin_only": True},
        "resume_agent": {"sensitivity": "high", "admin_only": True},
        "kill_switch": {"sensitivity": "critical", "admin_only": True},
        "modify_config": {"sensitivity": "high", "admin_only": True},
        "view_logs": {"sensitivity": "medium", "admin_only": True},
    },
    "defaults": {"unknown_action_sensitivity": "medium"},
    "execution": {
        "network": {
            "allowed_schemes": ["http", "https"],
            "blocked_hosts": ["localhost"],
            "block_private_ips": True,
            "timeout_seconds": 10,
            "content_preview_chars": 800,
        },
        "filesystem": {
            "read_dirs": ["sample_logs", "output_reports", "output_config", "sandbox"],
            "write_dirs": ["output_reports", "output_config", "sandbox"],
            "delete_dirs": ["output_reports", "sandbox"],
            "allow_dummy_delete_in_workspace": True,
        },
        "commands": {
            "allowed": ["whoami", "hostname", "ping", "ipconfig", "ifconfig", "echo"],
            "timeout_seconds": 5,
        },
    },
}


def _validate_policy(policy):
    if not isinstance(policy, dict):
        raise ValueError("Policy must be a JSON object")

    roles = policy.get("roles")
    actions = policy.get("actions")
    if not isinstance(roles, dict) or not roles:
        raise ValueError("Policy must define non-empty roles")
    if not isinstance(actions, dict) or not actions:
        raise ValueError("Policy must define non-empty actions")

    for role, role_policy in roles.items():
        if not isinstance(role_policy, dict):
            raise ValueError(f"Role policy for '{role}' must be an object")
        allowed_actions = role_policy.get("allowed_actions", [])
        inherited_roles = role_policy.get("inherits", [])
        if not isinstance(allowed_actions, list):
            raise ValueError(f"Role '{role}' allowed_actions must be a list")
        if not isinstance(inherited_roles, list):
            raise ValueError(f"Role '{role}' inherits must be a list")
        unknown_inherited = [item for item in inherited_roles if item not in roles]
        if unknown_inherited:
            raise ValueError(f"Role '{role}' inherits unknown role(s): {unknown_inherited}")

    for action, action_policy in actions.items():
        if not isinstance(action_policy, dict):
            raise ValueError(f"Action policy for '{action}' must be an object")
        sensitivity = action_policy.get("sensitivity")
        if sensitivity not in VALID_SENSITIVITIES:
            raise ValueError(
                f"Action '{action}' sensitivity must be one of {sorted(VALID_SENSITIVITIES)}"
            )

    return policy


def _load_json_policy():
    with open(POLICY_PATH, "r", encoding="utf-8") as file:
        return _validate_policy(json.load(file))


def _load_mongo_policy(bootstrap_policy):
    timeout_ms = int(os.getenv("POLICY_MONGO_TIMEOUT_MS", "1500"))
    repository = PolicyRepository(
        mongo_timeout_ms=timeout_ms,
        connect_timeout_ms=timeout_ms,
        socket_timeout_ms=timeout_ms,
    )
    document = repository.get_active()
    if not document:
        document = repository.bootstrap(bootstrap_policy)

    policy = _validate_policy(document.get("policy"))
    policy["_policy_source"] = "mongo"
    policy["_policy_id"] = document.get("policy_id")
    policy["_policy_checksum"] = document.get("checksum_sha256")
    return policy


@lru_cache(maxsize=1)
def load_policy():
    json_policy = None
    json_error = None
    try:
        json_policy = _load_json_policy()
    except Exception as exc:
        json_error = f"{type(exc).__name__}: {exc}"
        json_policy = _validate_policy(dict(FALLBACK_POLICY))

    try:
        return _load_mongo_policy(json_policy)
    except Exception as exc:
        policy = dict(json_policy)
        policy["_policy_source"] = "json_fallback"
        policy["_mongo_error"] = f"{type(exc).__name__}: {exc}"
        if json_error:
            policy["_load_error"] = json_error
        return policy


def refresh_policy_cache():
    load_policy.cache_clear()


def policy_load_error():
    return load_policy().get("_load_error")


def policy_source():
    return load_policy().get("_policy_source", "unknown")


def _role_allowed_actions(policy, role, seen=None):
    seen = seen or set()
    if role in seen:
        return set()
    seen.add(role)

    role_policy = policy.get("roles", {}).get(role, {})
    allowed = set(role_policy.get("allowed_actions", []))
    for inherited_role in role_policy.get("inherits", []):
        allowed.update(_role_allowed_actions(policy, inherited_role, seen))
    return allowed


def allowed_actions_for_role(role):
    return sorted(_role_allowed_actions(load_policy(), role))


def is_allowed(role, action):
    return action in allowed_actions_for_role(role)


def known_actions():
    policy = load_policy()
    configured = set(policy.get("actions", {}).keys())
    for role in policy.get("roles", {}):
        configured.update(allowed_actions_for_role(role))
    return sorted(configured)


def is_known_action(action):
    return action in set(known_actions())


def action_policy(action):
    return load_policy().get("actions", {}).get(action, {})


def action_sensitivity(action):
    policy = load_policy()
    default = policy.get("defaults", {}).get("unknown_action_sensitivity", "medium")
    return action_policy(action).get("sensitivity", default)


def execution_policy():
    return load_policy().get("execution", FALLBACK_POLICY["execution"])
