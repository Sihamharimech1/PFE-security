"""
Configurable policy engine for roles, actions, and action sensitivity.

The prototype originally kept RBAC and action risk directly in Python modules.
This engine keeps the same behavior while moving policy data into
config/policies.json so the backend is easier to audit and evolve.
"""

from functools import lru_cache
import json
from pathlib import Path


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


@lru_cache(maxsize=1)
def load_policy():
    try:
        with open(POLICY_PATH, "r", encoding="utf-8") as file:
            policy = json.load(file)
        return _validate_policy(policy)
    except Exception as exc:
        fallback = dict(FALLBACK_POLICY)
        fallback["_load_error"] = f"{type(exc).__name__}: {exc}"
        return fallback


def refresh_policy_cache():
    load_policy.cache_clear()


def policy_load_error():
    return load_policy().get("_load_error")


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


def policy_summary():
    policy = load_policy()
    roles = {
        role: {
            "description": role_policy.get("description"),
            "allowed_actions": allowed_actions_for_role(role),
            "direct_actions": role_policy.get("allowed_actions", []),
            "inherits": role_policy.get("inherits", []),
        }
        for role, role_policy in policy.get("roles", {}).items()
    }
    return {
        "version": policy.get("version"),
        "load_error": policy.get("_load_error"),
        "roles": roles,
        "actions": policy.get("actions", {}),
        "execution": execution_policy(),
        "known_actions": known_actions(),
    }
