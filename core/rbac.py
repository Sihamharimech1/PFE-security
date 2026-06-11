# core/rbac.py

from core.policy_engine import allowed_actions_for_role, is_allowed


def _build_compat_policies():
    return {
        role: allowed_actions_for_role(role)
        for role in ["collector", "analyst", "writer", "executor", "admin"]
    }


# Kept for compatibility with older imports/tests. New code should call
# core.policy_engine functions directly.
RBAC_POLICIES = _build_compat_policies()
