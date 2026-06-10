# core/rbac.py

RBAC_POLICIES = {
    "collector": ["fetch_api", "read_data"],

    "analyst": ["read_data", "direct_answer", "analyze_data"],

    "writer": ["read_data", "write_report", "format_document", "save_report"],

    "executor": ["execute_action", "delete_data", "write_data", "run_command"],

    "admin": [
        # All actions from every agent
        "fetch_api", "read_data",
        "direct_answer", "analyze_data",
        "write_report", "format_document", "save_report",
        "execute_action", "delete_data", "write_data", "run_command",
        # Admin-exclusive actions - no other agent can do these
        "suspend_agent", "resume_agent", "kill_switch", "modify_config", "view_logs"
    ]
}

def is_allowed(role, action):
    return action in RBAC_POLICIES.get(role, [])
