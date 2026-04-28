# core/rbac.py

RBAC_POLICIES = {
    "collector": ["fetch_api", "read_data"],

    "analyst": ["read_data", "direct_answer", "analyze_data"],

    "writer": ["read_data", "write_report", "format_document", "save_report"],

    "executor": ["execute_action", "delete_data", "write_data", "run_command"],

    "admin": [
        "fetch_api",
        "read_data",
        "analyze_data",
        "generate_report",
        "delete_data",
        "execute_action",
        "write_data",
        "run_command"
    ]
}

def is_allowed(role, action):
    return action in RBAC_POLICIES.get(role, [])