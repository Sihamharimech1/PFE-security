class RBAC:
    """
    Role-Based Access Control.
    Defines which actions each role is allowed to perform.
    """

    PERMISSIONS = {
        "collector": [
            "read_data",
            "fetch_api",
            "list_resources"
        ],
        "analyst": [
            "read_data",
            "fetch_api",
            "analyze_data",
            "generate_report",
            "write_report"
        ],
        "writer": [
            "write_report",
            "format_document",
            "save_report",
            "read_data"          # can read analyst output, nothing else
        ],
        "admin": [
            # admin can do everything
            "read_data", "fetch_api", "list_resources",
            "analyze_data", "generate_report", "write_report",
            "write_data", "delete_data", "modify_config",
            "suspend_agent", "kill_switch", "execute_external"
        ]
    }

    def check(self, role: str, action: str) -> tuple[bool, str]:
        """
        Returns (True, "ok") if the role can perform the action.
        Returns (False, reason) otherwise.
        """
        allowed_actions = self.PERMISSIONS.get(role, [])

        if action in allowed_actions:
            return True, "ok"
        else:
            return False, f"Role '{role}' is NOT allowed to perform '{action}'"