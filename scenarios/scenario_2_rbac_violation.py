from scenarios.scenario_support import build_system, latest_log, print_header, print_result


def run():
    print_header(
        2,
        "Forbidden action",
        "A collector attempts an action outside its role and RBAC blocks it.",
    )
    system = build_system()
    collector = system["agents"]["A1"]

    result = collector.execute_action("delete_data", {"target": "secret.txt"})
    last_log = latest_log(system)

    assert result == "DENIED"
    assert last_log["rbac_status"] == "DENIED"
    assert last_log["blocked_reason"] == "RBAC_DENIED"
    assert system["executor"].calls == []

    print_result("Returned result", result)
    print_result("RBAC status", last_log["rbac_status"])
    print_result("Execution attempts", len(system["executor"].calls))
    print_result("Outcome", "PASS - forbidden action blocked before execution")
    return system


if __name__ == "__main__":
    run()
