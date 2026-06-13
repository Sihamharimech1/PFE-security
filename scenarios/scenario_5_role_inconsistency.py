from scenarios.scenario_support import build_system, latest_log, print_header, print_result


def run():
    print_header(
        5,
        "Role identity inconsistency",
        "A registered agent claims a different role and is blocked before RBAC evaluation.",
    )
    system = build_system()

    result = system["control"].process_request(
        {
            "agent_id": "A1",
            "role": "admin",
            "action": "kill_switch",
            "params": {},
        }
    )
    last_log = latest_log(system)

    assert result["reason"] == "ROLE_INCONSISTENCY"
    assert last_log["detection_rule"] == "ROLE_IDENTITY_MISMATCH"
    assert last_log["agent_role"] == "unverified"
    assert system["executor"].calls == []

    print_result("Returned result", result["reason"])
    print_result("Detection rule", last_log["detection_rule"])
    print_result("Execution attempts", len(system["executor"].calls))
    print_result("Outcome", "PASS - identity inconsistency blocked before authorization")
    return system


if __name__ == "__main__":
    run()
