from scenarios.scenario_support import build_system, latest_log, print_header, print_result


def run():
    print_header(
        1,
        "Normal operation",
        "Each agent performs an action allowed by its role; no anomaly is triggered.",
    )
    system = build_system(frequency_threshold=10)
    agents = system["agents"]

    results = {
        "collector": agents["A1"].execute_action(
            "read_data",
            {"data": "sample security feed"},
        ),
        "analyst": agents["A2"].execute_action(
            "analyze_data",
            {"data": "authentication log excerpt"},
        ),
        "writer": agents["A3"].execute_action(
            "write_report",
            {"analyst_output": "No critical finding detected."},
        ),
        "executor": agents["A4"].execute_action(
            "write_data",
            {"target": "output_config/demo.json", "content": {"mode": "safe"}},
        ),
        "admin": agents["A5"].execute_action("view_logs", {}),
    }

    assert all(result["status"] == "success" for result in results.values())
    assert len(system["executor"].calls) == 5
    assert all(entry["final_status"] == "EXECUTED" for entry in system["logs"].entries)

    print_result("Actions executed", len(system["executor"].calls))
    print_result("Logs written", len(system["logs"].entries))
    print_result("Last final status", latest_log(system)["final_status"])
    print_result("Outcome", "PASS - normal workflow remains authorized")
    return system


if __name__ == "__main__":
    run()
