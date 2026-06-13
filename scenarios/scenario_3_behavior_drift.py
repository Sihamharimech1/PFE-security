from scenarios.scenario_support import build_system, latest_log, print_header, print_result


def run():
    print_header(
        3,
        "Behavior drift",
        "Repeated requests exceed the frequency threshold and trigger throttling.",
    )
    system = build_system(
        frequency_threshold=3,
        frequency_window_seconds=30,
        throttle_seconds=5,
    )
    collector = system["agents"]["A1"]
    clock = system["clock"]

    result_1 = collector.execute_action("fetch_api", {"url": "https://example.test/feed"})
    clock.advance(1)
    result_2 = collector.execute_action("fetch_api", {"url": "https://example.test/feed"})
    clock.advance(1)
    result_3 = collector.execute_action("fetch_api", {"url": "https://example.test/feed"})
    blocked_result = collector.execute_action("fetch_api", {"url": "https://example.test/feed"})

    assert result_1["status"] == "success"
    assert result_2["status"] == "success"
    assert result_3["status"] == "success"
    assert blocked_result["status"] == "blocked"
    assert blocked_result["reason"] == "THROTTLED"
    assert latest_log(system)["blocked_reason"] == "THROTTLED"

    anomaly_log = system["logs"].entries[-2]
    print_result("Anomaly rule", anomaly_log["detection_rule"])
    print_result("Incident action", anomaly_log["incident_action"])
    print_result("Blocked follow-up", blocked_result["reason"])
    print_result("Outcome", "PASS - drift detected and agent moved to DEGRADED")
    return system


if __name__ == "__main__":
    run()
