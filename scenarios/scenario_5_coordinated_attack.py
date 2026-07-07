from datetime import datetime, timezone
from pathlib import Path

from agents.admin_agent import AdminAgent
from agents.collector import CollectorAgent
from agents.executor_agent import ExecutorAgent
from agents.writer import WriterAgent
from core.control_module import ControlModule
from core.detection_module import DetectionModule
from storage.agent_repository import AgentRepository


SENSITIVE_LOG = "sample_logs/auth.log"
BLOCKED_EXPORT = Path("output_config/cross_agent_blocked_export.json")
DASHBOARD_URL = "http://127.0.0.1:5173"


def section(title):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def print_result(label, value):
    print(f"  {label:<18} {value}")


def print_step(number, title):
    print(f"\n[{number}/4] {title}")


def latest_matching_log(logs, *, agent_id=None, action=None, rule_id=None):
    for item in logs.get_recent(limit=50):
        if agent_id and item.get("agent", {}).get("id") != agent_id:
            continue
        if action and item.get("request", {}).get("action") != action:
            continue
        if rule_id and item.get("security", {}).get("detection_rule") != rule_id:
            continue
        return item
    return {}


def prepare_agents():
    repository = AgentRepository()
    for agent_id in ["A1", "A3", "A4", "A5"]:
        repository.update_status(
            agent_id,
            "active",
            "Preparing coordinated attack scenario",
        )


def run():
    section("SCENARIO 5 - COORDINATED ATTACK")
    print("Goal: detect coordinated behavior across real supervised agents.")
    print("Rule: A1 reads a sensitive file, then another agent exports/writes data inside the correlation window.")
    print_result("Dashboard", DASHBOARD_URL)

    if not Path(SENSITIVE_LOG).exists():
        raise FileNotFoundError(f"Required real log file not found: {SENSITIVE_LOG}")

    if BLOCKED_EXPORT.exists():
        BLOCKED_EXPORT.unlink()

    prepare_agents()

    control = ControlModule(DetectionModule(frequency_threshold=20))
    collector = CollectorAgent("A1", control)
    writer = WriterAgent("A3", control)
    executor = ExecutorAgent("A4", control)
    admin = AdminAgent("A5", control)
    admin.register_agents([collector, writer, executor])

    print_step(1, "A1 reads real sensitive authentication log")
    read_result = collector.execute_action("read_data", {"path": SENSITIVE_LOG})
    assert isinstance(read_result, dict)
    assert read_result["status"] == "success"
    print_result("A1 action", "read_data")
    print_result("Source file", read_result.get("path"))
    print_result("Characters read", len(read_result.get("data", "")))

    print_step(2, "A3 writes report: executed, but escalated")
    report_result = writer.execute_action(
        "write_report",
        {
            "analyst_output": (
                "Authentication log shows repeated failed SSH login attempts for admin "
                "from 192.168.1.5 and a firewall block on port 22."
            ),
            "report_type": "security",
        },
    )
    assert isinstance(report_result, dict)
    assert report_result["status"] == "success"
    writer_alert = latest_matching_log(
        control.logs,
        agent_id="A3",
        action="write_report",
        rule_id="CROSS_AGENT_CORRELATION",
    )
    assert writer_alert
    assert writer_alert["security"]["incident_action"] == "ALERT"
    assert writer_alert["final_status"] == "EXECUTED_WITH_ALERT"
    assert writer.status == "active"
    print_result("A3 action", "write_report")
    print_result("Detection rule", writer_alert["security"]["detection_rule"])
    print_result("Response", writer_alert["security"]["incident_action"])
    print_result("Incident", writer_alert["security"].get("incident_id"))
    print_result("Final status", writer_alert["final_status"])
    print_result("A3 runtime status", writer.status)

    print_step(3, "A4 attempts high-risk export: blocked and suspended")
    export_result = executor.execute_action(
        "write_data",
        {
            "target": str(BLOCKED_EXPORT),
            "content": {
                "case": "real_coordinated_attack",
                "source_agent": "A1",
                "source_file": SENSITIVE_LOG,
                "export_agent": "A4",
                "attempted_at": datetime.now(timezone.utc).isoformat(),
            },
        },
    )
    assert isinstance(export_result, dict)
    assert export_result["status"] == "blocked"
    assert export_result["reason"] == "CROSS_AGENT_CORRELATION"
    assert not BLOCKED_EXPORT.exists()
    executor_alert = latest_matching_log(
        control.logs,
        agent_id="A4",
        action="write_data",
        rule_id="CROSS_AGENT_CORRELATION",
    )
    assert executor_alert
    assert executor_alert["blocked"]["is_blocked"] is True
    assert executor_alert["security"]["incident_action"] == "SUSPEND"
    assert executor_alert["final_status"] == "BLOCKED"
    assert executor.status == "suspended"
    print_result("A4 action", "write_data")
    print_result("Detection rule", executor_alert["security"]["detection_rule"])
    print_result("Response", executor_alert["security"]["incident_action"])
    print_result("Incident", executor_alert["security"].get("incident_id"))
    print_result("Final status", executor_alert["final_status"])
    print_result("Blocked reason", executor_alert["blocked"]["reason"])
    print_result("Export file exists", BLOCKED_EXPORT.exists())
    print_result("A4 runtime status", executor.status)

    print_step(4, "A5 reviews live supervision logs")
    review_result = admin.view_logs()
    assert isinstance(review_result, dict)
    assert review_result["status"] == "success"
    print_result("A5 action", "view_logs")
    print_result("Review status", review_result["status"])
    print_result("Logs returned", len(review_result.get("logs", [])))

    section("DEMO SUMMARY - SHOW THIS ON DASHBOARD")
    print_result("Dashboard", DASHBOARD_URL)
    print_result("Logs", "A1 read_data, A3 write_report, A4 write_data, A5 view_logs")
    print_result("Alerts", "CROSS_AGENT_CORRELATION for A3 and A4")
    print_result("Incidents", f"{writer_alert['security'].get('incident_id')} / {executor_alert['security'].get('incident_id')}")
    print_result("A3 outcome", "EXECUTED_WITH_ALERT + ALERT")
    print_result("A4 outcome", "BLOCKED + SUSPEND")
    print_result("A4 status", executor.status)
    print_result("Export created", BLOCKED_EXPORT.exists())
    print("\nPASS: coordinated cross-agent attack detected, escalated, and contained.")

    return {
        "read_result": read_result,
        "report_result": report_result,
        "export_result": export_result,
        "review_result": review_result,
        "writer_alert": writer_alert,
        "executor_alert": executor_alert,
    }


if __name__ == "__main__":
    run()
