"""
Shared deterministic helpers for the official PFE scenarios.

The scenarios intentionally avoid MongoDB, network calls, and live LLM calls so
they stay reproducible during demos and automated checks.
"""

from agents.base_agent import BaseAgent
from core.control_module import ControlModule
from core.detection_module import DetectionModule
from core.incident_module import IncidentModule


class MemoryLogRepository:
    def __init__(self):
        self.entries = []

    def create_log(self, **kwargs):
        self.entries.append(kwargs)
        return len(self.entries)

    def get_recent(self, limit=50):
        return list(reversed(self.entries[-limit:]))


class MemoryAgentRepository:
    def __init__(self):
        self.register_calls = []
        self.status_updates = []

    def register(self, agent_id, role):
        self.register_calls.append((agent_id, role))

    def update_status(self, agent_id, new_status, reason=None):
        self.status_updates.append((agent_id, new_status, reason))


class DeterministicExecutor:
    """
    Minimal execution backend for scenarios.

    It proves that the control layer allows or blocks actions correctly without
    depending on external APIs, files, or LLM providers.
    """

    def __init__(self):
        self.calls = []

    def execute(self, action, params):
        self.calls.append((action, params))
        return {
            "status": "success",
            "action": action,
            "message": "simulated execution completed",
            "params": params,
        }


class ScenarioClock:
    def __init__(self, start=0.0):
        self.value = start

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def build_system(
    *,
    frequency_threshold=5,
    frequency_window_seconds=60,
    role_violation_threshold=3,
    role_violation_window_seconds=120,
    throttle_seconds=2,
):
    clock = ScenarioClock()
    logs = MemoryLogRepository()
    executor = DeterministicExecutor()
    detection = DetectionModule(
        frequency_threshold=frequency_threshold,
        frequency_window_seconds=frequency_window_seconds,
        role_violation_threshold=role_violation_threshold,
        role_violation_window_seconds=role_violation_window_seconds,
        clock=clock,
    )
    incidents = IncidentModule(throttle_seconds=throttle_seconds, clock=clock)
    control = ControlModule(
        detection,
        executor=executor,
        log_repository=logs,
        incident_module=incidents,
    )

    repositories = {}
    agents = {}
    for agent_id, role in [
        ("A1", "collector"),
        ("A2", "analyst"),
        ("A3", "writer"),
        ("A4", "executor"),
        ("A5", "admin"),
    ]:
        repo = MemoryAgentRepository()
        repositories[agent_id] = repo
        agents[agent_id] = BaseAgent(agent_id, role, control, repo=repo)

    return {
        "clock": clock,
        "logs": logs,
        "executor": executor,
        "detection": detection,
        "incidents": incidents,
        "control": control,
        "agents": agents,
        "repositories": repositories,
    }


def print_header(number, title, objective):
    print("\n" + "=" * 72)
    print(f"SCENARIO {number}: {title}")
    print("=" * 72)
    print(f"Objective: {objective}")


def print_result(label, value):
    print(f"{label}: {value}")


def latest_log(system):
    return system["logs"].entries[-1] if system["logs"].entries else {}


def count_logs(system, **filters):
    total = 0
    for entry in system["logs"].entries:
        if all(entry.get(key) == value for key, value in filters.items()):
            total += 1
    return total
