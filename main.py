"""
Clean demo launcher for the PFE security supervision project.

Use this file when rehearsing or presenting the project:

    python main.py list
    python main.py scenario5
    python main.py tests
"""

import argparse
import subprocess
import sys


DEMOS = {
    "scenario1": {
        "title": "Normal workflow",
        "command": [sys.executable, "-m", "scenarios.scenario_1_normal"],
        "display": "python -m scenarios.scenario_1_normal",
    },
    "scenario2": {
        "title": "RBAC violation",
        "command": [sys.executable, "-m", "scenarios.scenario_2_rbac_violation"],
        "display": "python -m scenarios.scenario_2_rbac_violation",
    },
    "scenario3": {
        "title": "Behavior drift",
        "command": [sys.executable, "-m", "scenarios.scenario_3_behavior_drift"],
        "display": "python -m scenarios.scenario_3_behavior_drift",
    },
    "scenario4": {
        "title": "Malicious input",
        "command": [sys.executable, "-m", "scenarios.scenario_4_malicious_input"],
        "display": "python -m scenarios.scenario_4_malicious_input",
    },
    "scenario5": {
        "title": "Coordinated cross-agent attack",
        "command": [sys.executable, "-m", "scenarios.scenario_5_coordinated_attack"],
        "display": "python -m scenarios.scenario_5_coordinated_attack",
    },
    "scenario6": {
        "title": "Role identity inconsistency",
        "command": [sys.executable, "-m", "scenarios.scenario_6_role_inconsistency"],
        "display": "python -m scenarios.scenario_6_role_inconsistency",
    },
}


def section(title):
    print("\n" + "=" * 72, flush=True)
    print(title, flush=True)
    print("=" * 72, flush=True)


def run_command(command):
    completed = subprocess.run(command, cwd=".", check=False)
    return completed.returncode


def list_demos():
    section("Available Demos")
    for key, demo in DEMOS.items():
        print(f"{key:<10} {demo['title']}")
        print(f"{'':<10} {demo['display']}")
    print()
    print("dashboard  Start the API with: python -m dashboard.api_server")
    print("frontend   Start the UI with: cd dashboard\\web ; npm run dev")
    print("tests      Run backend scenario/system checks")
    return 0


def run_tests():
    section("Running Project Tests")
    return run_command([sys.executable, "-m", "unittest", "tests.test_system", "tests.test_scenarios"])


def run_demo(name):
    demo = DEMOS[name]
    section(f"Running {name}: {demo['title']}")
    return run_command(demo["command"])


def main():
    parser = argparse.ArgumentParser(description="PFE security supervision demo launcher")
    parser.add_argument(
        "command",
        nargs="?",
        default="list",
        choices=[*DEMOS.keys(), "list", "tests"],
        help="Demo or utility command to run",
    )
    args = parser.parse_args()

    if args.command == "list":
        return list_demos()
    if args.command == "tests":
        return run_tests()
    return run_demo(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
