import unittest

from scenarios.scenario_1_normal import run as run_scenario_1
from scenarios.scenario_2_rbac_violation import run as run_scenario_2
from scenarios.scenario_3_behavior_drift import run as run_scenario_3
from scenarios.scenario_4_malicious_input import run as run_scenario_4


class TestOfficialScenarios(unittest.TestCase):
    def test_scenario_1_normal(self):
        system = run_scenario_1()
        self.assertEqual(len(system["logs"].entries), 5)

    def test_scenario_2_rbac_violation(self):
        system = run_scenario_2()
        self.assertEqual(system["logs"].entries[-1]["blocked_reason"], "RBAC_DENIED")

    def test_scenario_3_behavior_drift(self):
        system = run_scenario_3()
        self.assertEqual(system["logs"].entries[-2]["incident_action"], "LIMIT")
        self.assertEqual(system["logs"].entries[-1]["blocked_reason"], "THROTTLED")

    def test_scenario_4_malicious_input(self):
        system = run_scenario_4()
        self.assertEqual(system["logs"].entries[-1]["incident_action"], "ALERT")


if __name__ == "__main__":
    unittest.main()
