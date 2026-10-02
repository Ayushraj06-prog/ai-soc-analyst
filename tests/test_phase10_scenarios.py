import tempfile
import unittest
from pathlib import Path

from replay.runner import replay_scenario
from scenarios.registry import SCENARIOS
from scenarios.runner import run_scenario


class Phase10ScenarioTests(unittest.TestCase):
    def test_brute_force_pipeline_is_deterministic_and_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run_scenario(SCENARIOS["brute_force"], Path(directory) / "scenario.db", reset=True)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["counts"]["events"], 6)
        self.assertEqual(result["counts"]["incidents"], 1)
        self.assertEqual(result["investigation"]["status"], "completed")
        self.assertEqual(result["simulated_actions"], 0)

    def test_replay_entity_hashes_match(self):
        result = replay_scenario("brute_force")
        self.assertTrue(result["passed"], result)


if __name__ == "__main__":
    unittest.main()
