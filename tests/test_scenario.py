import tempfile
import unittest
from pathlib import Path

from protocol_plaza.scenario import run_full_scenario


class FullScenarioTests(unittest.TestCase):
    def test_full_acceptance_scenario(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = run_full_scenario(Path(temp) / "run")
            self.assertTrue(result["artifact_verified"])
            self.assertTrue(result["relay_discovery"]["integrity_verified"])
            self.assertTrue(result["relay_discovery"]["identity_pinned"])
            self.assertIsNone(result["relay_discovery"]["external_identity_provider"])
            self.assertFalse(any(result["relay_plaintext_checks"].values()))
            self.assertEqual(result["relay"]["pending"], 0)
            self.assertEqual(result["state"]["Atlas"]["epoch"], 2)
            self.assertEqual(result["state"]["Beacon"]["epoch"], 2)
            self.assertEqual(result["state"]["Cipher"]["epoch"], 1)
            self.assertEqual(result["state"]["Atlas"]["tasks"][0]["status"], "verified")
            self.assertEqual(result["state"]["Atlas"]["decisions"][0]["resolution"], "accept")
            self.assertEqual(result["state"]["Atlas"]["commitments"][0]["status"], "fulfilled")
            story = Path(result["story"]).read_text(encoding="utf-8")
            self.assertIn("Structured collective state", story)
            self.assertIn("advanced collective epoch to 2", story)


if __name__ == "__main__":
    unittest.main()
