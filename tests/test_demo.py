import tempfile
import unittest
from pathlib import Path

from protocol_plaza.demo import run_demo


class DemoTests(unittest.TestCase):
    def test_demo_writes_story_and_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "demo"
            result = run_demo(root)
            self.assertFalse(result["relay_contains_first_message_plaintext"])
            self.assertEqual(len(result["messages"]["atlas"]), 2)
            self.assertEqual(len(result["messages"]["beacon"]), 2)
            story = (root / "story.md").read_text(encoding="utf-8")
            self.assertIn("Relay's limited view", story)
            self.assertIn("Quiet Workshop", story)
            self.assertIn("Verified locally", story)
            relay_db = root / "relay.db"
            self.assertNotIn(b"Quiet Workshop", relay_db.read_bytes())
            self.assertNotIn(b"collective_invitation", relay_db.read_bytes())

    def test_demo_crosses_http_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = run_demo(Path(temp) / "networked", transport="http")
            self.assertEqual(result["transport"], "http")
            self.assertFalse(result["relay_contains_first_message_plaintext"])
            self.assertEqual(result["relay"]["pending"], 0)


if __name__ == "__main__":
    unittest.main()
