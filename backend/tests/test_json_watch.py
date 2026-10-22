"""Tests for detector watcher selection and safe command construction."""

import tempfile
import unittest
from pathlib import Path

from backend.app.workers.detectors.json_watch import pending_json_files, run_detector


class JsonWatchTests(unittest.TestCase):
    def test_ignores_generated_alert_json_and_builds_detector_command(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "capture_parsed.json"
            source.write_text("[]", encoding="utf-8")
            (root / "capture_nmap_alerts.json").write_text("[]", encoding="utf-8")
            self.assertEqual(pending_json_files(root, set()), [source])
            commands = []

            def runner(command, **kwargs):
                commands.append((command, kwargs))
                return type("Result", (), {"returncode": 0})()

            run_detector("nmap", source, root / "out", runner)
            self.assertEqual(commands[0][0][1:3], ["-m", "backend.app.workers.detectors.nmap_detector"])
            self.assertFalse(commands[0][1].get("shell", False))
