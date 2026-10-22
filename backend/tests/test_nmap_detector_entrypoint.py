"""Tests for the canonical Nmap detector entry point."""

import unittest

from backend.app.workers.detectors.nmap_detector import DETECTOR_ENGINE, run_detector


class NmapDetectorEntrypointTests(unittest.TestCase):
    def test_delegates_without_a_shell(self):
        commands = []

        def runner(command, **kwargs):
            commands.append((command, kwargs))
            return type("Result", (), {"returncode": 0})()

        result = run_detector(["sample.json", "--log", "output.log"], runner)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(commands[0][0][1], str(DETECTOR_ENGINE))
        self.assertFalse(commands[0][1].get("shell", False))
