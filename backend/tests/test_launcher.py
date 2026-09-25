"""Tests for local service launcher command construction."""

import unittest
from unittest.mock import patch

from scripts import launcher


class LauncherTests(unittest.TestCase):
    @patch("scripts.launcher.time.sleep")
    @patch("scripts.launcher.subprocess.Popen")
    def test_capture_starts_as_a_python_module(self, popen, _sleep):
        process = popen.return_value
        process.poll.return_value = None

        with patch("scripts.launcher.port_is_available", return_value=True):
            launcher.start_service("capture")

        command = popen.call_args.args[0]
        self.assertEqual(command[1:], ["-m", "backend.app.workers.capture.pcap_watch"])

    @patch("scripts.launcher.time.sleep")
    @patch("scripts.launcher.subprocess.Popen")
    def test_rule_worker_starts_in_monitor_mode(self, popen, _sleep):
        process = popen.return_value
        process.poll.return_value = None

        launcher.start_service("rules")

        command = popen.call_args.args[0]
        self.assertEqual(command[-1], "monitor")

    @patch("scripts.launcher.time.sleep")
    @patch("scripts.launcher.subprocess.Popen")
    def test_detector_service_uses_the_selected_detector(self, popen, _sleep):
        process = popen.return_value
        process.poll.return_value = None

        launcher.start_service("detector-arp")

        command = popen.call_args.args[0]
        self.assertEqual(command[1:], ["-m", "backend.app.workers.detectors.json_watch", "--detector", "arp"])

    def test_pipeline_includes_detector_and_alert_workers(self):
        self.assertTrue({"detector-nmap", "detector-arp", "detector-icmp", "alerts"}.issubset(launcher.PIPELINE_SERVICES))
