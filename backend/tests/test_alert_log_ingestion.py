"""Tests for incremental detector-log ingestion."""

import tempfile
import unittest
from pathlib import Path

from backend.app.workers.alert_log_ingestion import ingest_once


class FakeRepository:
    def __init__(self):
        self.alerts = []

    def upsert_alerts(self, alerts):
        self.alerts.extend(alerts)
        return len(alerts)


class AlertLogIngestionTests(unittest.TestCase):
    def test_imports_only_new_detector_log_lines_and_writes_canonical_log(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output_dir, merged_log = root / "detector_output", root / "alerts.log"
            output_dir.mkdir()
            source_log = output_dir / "nmap_alerts.log"
            source_log.write_text(
                "2026-08-18 12:00:00 - - SYN_SCAN ALERT from 192.0.2.8 | Target_IP: 192.0.2.1 | "
                "SRC_MAC: aa:bb:cc:dd:ee:ff | Claimed_MAC: N/A | Previous_MAC: N/A | "
                "Ports: 22, 80 | Ports Scanned: 2 | Start: 2026-08-18 11:59:58 | Duration: 2.0s\n",
                encoding="utf-8",
            )
            repository, offsets = FakeRepository(), {}

            self.assertEqual(ingest_once(output_dir, merged_log, offsets, repository), (1, 1))
            self.assertEqual(ingest_once(output_dir, merged_log, offsets, repository), (0, 0))
            self.assertEqual(repository.alerts[0]["alert_type"], "SYN_SCAN")
            self.assertIn("SYN_SCAN ALERT", merged_log.read_text(encoding="utf-8"))
