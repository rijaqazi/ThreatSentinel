"""Unit tests for CVSS scoring without MongoDB."""

import unittest

from backend.app.services.scoring.cvss_service import calculate_cvss_score, process_alert


class CvssServiceTests(unittest.TestCase):
    def test_known_vector_produces_a_score(self):
        self.assertGreater(calculate_cvss_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 0)

    def test_alert_is_mapped_to_a_priority(self):
        result = process_alert({"_id": "1", "alert_type": "ARP MITM"})
        self.assertEqual(result["attack_type"], "ARP_MITM")
        self.assertIn(result["priority"], {"Critical", "High", "Medium", "Low"})

    def test_detector_style_alert_type_is_normalized(self):
        result = process_alert({"_id": "1", "alert_type": "ICMP Echo Request Flood"})
        self.assertEqual(result["attack_type"], "ICMP_ECHO_REQUEST_FLOOD")
        self.assertGreater(result["cvss_score"], 0)
