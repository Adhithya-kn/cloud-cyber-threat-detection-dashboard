"""
tests/test_detection_rules.py
=============================
Unit tests for heuristic rule detection engines and risk scoring.
"""

import unittest
import pandas as pd
from datetime import datetime, timedelta, timezone

from detection.rules import detect_brute_force, detect_port_scan, detect_abnormal_traffic
from detection.risk_score import calculate_risk_score, assign_severity, enrich_detection


class TestDetectionRules(unittest.TestCase):
    """Test suite for detection heuristics and risk scoring."""

    def test_brute_force_rule(self):
        now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            {
                "timestamp": now + timedelta(seconds=i * 5),
                "source_ip": "198.51.100.1",
                "destination_ip": "10.0.0.1",
                "destination_port": 22,
                "event_type": "failed_login",
                "status": "FAILURE",
            }
            for i in range(8)
        ]
        df = pd.DataFrame(events)
        dets = detect_brute_force(df)
        self.assertGreater(len(dets), 0)
        self.assertEqual(dets[0]["threat_type"], "brute_force")
        self.assertEqual(dets[0]["source_ip"], "198.51.100.1")

    def test_port_scan_rule(self):
        now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            {
                "timestamp": now + timedelta(seconds=i),
                "source_ip": "198.51.100.2",
                "destination_ip": "10.0.0.1",
                "destination_port": 1000 + i,  # 20 unique ports
                "event_type": "connection_attempt",
                "status": "CLOSED",
            }
            for i in range(20)
        ]
        df = pd.DataFrame(events)
        dets = detect_port_scan(df)
        self.assertGreater(len(dets), 0)
        self.assertEqual(dets[0]["threat_type"], "port_scan")

    def test_abnormal_traffic_rule(self):
        now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            {
                "timestamp": now,
                "source_ip": "198.51.100.3",
                "destination_ip": "10.0.0.1",
                "destination_port": 443,
                "bytes": 15_000_000,  # 15 MB > 10 MB threshold
                "packets": 1000,
                "event_type": "data_transfer",
            }
        ]
        df = pd.DataFrame(events)
        dets = detect_abnormal_traffic(df)
        self.assertGreater(len(dets), 0)
        self.assertEqual(dets[0]["threat_type"], "abnormal_traffic")

    def test_risk_score_and_severity(self):
        detection = {
            "threat_type": "brute_force",
            "source_ip": "198.51.100.1",
            "confidence": 0.9,
            "evidence_count": 25,
            "destination_port": 22,
        }
        score, reasons = calculate_risk_score(detection)
        self.assertGreaterEqual(score, 65)  # 65 base + bonuses
        severity = assign_severity(score)
        self.assertIn(severity, ["HIGH", "CRITICAL"])

        enriched = enrich_detection(detection)
        self.assertEqual(enriched["risk_score"], score)
        self.assertEqual(enriched["severity"], severity)


if __name__ == "__main__":
    unittest.main()
