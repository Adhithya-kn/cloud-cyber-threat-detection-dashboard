"""
tests/test_multi_agent.py
=========================
Unit and integration tests for the CyberShield Multi-Agent SOC Architecture.
Verifies all 5 agents, rule divisions, step annotations, and orchestration.
"""

import unittest
import pandas as pd
from datetime import datetime, timezone

from orchestration import (
    get_orchestrator,
    MultiAgentSOCOrchestrator,
    IngestionSentinelAgent,
    HeuristicHunterAgent,
    AnomalyOracleAgent,
    CorrelationRiskAgent,
    AutonomousResponderAgent,
)


class TestMultiAgentSOC(unittest.TestCase):
    """Test suite for Multi-Agent SOC Autonomous Fleet."""

    def setUp(self):
        self.orchestrator = MultiAgentSOCOrchestrator()
        
        # Synthetic baseline dataframe
        now = datetime.now(timezone.utc)
        self.sample_logs = pd.DataFrame([
            {
                "timestamp": now.isoformat(),
                "source_ip": "192.168.1.50",
                "destination_ip": "10.0.0.1",
                "source_port": 50000 + i,
                "destination_port": 80,
                "protocol": "TCP",
                "user": "web-user",
                "event_type": "http_request",
                "status": "SUCCESS",
                "bytes": 1024,
                "packets": 5,
            }
            for i in range(15)
        ])

        # Attack logs: 10 failed logins for brute force
        self.brute_force_logs = pd.DataFrame([
            {
                "timestamp": now.isoformat(),
                "source_ip": "203.0.113.5",
                "destination_ip": "10.0.0.2",
                "source_port": 40000 + i,
                "destination_port": 22,
                "protocol": "SSH",
                "user": "root",
                "event_type": "failed_login",
                "status": "FAILURE",
                "bytes": 500,
                "packets": 3,
            }
            for i in range(10)
        ])

    def test_agent_alpha_ingestion_sentinel(self):
        agent = IngestionSentinelAgent()
        df_feat, res = agent.process(self.sample_logs)
        
        self.assertEqual(res.agent_id, "agent_alpha")
        self.assertEqual(res.status, "SUCCESS")
        self.assertGreater(len(df_feat), 0)
        self.assertIn("failed_login_count", df_feat.columns)
        self.assertIn("unique_ports_per_ip", df_feat.columns)
        self.assertIn("request_rate", df_feat.columns)
        self.assertIn("bytes_per_source", df_feat.columns)
        self.assertTrue(len(res.annotation) > 10)

    def test_agent_beta_heuristic_hunter(self):
        agent_alpha = IngestionSentinelAgent()
        df_feat, _ = agent_alpha.process(self.brute_force_logs)

        agent_beta = HeuristicHunterAgent()
        res = agent_beta.analyze(df_feat)

        self.assertEqual(res.agent_id, "agent_beta")
        self.assertEqual(res.status, "THREATS_DETECTED")
        self.assertGreater(len(res.detections), 0)
        self.assertEqual(res.detections[0]["threat_type"], "brute_force")
        self.assertTrue(len(res.annotation) > 10)

    def test_agent_delta_mitre_mapping(self):
        agent_delta = CorrelationRiskAgent()
        rule_detections = [
            {
                "threat_type": "brute_force",
                "source_ip": "203.0.113.5",
                "destination_ip": "10.0.0.2",
                "timestamp": pd.Timestamp.now(),
                "reason": "Excessive failed logins",
                "severity_candidate": "HIGH",
                "confidence": 0.95,
                "evidence_count": 10,
            }
        ]
        res = agent_delta.correlate(rule_detections, [])
        self.assertEqual(res.status, "THREATS_DETECTED")
        self.assertGreater(len(res.detections), 0)
        det = res.detections[0]
        self.assertEqual(det["mitre_technique_id"], "T1110")
        self.assertEqual(det["mitre_tactic"], "Credential Access")
        self.assertIn("severity", det)
        self.assertIn("risk_score", det)

    def test_agent_epsilon_playbook_generation(self):
        agent_epsilon = AutonomousResponderAgent()
        correlated = [
            {
                "source_ip": "203.0.113.5",
                "severity": "CRITICAL",
                "risk_score": 90,
                "threat_type": "brute_force",
                "mitre_technique_id": "T1110",
            }
        ]
        res = agent_epsilon.formulate_playbooks(correlated)
        self.assertEqual(res.status, "MITIGATIONS_DISPATCHED")
        self.assertEqual(len(res.playbooks), 1)
        pb = res.playbooks[0]
        self.assertEqual(pb["offending_ip"], "203.0.113.5")
        self.assertGreaterEqual(len(pb["actions"]), 2)
        # Check AWS WAF or iptables command presence
        has_firewall = any("FIREWALL_DROP" in a["type"] for a in pb["actions"])
        self.assertTrue(has_firewall)

    def test_end_to_end_orchestration_annotations(self):
        session = self.orchestrator.run_pipeline(
            self.brute_force_logs,
            dataset_name="Test-Brute-Force",
            persist_alerts=False
        )

        self.assertIsNotNone(session.session_id)
        self.assertEqual(len(session.step_annotations), 5)
        
        # Verify sequential step annotations
        for idx, step in enumerate(session.step_annotations):
            self.assertEqual(step.step_number, idx + 1)
            self.assertTrue(len(step.annotation) > 0)
            self.assertGreaterEqual(step.confidence, 0.0)
            self.assertLessEqual(step.confidence, 1.0)
            self.assertGreaterEqual(step.execution_time_ms, 0.0)

        self.assertGreater(session.total_threats, 0)
        self.assertGreater(len(session.playbooks), 0)
        self.assertIn("orchestration_confidence", session.consensus_summary)


if __name__ == "__main__":
    unittest.main()
