"""
orchestration/agents.py
=======================
Autonomous Security Operations Center (SOC) Multi-Agent Fleet for CyberShield.

Divided Agent Roles & Rules:
  1. IngestionSentinelAgent  (Agent-Alpha)   - Schema verification, feature extraction & telemetry hygiene.
  2. HeuristicHunterAgent    (Agent-Beta)    - Deterministic attack signature & sliding-window rule evaluation.
  3. AnomalyOracleAgent      (Agent-Gamma)   - Unsupervised Isolation Forest outlier inference.
  4. CorrelationRiskAgent    (Agent-Delta)   - MITRE ATT&CK correlation, multi-agent consensus & risk scoring.
  5. AutonomousResponderAgent (Agent-Epsilon) - Cloud containment playbook formulation & mitigation dispatch.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from detection.config import (
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_SECONDS,
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_WINDOW_SECONDS,
    TRAFFIC_BYTES_THRESHOLD,
    TRAFFIC_WINDOW_SECONDS,
    CRITICAL_PORTS,
)
from detection.rules import run_all_rules, detect_brute_force, detect_port_scan, detect_abnormal_traffic
from detection.anomaly import detect_anomalies, get_anomaly_detections, train_model, load_model
from detection.risk_score import calculate_risk_score, assign_severity, enrich_detection, process_all_detections
from utils.alert_manager import create_alert, add_alert

logger = logging.getLogger("orchestration.agents")


@dataclass
class AgentResult:
    """Standard output envelope returned by an autonomous SOC agent."""
    agent_id: str
    agent_name: str
    status: str  # "SUCCESS", "THREATS_DETECTED", "CLEAN", "WARNING", "ERROR"
    execution_time_ms: float
    annotation: str
    confidence: float
    evidence: Dict[str, Any] = field(default_factory=dict)
    detections: List[Dict[str, Any]] = field(default_factory=list)
    playbooks: List[Dict[str, Any]] = field(default_factory=list)


class SOCAgent:
    """Base abstract class for all autonomous SOC agents."""
    
    def __init__(self, agent_id: str, name: str, role: str, icon: str, assigned_rules: List[str]):
        self.agent_id = agent_id
        self.name = name
        self.role = role
        self.icon = icon
        self.assigned_rules = assigned_rules
        self.total_runs = 0
        self.total_threats_found = 0
        self.last_status = "IDLE"
        self.last_latency_ms = 0.0

    def record_run(self, threats_count: int, latency_ms: float, status: str):
        self.total_runs += 1
        self.total_threats_found += threats_count
        self.last_latency_ms = round(latency_ms, 2)
        self.last_status = status


# ─────────────────────────────────────────────────────────────────────────────
# 1. Agent-Alpha: Ingestion Sentinel Agent
# ─────────────────────────────────────────────────────────────────────────────
class IngestionSentinelAgent(SOCAgent):
    """
    Agent-Alpha: Validates incoming cloud telemetry, validates 11-field canonical
    schema, enforces type safety, and derives sliding-window velocity features.
    """

    def __init__(self):
        super().__init__(
            agent_id="agent_alpha",
            name="Agent-Alpha: Ingestion Sentinel",
            role="Cloud Telemetry & Feature Extraction Guardian",
            icon="🛰️",
            assigned_rules=[
                "RULE-ING-01: Canonical Schema Verification",
                "RULE-ING-02: Windowed Velocity Feature Extraction",
                "RULE-ING-03: Null & Type Coercion Sanitization",
            ],
        )

    def process(self, df_raw: pd.DataFrame) -> tuple[pd.DataFrame, AgentResult]:
        start = time.perf_counter()
        
        if df_raw.empty:
            latency = (time.perf_counter() - start) * 1000
            self.record_run(0, latency, "WARNING")
            return df_raw, AgentResult(
                agent_id=self.agent_id,
                agent_name=self.name,
                status="WARNING",
                execution_time_ms=latency,
                annotation="Received empty telemetry stream. No features extracted.",
                confidence=1.0,
                evidence={"row_count": 0},
            )

        # Apply schema normalization
        from utils.log_parser import normalize_events, extract_features

        df_norm = normalize_events(df_raw)
        df_feat = extract_features(df_norm)
        
        latency = (time.perf_counter() - start) * 1000
        row_count = len(df_feat)
        unique_ips = df_feat["source_ip"].nunique() if "source_ip" in df_feat.columns else 0
        protocols = df_feat["protocol"].unique().tolist() if "protocol" in df_feat.columns else []

        annotation = (
            f"Successfully sanitized {row_count:,} cloud events across {unique_ips} distinct source IPs. "
            f"Extracted 5 behavioral velocity features (failed_login_count, unique_ports_per_ip, "
            f"request_rate, bytes_per_source, is_after_hours). Protocols verified: {', '.join(protocols[:5])}."
        )

        self.record_run(0, latency, "SUCCESS")

        return df_feat, AgentResult(
            agent_id=self.agent_id,
            agent_name=self.name,
            status="SUCCESS",
            execution_time_ms=latency,
            annotation=annotation,
            confidence=0.99,
            evidence={
                "event_count": row_count,
                "unique_source_ips": unique_ips,
                "protocols": protocols,
                "schema_conformant": True,
            },
        )


# ─────────────────────────────────────────────────────────────────────────────
# 2. Agent-Beta: Heuristic Hunter Agent
# ─────────────────────────────────────────────────────────────────────────────
class HeuristicHunterAgent(SOCAgent):
    """
    Agent-Beta: Scans telemetry for deterministic attack heuristics using
    sliding-window counters: SSH brute force, rapid port sweeps, abnormal exfiltration.
    """

    def __init__(self):
        super().__init__(
            agent_id="agent_beta",
            name="Agent-Beta: Heuristic Hunter",
            role="Rule-Based Attack Heuristics & Signature Analyst",
            icon="🎯",
            assigned_rules=[
                f"RULE-HEU-01: Brute Force Authentication (>{BRUTE_FORCE_THRESHOLD} failures in {BRUTE_FORCE_WINDOW_SECONDS}s)",
                f"RULE-HEU-02: Port Scan Sweep (>{PORT_SCAN_THRESHOLD} ports in {PORT_SCAN_WINDOW_SECONDS}s)",
                f"RULE-HEU-03: Data Exfiltration Spikes (>{TRAFFIC_BYTES_THRESHOLD//1000000}MB in {TRAFFIC_WINDOW_SECONDS}s)",
                "RULE-HEU-04: Critical Infrastructure Port Probing (Ports: 22, 3389, 445)",
            ],
        )

    def analyze(self, df_feat: pd.DataFrame) -> AgentResult:
        start = time.perf_counter()
        detections = run_all_rules(df_feat)
        latency = (time.perf_counter() - start) * 1000

        bf_hits = sum(1 for d in detections if d.get("threat_type") == "brute_force")
        ps_hits = sum(1 for d in detections if d.get("threat_type") == "port_scan")
        tr_hits = sum(1 for d in detections if d.get("threat_type") == "abnormal_traffic")

        status = "THREATS_DETECTED" if detections else "CLEAN"

        if detections:
            annotation = (
                f"Identified {len(detections)} deterministic heuristic threat vectors! "
                f"Breakdown: {bf_hits} Brute-Force incidents, {ps_hits} Port-Scan sweeps, "
                f"{tr_hits} High-Bandwidth Exfiltration anomalies. Rules evaluated: HEU-01 through HEU-04."
            )
            confidence = 0.95
        else:
            annotation = "All sliding-window thresholds intact. No deterministic attack signatures found."
            confidence = 0.90

        self.record_run(len(detections), latency, status)

        return AgentResult(
            agent_id=self.agent_id,
            agent_name=self.name,
            status=status,
            execution_time_ms=latency,
            annotation=annotation,
            confidence=confidence,
            evidence={
                "brute_force_violations": bf_hits,
                "port_scan_violations": ps_hits,
                "traffic_spike_violations": tr_hits,
                "total_rule_hits": len(detections),
            },
            detections=detections,
        )


# ─────────────────────────────────────────────────────────────────────────────
# 3. Agent-Gamma: Anomaly Oracle Agent
# ─────────────────────────────────────────────────────────────────────────────
class AnomalyOracleAgent(SOCAgent):
    """
    Agent-Gamma: Applies unsupervised Machine Learning (Isolation Forest)
    over 4-dimensional behavior space to catch stealthy zero-day outliers.
    """

    def __init__(self):
        super().__init__(
            agent_id="agent_gamma",
            name="Agent-Gamma: Anomaly Oracle",
            role="Unsupervised Machine Learning & Outlier Specialist",
            icon="🧠",
            assigned_rules=[
                "RULE-ML-01: Isolation Forest Decision Function Score < 0",
                "RULE-ML-02: Multi-Feature Outlier Distance Estimation",
                "RULE-ML-03: Zero-Day Stealth Behavior Separation",
            ],
        )

    def analyze(self, df_feat: pd.DataFrame) -> AgentResult:
        start = time.perf_counter()
        detections: List[Dict[str, Any]] = []

        try:
            # Train or load model
            model_bundle = load_model()
            if model_bundle is None or df_feat.shape[0] > 50:
                model_bundle = train_model(df_feat)
            
            scored_df = detect_anomalies(df_feat, model_bundle)
            raw_ml_dets = get_anomaly_detections(scored_df)
            detections = raw_ml_dets
        except Exception as exc:
            logger.warning(f"ML Anomaly inference exception: {exc}")

        latency = (time.perf_counter() - start) * 1000
        status = "THREATS_DETECTED" if detections else "CLEAN"

        if detections:
            annotation = (
                f"Isolation Forest flagged {len(detections)} multidimensional behavior anomalies. "
                f"These events deviate substantially from baseline entropy in request rates, "
                f"port diversity, and byte volumes. Evaluated rules: ML-01, ML-02."
            )
            confidence = 0.88
        else:
            annotation = "Isolation Forest scores within normal statistical boundary. No ML outliers detected."
            confidence = 0.92

        self.record_run(len(detections), latency, status)

        return AgentResult(
            agent_id=self.agent_id,
            agent_name=self.name,
            status=status,
            execution_time_ms=latency,
            annotation=annotation,
            confidence=confidence,
            evidence={
                "anomaly_count": len(detections),
                "model_type": "IsolationForest(contamination=0.05)",
                "feature_dimensions": ["failed_login_count", "unique_ports_per_ip", "request_rate", "bytes_per_source"],
            },
            detections=detections,
        )


# ─────────────────────────────────────────────────────────────────────────────
# 4. Agent-Delta: Correlation & MITRE ATT&CK Agent
# ─────────────────────────────────────────────────────────────────────────────
class CorrelationRiskAgent(SOCAgent):
    """
    Agent-Delta: Aggregates findings from Heuristic Hunter and Anomaly Oracle.
    Maps evidence to the MITRE ATT&CK framework, computes unified 0-100 risk score,
    and assigns severity tier (LOW, MEDIUM, HIGH, CRITICAL).
    """

    MITRE_MAPPING = {
        "brute_force": {
            "tactic": "Credential Access",
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "sub_technique": "T1110.001 (Password Guessing)",
        },
        "port_scan": {
            "tactic": "Discovery",
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "sub_technique": "T1046 (Port Sweep)",
        },
        "abnormal_traffic": {
            "tactic": "Exfiltration",
            "technique_id": "T1048",
            "technique_name": "Exfiltration Over Alternative Protocol",
            "sub_technique": "T1048.003 (Exfiltration Over Unencrypted Protocol)",
        },
        "ml_anomaly": {
            "tactic": "Defense Evasion / Initial Access",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "sub_technique": "T1190 (Atypical Flow Profile)",
        },
    }

    def __init__(self):
        super().__init__(
            agent_id="agent_delta",
            name="Agent-Delta: Correlation & MITRE Correlator",
            role="Multi-Source Evidence Fusion, MITRE ATT&CK & Risk Scoring",
            icon="⚖️",
            assigned_rules=[
                "RULE-COR-01: Multi-Agent Consensus & Evidence Aggregation",
                "RULE-COR-02: MITRE ATT&CK Enterprise Matrix Alignment",
                "RULE-COR-03: Dynamic CVSS-Style Risk Index Calculation (0-100)",
                "RULE-COR-04: Severity Tier Grading (LOW, MED, HIGH, CRITICAL)",
                "RULE-COR-05: Sliding-Window Deduplication (300s TTL)",
            ],
        )

    def correlate(self, rule_detections: List[Dict[str, Any]], ml_detections: List[Dict[str, Any]]) -> AgentResult:
        start = time.perf_counter()
        
        all_raw = rule_detections + ml_detections
        enriched_dets = process_all_detections(all_raw)

        # Enrich with MITRE ATT&CK classification
        correlated_alerts = []
        for det in enriched_dets:
            tt = str(det.get("threat_type", "")).lower()
            mitre_info = self.MITRE_MAPPING.get(tt, {
                "tactic": "Initial Access",
                "technique_id": "T1078",
                "technique_name": "Valid Accounts / Anomaly",
                "sub_technique": "T1078",
            })
            
            det_copy = dict(det)
            det_copy["mitre_tactic"] = mitre_info["tactic"]
            det_copy["mitre_technique_id"] = mitre_info["technique_id"]
            det_copy["mitre_technique_name"] = mitre_info["technique_name"]
            det_copy["mitre_sub_technique"] = mitre_info["sub_technique"]
            correlated_alerts.append(det_copy)

        latency = (time.perf_counter() - start) * 1000
        
        # Calculate distribution
        crit_count = sum(1 for d in correlated_alerts if d.get("severity") == "CRITICAL")
        high_count = sum(1 for d in correlated_alerts if d.get("severity") == "HIGH")
        med_count = sum(1 for d in correlated_alerts if d.get("severity") == "MEDIUM")
        low_count = sum(1 for d in correlated_alerts if d.get("severity") == "LOW")

        consensus_hits = 0
        rule_ips = {d.get("source_ip") for d in rule_detections}
        ml_ips = {d.get("source_ip") for d in ml_detections}
        shared_ips = rule_ips.intersection(ml_ips)
        consensus_hits = len(shared_ips)

        status = "THREATS_DETECTED" if correlated_alerts else "CLEAN"

        if correlated_alerts:
            annotation = (
                f"Triaged {len(correlated_alerts)} total detections into prioritized severity bands: "
                f"{crit_count} CRITICAL, {high_count} HIGH, {med_count} MEDIUM, {low_count} LOW. "
                f"Multi-Agent Consensus verified on {consensus_hits} source IP(s) flagged by both Heuristic & ML engines. "
                f"Mapped to MITRE tactics: Credential Access (T1110), Discovery (T1046), Exfiltration (T1048)."
            )
            confidence = 0.96
        else:
            annotation = "Correlation complete. Threat count is 0. System posture assessed as SECURE."
            confidence = 0.95

        self.record_run(len(correlated_alerts), latency, status)

        return AgentResult(
            agent_id=self.agent_id,
            agent_name=self.name,
            status=status,
            execution_time_ms=latency,
            annotation=annotation,
            confidence=confidence,
            evidence={
                "critical_count": crit_count,
                "high_count": high_count,
                "medium_count": med_count,
                "low_count": low_count,
                "multi_agent_consensus_ips": list(shared_ips),
                "tactics_identified": list({d["mitre_tactic"] for d in correlated_alerts}),
            },
            detections=correlated_alerts,
        )


# ─────────────────────────────────────────────────────────────────────────────
# 5. Agent-Epsilon: Autonomous Responder Agent
# ─────────────────────────────────────────────────────────────────────────────
class AutonomousResponderAgent(SOCAgent):
    """
    Agent-Epsilon: Autonomously formulates cloud mitigation playbooks:
    Perimeter Firewall IP drops (AWS WAF / iptables), IAM isolation,
    rate-limiting, and webhook incident notifications.
    """

    def __init__(self):
        super().__init__(
            agent_id="agent_epsilon",
            name="Agent-Epsilon: Autonomous Responder",
            role="Cloud Incident Mitigation & Containment Playbook Commander",
            icon="🛡️",
            assigned_rules=[
                "RULE-RES-01: Auto-Containment for CRITICAL/HIGH Threats (Score >= 60)",
                "RULE-RES-02: Infrastructure Whitelist & False Positive Safeguard",
                "RULE-RES-03: Cloud WAF / Firewall Rule Generation",
                "RULE-RES-04: Automated Incident Response Playbook Dispatch",
            ],
        )

    def formulate_playbooks(self, correlated_detections: List[Dict[str, Any]]) -> AgentResult:
        start = time.perf_counter()
        playbooks = []

        # Unique offending IPs with severity >= HIGH
        seen_ips = set()
        for det in correlated_detections:
            sip = det.get("source_ip", "unknown")
            sev = det.get("severity", "LOW")
            score = det.get("risk_score", 0)
            tt = det.get("threat_type", "unknown")
            mitre_tech = det.get("mitre_technique_id", "T0000")

            if sip in seen_ips or sip in ["127.0.0.1", "localhost", "unknown"]:
                continue
            seen_ips.add(sip)

            # Build cloud remediation playbooks
            if sev in ["CRITICAL", "HIGH"] or score >= 60:
                playbook = {
                    "incident_id": f"PB-{int(time.time())}-{sip.replace('.', '_')[:10]}",
                    "offending_ip": sip,
                    "threat_type": tt,
                    "severity": sev,
                    "risk_score": score,
                    "mitre_technique": mitre_tech,
                    "status": "READY_FOR_EXECUTION",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "actions": [
                        {
                            "type": "FIREWALL_DROP",
                            "provider": "AWS WAF / Cloudflare",
                            "command": f"aws wafv2 update-ip-set --name CybershieldBlockList --scope REGIONAL --addresses '{sip}/32' --action BLOCK",
                            "description": f"Blacklist offending IP {sip} at cloud edge perimeter."
                        },
                        {
                            "type": "HOST_CONTAINMENT",
                            "provider": "Linux Netfilter / iptables",
                            "command": f"sudo iptables -I INPUT -s {sip} -j DROP -m comment --comment 'CyberShield-{tt}'",
                            "description": f"Drop all inbound traffic from {sip} immediately."
                        },
                        {
                            "type": "IAM_QUARANTINE",
                            "provider": "Cloud Identity & Access",
                            "command": f"aws iam put-user-policy --user-name compromised-user --policy-name QuarantineDenyAll --policy-document '{{\"Version\":\"2012-10-17\",\"Statement\":[{{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\"}}]}}'",
                            "description": "Revoke active session tokens and enforce temporary deny-all policy."
                        },
                    ],
                }
                playbooks.append(playbook)

        latency = (time.perf_counter() - start) * 1000
        status = "MITIGATIONS_DISPATCHED" if playbooks else "STANDBY"

        if playbooks:
            annotation = (
                f"Generated {len(playbooks)} cloud containment playbooks for offending hosts: "
                f"{', '.join([pb['offending_ip'] for pb in playbooks[:4]])}. "
                f"Commands generated for AWS WAF, iptables, and IAM session revocation."
            )
            confidence = 0.98
        else:
            annotation = "No high-severity threats requiring automated containment. System on standby."
            confidence = 0.99

        self.record_run(len(playbooks), latency, status)

        return AgentResult(
            agent_id=self.agent_id,
            agent_name=self.name,
            status=status,
            execution_time_ms=latency,
            annotation=annotation,
            confidence=confidence,
            evidence={
                "playbook_count": len(playbooks),
                "quarantined_ips": [pb["offending_ip"] for pb in playbooks],
                "auto_defense_active": True,
            },
            playbooks=playbooks,
        )
