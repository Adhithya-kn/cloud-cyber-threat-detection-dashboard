"""
orchestration/orchestrator.py
=============================
Multi-Agent Orchestrator & Execution Step Trace Annotator for CyberShield.

Coordinates the 5 autonomous SOC agents in a strict pipeline, logging and
annotating every single reasoning step, decision, and verification check.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from .agents import (
    AgentResult,
    IngestionSentinelAgent,
    HeuristicHunterAgent,
    AnomalyOracleAgent,
    CorrelationRiskAgent,
    AutonomousResponderAgent,
)
from utils.alert_manager import create_alert, add_alert, save_alerts

logger = logging.getLogger("orchestration.orchestrator")


@dataclass
class ExecutionStepAnnotation:
    """Detailed audit annotation for a single step in the multi-agent pipeline."""
    step_number: int
    timestamp: str
    agent_id: str
    agent_name: str
    agent_icon: str
    rule_category: str
    annotation: str
    status: str
    confidence: float
    execution_time_ms: float
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OrchestrationSession:
    """Complete multi-agent orchestration session result."""
    session_id: str
    timestamp: str
    dataset_name: str
    total_events: int
    total_threats: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    total_latency_ms: float
    step_annotations: List[ExecutionStepAnnotation]
    enriched_df: pd.DataFrame
    alerts_df: pd.DataFrame
    playbooks: List[Dict[str, Any]]
    agent_stats: Dict[str, Dict[str, Any]]
    consensus_summary: Dict[str, Any]


class MultiAgentSOCOrchestrator:
    """
    Central Orchestrator coordinating the CyberShield Multi-Agent Fleet.
    Ensures every processing step is thoroughly verified, annotated, and auditable.
    """

    def __init__(self):
        # Instantiate the 5 specialized SOC agents
        self.agent_alpha = IngestionSentinelAgent()
        self.agent_beta = HeuristicHunterAgent()
        self.agent_gamma = AnomalyOracleAgent()
        self.agent_delta = CorrelationRiskAgent()
        self.agent_epsilon = AutonomousResponderAgent()

    def run_pipeline(
        self,
        df_raw: pd.DataFrame,
        dataset_name: str = "Cloud Telemetry Stream",
        persist_alerts: bool = True
    ) -> OrchestrationSession:
        """
        Executes the entire multi-agent detection, ML, correlation, and response cycle.
        Annotates and verifies each step sequentially.
        """
        session_id = f"SOC-SES-{uuid.uuid4().hex[:8].upper()}"
        session_start = time.perf_counter()
        session_time = datetime.now(timezone.utc).isoformat()
        step_annotations: List[ExecutionStepAnnotation] = []

        logger.info(f"Starting Multi-Agent Orchestration Session {session_id} on '{dataset_name}'")

        # ── Step 1: Agent-Alpha (Ingestion Sentinel) ──────────────────────────
        df_feat, res_alpha = self.agent_alpha.process(df_raw)
        step_annotations.append(ExecutionStepAnnotation(
            step_number=1,
            timestamp=datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3],
            agent_id=res_alpha.agent_id,
            agent_name=res_alpha.agent_name,
            agent_icon=self.agent_alpha.icon,
            rule_category="Telemetry Ingestion & Schema Normalization",
            annotation=res_alpha.annotation,
            status=res_alpha.status,
            confidence=res_alpha.confidence,
            execution_time_ms=res_alpha.execution_time_ms,
            evidence=res_alpha.evidence,
        ))

        # ── Step 2: Agent-Beta (Heuristic Hunter) ─────────────────────────────
        res_beta = self.agent_beta.analyze(df_feat)
        step_annotations.append(ExecutionStepAnnotation(
            step_number=2,
            timestamp=datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3],
            agent_id=res_beta.agent_id,
            agent_name=res_beta.agent_name,
            agent_icon=self.agent_beta.icon,
            rule_category="Deterministic Rule-Based Attack Scanning",
            annotation=res_beta.annotation,
            status=res_beta.status,
            confidence=res_beta.confidence,
            execution_time_ms=res_beta.execution_time_ms,
            evidence=res_beta.evidence,
        ))

        # ── Step 3: Agent-Gamma (Anomaly Oracle) ──────────────────────────────
        res_gamma = self.agent_gamma.analyze(df_feat)
        step_annotations.append(ExecutionStepAnnotation(
            step_number=3,
            timestamp=datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3],
            agent_id=res_gamma.agent_id,
            agent_name=res_gamma.agent_name,
            agent_icon=self.agent_gamma.icon,
            rule_category="Unsupervised Isolation Forest Outlier Inference",
            annotation=res_gamma.annotation,
            status=res_gamma.status,
            confidence=res_gamma.confidence,
            execution_time_ms=res_gamma.execution_time_ms,
            evidence=res_gamma.evidence,
        ))

        # ── Step 4: Agent-Delta (Correlation & MITRE Correlator) ──────────────
        res_delta = self.agent_delta.correlate(
            rule_detections=res_beta.detections,
            ml_detections=res_gamma.detections,
        )
        step_annotations.append(ExecutionStepAnnotation(
            step_number=4,
            timestamp=datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3],
            agent_id=res_delta.agent_id,
            agent_name=res_delta.agent_name,
            agent_icon=self.agent_delta.icon,
            rule_category="Evidence Fusion, MITRE Mapping & Risk Scoring",
            annotation=res_delta.annotation,
            status=res_delta.status,
            confidence=res_delta.confidence,
            execution_time_ms=res_delta.execution_time_ms,
            evidence=res_delta.evidence,
        ))

        # ── Step 5: Agent-Epsilon (Autonomous Responder) ──────────────────────
        res_epsilon = self.agent_epsilon.formulate_playbooks(res_delta.detections)
        step_annotations.append(ExecutionStepAnnotation(
            step_number=5,
            timestamp=datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3],
            agent_id=res_epsilon.agent_id,
            agent_name=res_epsilon.agent_name,
            agent_icon=self.agent_epsilon.icon,
            rule_category="Autonomous Cloud Mitigation & Containment Playbooks",
            annotation=res_epsilon.annotation,
            status=res_epsilon.status,
            confidence=res_epsilon.confidence,
            execution_time_ms=res_epsilon.execution_time_ms,
            evidence=res_epsilon.evidence,
        ))

        # ── Format Final Alerts DataFrame ────────────────────────────────────
        alerts_tracker = pd.DataFrame()
        raw_alert_dicts = []
        for det in res_delta.detections:
            try:
                rec = create_alert(det)
                alerts_tracker = add_alert(rec, alerts_tracker)
            except Exception:
                raw_alert_dicts.append(det)

        if not alerts_tracker.empty:
            alerts_final = alerts_tracker
        elif raw_alert_dicts:
            alerts_final = pd.DataFrame(raw_alert_dicts)
        else:
            alerts_final = pd.DataFrame(columns=[
                "alert_id", "timestamp", "threat_type", "source_ip",
                "destination_ip", "severity", "risk_score", "status",
                "reason", "suggested_action", "mitre_tactic", "mitre_technique_id"
            ])

        # Optionally persist
        if persist_alerts and not alerts_final.empty:
            try:
                save_alerts(alerts_final, "data/alerts.csv")
            except Exception as e:
                logger.warning(f"Could not persist alerts to CSV: {e}")

        total_latency = (time.perf_counter() - session_start) * 1000

        # Severities
        crit_c = int((alerts_final["severity"].str.upper() == "CRITICAL").sum()) if not alerts_final.empty and "severity" in alerts_final.columns else 0
        high_c = int((alerts_final["severity"].str.upper() == "HIGH").sum()) if not alerts_final.empty and "severity" in alerts_final.columns else 0
        med_c  = int((alerts_final["severity"].str.upper() == "MEDIUM").sum()) if not alerts_final.empty and "severity" in alerts_final.columns else 0
        low_c  = int((alerts_final["severity"].str.upper() == "LOW").sum()) if not alerts_final.empty and "severity" in alerts_final.columns else 0

        agent_stats = {
            "agent_alpha": {
                "name": self.agent_alpha.name,
                "role": self.agent_alpha.role,
                "icon": self.agent_alpha.icon,
                "last_latency_ms": self.agent_alpha.last_latency_ms,
                "status": self.agent_alpha.last_status,
                "rules": self.agent_alpha.assigned_rules,
            },
            "agent_beta": {
                "name": self.agent_beta.name,
                "role": self.agent_beta.role,
                "icon": self.agent_beta.icon,
                "last_latency_ms": self.agent_beta.last_latency_ms,
                "status": self.agent_beta.last_status,
                "threats_found": self.agent_beta.total_threats_found,
                "rules": self.agent_beta.assigned_rules,
            },
            "agent_gamma": {
                "name": self.agent_gamma.name,
                "role": self.agent_gamma.role,
                "icon": self.agent_gamma.icon,
                "last_latency_ms": self.agent_gamma.last_latency_ms,
                "status": self.agent_gamma.last_status,
                "threats_found": self.agent_gamma.total_threats_found,
                "rules": self.agent_gamma.assigned_rules,
            },
            "agent_delta": {
                "name": self.agent_delta.name,
                "role": self.agent_delta.role,
                "icon": self.agent_delta.icon,
                "last_latency_ms": self.agent_delta.last_latency_ms,
                "status": self.agent_delta.last_status,
                "threats_found": self.agent_delta.total_threats_found,
                "rules": self.agent_delta.assigned_rules,
            },
            "agent_epsilon": {
                "name": self.agent_epsilon.name,
                "role": self.agent_epsilon.role,
                "icon": self.agent_epsilon.icon,
                "last_latency_ms": self.agent_epsilon.last_latency_ms,
                "status": self.agent_epsilon.last_status,
                "playbooks_count": len(res_epsilon.playbooks),
                "rules": self.agent_epsilon.assigned_rules,
            },
        }

        consensus_summary = {
            "total_threats": len(alerts_final),
            "consensus_ips": res_delta.evidence.get("multi_agent_consensus_ips", []),
            "mitre_tactics": res_delta.evidence.get("tactics_identified", []),
            "playbooks_generated": len(res_epsilon.playbooks),
            "orchestration_confidence": round(float(np.mean([
                res_alpha.confidence, res_beta.confidence,
                res_gamma.confidence, res_delta.confidence,
                res_epsilon.confidence
            ])), 3),
        }

        return OrchestrationSession(
            session_id=session_id,
            timestamp=session_time,
            dataset_name=dataset_name,
            total_events=len(df_feat),
            total_threats=len(alerts_final),
            critical_count=crit_c,
            high_count=high_c,
            medium_count=med_c,
            low_count=low_c,
            total_latency_ms=round(total_latency, 2),
            step_annotations=step_annotations,
            enriched_df=df_feat,
            alerts_df=alerts_final,
            playbooks=res_epsilon.playbooks,
            agent_stats=agent_stats,
            consensus_summary=consensus_summary,
        )


# Global singleton orchestrator
_default_orchestrator: Optional[MultiAgentSOCOrchestrator] = None

def get_orchestrator() -> MultiAgentSOCOrchestrator:
    """Retrieve or create the global MultiAgentSOCOrchestrator singleton."""
    global _default_orchestrator
    if _default_orchestrator is None:
        _default_orchestrator = MultiAgentSOCOrchestrator()
    return _default_orchestrator
