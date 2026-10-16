"""
utils/pipeline.py
-----------------
Unified processing and data loading pipeline for CyberShield.
Ensures session data is always available across all pages, supporting:
- Log ingestion & normalization
- Dual-layer threat detection (Rules + Isolation Forest ML)
- CVSS-aligned risk scoring
- Alert lifecycle management & MITRE ATT&CK enrichment
"""

import os
import logging
import streamlit as st
import pandas as pd
import numpy as np

from utils.log_parser import normalize_events, extract_features, load_data
from detection.rules import run_all_rules
from detection.anomaly import train_model, detect_anomalies, get_anomaly_detections
from detection.risk_score import process_all_detections
from utils.alert_manager import create_alert, add_alert, save_alerts, load_alerts

logger = logging.getLogger(__name__)

# MITRE ATT&CK Mapping
MITRE_MAP = {
    "brute_force": "T1110 — Brute Force (Credential Access)",
    "port_scan": "T1046 — Network Service Discovery (Discovery)",
    "abnormal_traffic": "T1048 — Exfiltration Over Alternative Protocol (Exfiltration)",
    "ml_anomaly": "T1078 — Behavioral Anomaly / Anomaly in Access (Defense Evasion)",
    "ransomware_indicator": "T1486 — Data Encrypted for Impact (Impact)",
    "data_exfiltration": "T1567 — Exfiltration to Cloud Storage (Exfiltration)",
}

AVAILABLE_DATASETS = {
    "🟢 Dataset 1: Normal Cloud Activity (Routine Baseline)": "data/dataset_1_normal_baseline.csv",
    "🚨 Dataset 2: Active Cyber Attack Incidents (Intrusions & Threats)": "data/demo_security_logs.csv",
}

DEFAULT_DATASET_NAME = "🚨 Dataset 2: Active Cyber Attack Incidents (Intrusions & Threats)"
DEFAULT_DATASET_PATH = "data/demo_security_logs.csv"


def run_pipeline(df_input: pd.DataFrame, source_name: str = "Uploaded Dataset") -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Executes end-to-end log parsing, feature extraction, rule & ML detection,
    risk scoring, and alert generation on any DataFrame.
    """
    # 1. Normalize events
    try:
        df_norm = normalize_events(df_input)
    except Exception as e:
        logger.warning(f"Normalization failed: {e}")
        df_norm = df_input.copy()

    # 2. Extract features
    try:
        df_feat = extract_features(df_norm)
    except Exception as e:
        logger.warning(f"Feature extraction failed: {e}")
        df_feat = df_norm.copy()

    # 3. Deterministic Rules
    rule_dets = []
    try:
        rule_dets = run_all_rules(df_feat)
    except Exception as e:
        logger.warning(f"Rule detection error: {e}")

    # 4. ML Anomaly Detection (Isolation Forest)
    ml_dets = []
    try:
        has_suspicious_features = (
            (df_feat.get("failed_login_count", pd.Series([0])) > 0).any() or
            (df_feat.get("unique_ports_per_ip", pd.Series([0])) > 2).any() or
            (df_feat.get("request_rate", pd.Series([0])) > 5).any() or
            (df_feat.get("bytes_per_source", pd.Series([0])) > 50000).any()
        )
        if has_suspicious_features:
            bundle = train_model(df_feat)
            scored = detect_anomalies(df_feat, bundle)
            candidate_rows = scored[
                (scored["anomaly_flag"] == True) &
                (
                    (scored["failed_login_count"] > 0) |
                    (scored["unique_ports_per_ip"] > 2) |
                    (scored["request_rate"] > 5) |
                    (scored["bytes_per_source"] > 50000)
                )
            ]
            ml_dets = get_anomaly_detections(candidate_rows)
    except Exception as e:
        logger.warning(f"ML anomaly error: {e}")

    # 5. Composite Risk Scoring & CVSS Enrichment
    all_dets = rule_dets + ml_dets
    try:
        enriched = process_all_detections(all_dets)
    except Exception as e:
        logger.warning(f"Risk scoring error: {e}")
        enriched = all_dets

    # 6. Alert Record Creation & Deduplication
    alerts_tracker = pd.DataFrame()
    alert_rows = []
    for det in enriched:
        try:
            rec = create_alert(det)
            # Add MITRE ATT&CK technique
            threat_key = str(rec.get("threat_type", "")).lower()
            rec["mitre_attack"] = MITRE_MAP.get(threat_key, "T1059 — Command and Scripting Interpreter")
            alerts_tracker = add_alert(rec, alerts_tracker)
        except Exception:
            alert_rows.append(det)

    if not alerts_tracker.empty:
        alerts_final = alerts_tracker
    elif alert_rows:
        alerts_final = pd.DataFrame(alert_rows)
    else:
        alerts_final = pd.DataFrame(columns=[
            "alert_id", "timestamp", "threat_type", "source_ip",
            "target_ip", "source_port", "destination_port", "protocol",
            "risk_score", "severity", "reason", "score_reason",
            "evidence_count", "confidence", "status", "suggested_action", "mitre_attack"
        ])

    # Ensure MITRE column exists
    if "mitre_attack" not in alerts_final.columns and not alerts_final.empty:
        alerts_final["mitre_attack"] = alerts_final["threat_type"].map(
            lambda t: MITRE_MAP.get(str(t).lower(), "T1059 — Execution")
        )

    # Persist in session state
    st.session_state["logs_df"] = df_feat
    st.session_state["alerts_df"] = alerts_final
    st.session_state["active_dataset_name"] = source_name

    # Save alerts to disk
    try:
        if not alerts_final.empty:
            save_alerts(alerts_final, "data/alerts.csv")
    except Exception as e:
        logger.warning(f"Could not persist alerts to disk: {e}")

    return df_feat, alerts_final


def ensure_session_data() -> tuple[pd.DataFrame, pd.DataFrame, str]:
    """
    Checks st.session_state for logs and alerts.
    If missing or empty (e.g. direct URL visit or fresh worker start),
    automatically loads the historical benchmark dataset, runs the full detection
    pipeline, and populates st.session_state.
    """
    logs_df = st.session_state.get("logs_df")
    alerts_df = st.session_state.get("alerts_df")
    dataset_name = st.session_state.get("active_dataset_name")

    if logs_df is not None and not logs_df.empty:
        return logs_df, alerts_df if alerts_df is not None else pd.DataFrame(), dataset_name or "Active Session"

    # Need initialization - pick best available dataset
    candidate_path = DEFAULT_DATASET_PATH if os.path.exists(DEFAULT_DATASET_PATH) else "data/demo_security_logs.csv"
    candidate_name = DEFAULT_DATASET_NAME if os.path.exists(DEFAULT_DATASET_PATH) else "demo_security_logs.csv"

    if os.path.exists(candidate_path):
        try:
            df_raw = pd.read_csv(candidate_path)
            logs_df, alerts_df = run_pipeline(df_raw, candidate_name)
            return logs_df, alerts_df, candidate_name
        except Exception as e:
            logger.error(f"Failed to auto-initialize dataset {candidate_path}: {e}")

    # Fallback to empty DataFrames if files missing
    empty_logs = pd.DataFrame()
    empty_alerts = pd.DataFrame()
    st.session_state["logs_df"] = empty_logs
    st.session_state["alerts_df"] = empty_alerts
    st.session_state["active_dataset_name"] = "None"
    return empty_logs, empty_alerts, "None"
