"""
pages/05_🔍_Investigation.py
============================
Investigation Workbench Page for CyberShield SOC Analysts.

Displays:
- Left panel: Alert selector with risk badge, MITRE ATT&CK technique & status
- Drill-down panel:
  * Alert details (threat category, source IP, target IP, evidence count, MITRE tag)
  * Dynamic Composite Risk Index Gauge (Plotly, 0-100)
  * Root cause detection narrative & CVSS score breakdown
  * Suggested SOC playbook action
  * Correlated raw log telemetry for the suspect entity
  * Interactive incident activity timeline
  * Case management notes & status transition triage
  * Downloadable SOC Incident Dossier (TXT)
"""

import sys
import os
sys.path.insert(0, ".")

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta

from utils.pipeline import (
    ensure_session_data,
    run_pipeline,
    AVAILABLE_DATASETS,
    DEFAULT_DATASET_NAME,
    DEFAULT_DATASET_PATH,
    MITRE_MAP
)
from utils.alert_manager import update_alert_status, save_alerts

st.set_page_config(
    page_title="Investigation Workbench | CyberShield",
    page_icon="🔍",
    layout="wide",
)

# Custom SOC Dark styling
st.markdown("""
<style>
.main { background-color: #0a0e1a; }
.stApp { background-color: #0a0e1a; }
[data-testid="stSidebar"] { background-color: #0d1117; border-right: 1px solid #21262d; }
.alert-card {
    background: #111827;
    border-left: 4px solid #00d4ff;
    padding: 16px;
    border-radius: 8px;
    margin-bottom: 12px;
}
.reason-box {
    background: #1f2937;
    border: 1px solid #374151;
    border-radius: 8px;
    padding: 14px;
    color: #e5e7eb;
    margin: 8px 0;
    line-height: 1.5;
}
.action-box {
    background: #064e3b;
    border: 1px solid #059669;
    border-radius: 8px;
    padding: 14px;
    color: #a7f3d0;
    margin: 8px 0;
    font-weight: 500;
    line-height: 1.5;
}
.mitre-badge {
    background: #1e3a5f;
    color: #93c5fd;
    border: 1px solid #2563eb;
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 0.85rem;
    font-weight: 600;
}
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Self-Initializing Session Data
# ---------------------------------------------------------------------------
logs_df, alerts_df, active_name = ensure_session_data()

# ---------------------------------------------------------------------------
# Sidebar: Dataset Switcher & Investigation Status
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown('<div style="font-size:1.4rem;font-weight:800;color:#00d4ff;">🛡️ CyberShield</div>', unsafe_allow_html=True)
    st.caption("Forensic Investigation Workbench")
    st.divider()

    st.markdown("### 📥 Switch Telemetry Dataset")
    ds_options = list(AVAILABLE_DATASETS.keys())
    curr_ds = st.session_state.get("active_dataset_name", DEFAULT_DATASET_NAME)
    curr_idx = ds_options.index(curr_ds) if curr_ds in ds_options else 0
    sel_ds = st.selectbox("Active Dataset:", ds_options, index=curr_idx)

    if sel_ds != curr_ds:
        fpath = AVAILABLE_DATASETS.get(sel_ds)
        if fpath and os.path.exists(fpath):
            chosen_df = pd.read_csv(fpath)
            run_pipeline(chosen_df, sel_ds)
            st.rerun()

    st.divider()
    st.markdown(f"**Telemetry Source:** `{st.session_state.get('active_dataset_name', 'Benchmark')}`")
    st.markdown(f"**Total Logs Ingested:** `{len(logs_df):,}`")
    st.markdown(f"**Active Security Alerts:** `{len(alerts_df):,}`")
    st.divider()

    if st.button("🔄 Reload Default Benchmark", use_container_width=True):
        if os.path.exists(DEFAULT_DATASET_PATH):
            run_pipeline(pd.read_csv(DEFAULT_DATASET_PATH), DEFAULT_DATASET_NAME)
            st.rerun()


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.title("🔍 SOC Investigation Workbench")
st.markdown(
    f"Deep-dive forensic analysis, correlated entity tracking, and incident triage on `{active_name}`."
)

if alerts_df.empty:
    st.info("✅ **No high-risk security alerts in current dataset.** Baseline traffic conforms to normal operation.")
    col_load_b1, col_load_b2 = st.columns([1, 3])
    with col_load_b1:
        if st.button("⚡ Load CIC-IDS2017 Intrusion Benchmark", type="primary"):
            if os.path.exists(DEFAULT_DATASET_PATH):
                run_pipeline(pd.read_csv(DEFAULT_DATASET_PATH), DEFAULT_DATASET_NAME)
                st.rerun()
    st.stop()


# ---------------------------------------------------------------------------
# Alert Selector & Metadata Header
# ---------------------------------------------------------------------------
col_select, col_meta = st.columns([3, 1])

with col_select:
    alert_options = []
    for idx, r in alerts_df.iterrows():
        aid = r.get("alert_id", f"ALT-{idx+1:03d}")
        ttype = str(r.get("threat_type", "INCIDENT")).upper()
        sip = r.get("source_ip", "Unknown")
        tip = r.get("target_ip", "Various")
        rscore = r.get("risk_score", 50)
        alert_options.append(f"{aid} | {ttype} | {sip} ➔ {tip} (Risk: {rscore}/100)")

    selected_option = st.selectbox("Select Incident Alert to Investigate:", alert_options)
    selected_id = selected_option.split(" | ")[0]
    matched = alerts_df[alerts_df["alert_id"] == selected_id]
    if matched.empty:
        alert_record = alerts_df.iloc[0]
        selected_id = alert_record.get("alert_id", "ALT-001")
    else:
        alert_record = matched.iloc[0]

with col_meta:
    st.markdown("<br>", unsafe_allow_html=True)
    sev = str(alert_record.get("severity", "MEDIUM")).upper()
    sev_color = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#3b82f6",
        "LOW": "#22c55e"
    }.get(sev, "#3b82f6")
    st.markdown(
        f'<div style="text-align:right;"><span style="background:{sev_color};color:#fff;padding:8px 16px;border-radius:6px;font-weight:800;font-size:1.05rem;letter-spacing:0.05em;">{sev} SEVERITY</span></div>',
        unsafe_allow_html=True
    )

st.markdown("---")

# ---------------------------------------------------------------------------
# Alert Drill-down (Two columns: Incident Details & Gauge)
# ---------------------------------------------------------------------------
c_details, c_gauge = st.columns([3, 2])

with c_details:
    st.subheader(f"📌 Incident Dossier: `{selected_id}`")
    
    info_col1, info_col2 = st.columns(2)
    with info_col1:
        st.markdown(f"**Threat Vector:** `{str(alert_record.get('threat_type', 'N/A')).upper()}`")
        st.markdown(f"**Attacker Source IP:** `{alert_record.get('source_ip', 'N/A')}`")
        st.markdown(f"**Target Host IP:** `{alert_record.get('target_ip', 'N/A')}`")
        st.markdown(f"**Detection Time:** `{alert_record.get('timestamp', 'N/A')}`")
    with info_col2:
        st.markdown(f"**Triage Status:** `{alert_record.get('status', 'NEW')}`")
        st.markdown(f"**Evidence Count:** `{alert_record.get('evidence_count', 'N/A')} events`")
        st.markdown(f"**Confidence Factor:** `{float(alert_record.get('confidence', 0.8)):.2f}`")
        dest_port = alert_record.get('destination_port', 'N/A')
        st.markdown(f"**Target Port:** `{dest_port if pd.notna(dest_port) and str(dest_port) != '' else 'Varied'}`")

    # MITRE ATT&CK Mapping
    threat_k = str(alert_record.get('threat_type', '')).lower()
    mitre_val = alert_record.get('mitre_attack') or MITRE_MAP.get(threat_k, "T1059 — Command and Scripting")
    st.markdown(f"**MITRE ATT&CK® Tactic/Technique:** <span class='mitre-badge'>{mitre_val}</span>", unsafe_allow_html=True)

    st.markdown("#### 🎯 Technical Detection Rationale")
    reason_text = alert_record.get("reason", "Automated anomaly signature triggered.")
    st.markdown(f'<div class="reason-box">{reason_text}</div>', unsafe_allow_html=True)

    st.markdown("#### 🛡️ Prescribed SOC Playbook Action")
    action_text = alert_record.get("suggested_action", "Isolate host and perform manual log review.")
    st.markdown(f'<div class="action-box">▶ {action_text}</div>', unsafe_allow_html=True)

with c_gauge:
    st.subheader("📊 Dynamic CVSS Risk Score")
    risk_val = int(alert_record.get("risk_score", 50))
    
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number",
        value=risk_val,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Composite Risk Index (0-100)", 'font': {'color': '#e2e8f0', 'size': 16}},
        gauge={
            'axis': {'range': [0, 100], 'tickcolor': "#9ca3af"},
            'bar': {'color': "#00d4ff", 'thickness': 0.25},
            'bgcolor': "#1f2937",
            'borderwidth': 1,
            'bordercolor': "#374151",
            'steps': [
                {'range': [0, 30], 'color': "rgba(34, 197, 94, 0.3)"},
                {'range': [30, 60], 'color': "rgba(59, 130, 246, 0.3)"},
                {'range': [60, 80], 'color': "rgba(249, 115, 22, 0.4)"},
                {'range': [80, 100], 'color': "rgba(239, 68, 68, 0.5)"},
            ],
            'threshold': {
                'line': {'color': "#ef4444", 'width': 4},
                'thickness': 0.75,
                'value': 80
            }
        }
    ))
    fig_gauge.update_layout(
        paper_bgcolor="#111827",
        font=dict(color="#e2e8f0"),
        height=260,
        margin=dict(t=30, b=10, l=20, r=20)
    )
    st.plotly_chart(fig_gauge, use_container_width=True)

    score_reason = alert_record.get("score_reason", "Deterministic CVSS calculation applied.")
    st.caption(f"**Scoring Formula Breakdown:**\n\n{score_reason}")

st.markdown("---")

# ---------------------------------------------------------------------------
# Correlated Log Telemetry & Timeline for Suspect Entity
# ---------------------------------------------------------------------------
suspect_ip = str(alert_record["source_ip"])
st.subheader(f"📂 Correlated Telemetry for Suspect: `{suspect_ip}`")

if not logs_df.empty and "source_ip" in logs_df.columns:
    related_logs = logs_df[logs_df["source_ip"].astype(str) == suspect_ip].copy()
    if not related_logs.empty:
        st.write(f"Found **{len(related_logs)}** correlated events matching suspect entity.")
        
        # Ensure timestamp is datetime for plotting
        if "timestamp" in related_logs.columns:
            related_logs["timestamp"] = pd.to_datetime(related_logs["timestamp"], errors="coerce")
            valid_time_logs = related_logs.dropna(subset=["timestamp"])
            
            if not valid_time_logs.empty:
                st.markdown("##### ⏱️ Attack Activity Timeline")
                fig_timeline = px.scatter(
                    valid_time_logs,
                    x="timestamp",
                    y="event_type" if "event_type" in valid_time_logs.columns else "protocol",
                    color="status" if "status" in valid_time_logs.columns else None,
                    size="bytes" if "bytes" in valid_time_logs.columns else None,
                    color_discrete_map={"success": "#22c55e", "failed": "#ef4444", "rejected": "#f59e0b", "Failure": "#ef4444", "Success": "#22c55e"},
                    hover_data=[c for c in ["destination_ip", "destination_port", "protocol"] if c in valid_time_logs.columns]
                )
                fig_timeline.update_layout(
                    paper_bgcolor="#111827",
                    plot_bgcolor="#111827",
                    font=dict(color="#e2e8f0"),
                    height=240,
                    margin=dict(t=15, b=15, l=15, r=15),
                    xaxis_title="Time of Occurrence (UTC)",
                    yaxis_title="Activity Vector"
                )
                st.plotly_chart(fig_timeline, use_container_width=True)

        # Raw logs table
        display_cols = [c for c in ["timestamp", "source_ip", "destination_ip", "destination_port", "protocol", "event_type", "status", "bytes"] if c in related_logs.columns]
        st.dataframe(related_logs[display_cols].head(40), use_container_width=True)
    else:
        st.info(f"No direct connection rows found in current log window for source IP {suspect_ip}.")
else:
    st.info("Log stream not loaded.")

st.markdown("---")

# ---------------------------------------------------------------------------
# Case Management & Triage Status Transition
# ---------------------------------------------------------------------------
st.subheader("✍️ Analyst Case Management & Incident Triage")

col_triage1, col_triage2 = st.columns([2, 1])

with col_triage1:
    notes_key = f"notes_{selected_id}"
    analyst_notes = st.text_area(
        "SOC Investigation Notes & Forensic Findings:",
        value=st.session_state.get(notes_key, f"Case opened on {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}. Observed {alert_record.get('threat_type', 'threat')} indicators from {suspect_ip}."),
        height=120
    )
    if st.button("💾 Save Case Notes"):
        st.session_state[notes_key] = analyst_notes
        st.success("Case notes saved to session record!")

with col_triage2:
    st.markdown("#### Transition Incident Status")
    current_status = str(alert_record.get("status", "NEW")).upper()
    valid_statuses = ["NEW", "REVIEWING", "RESOLVED", "FALSE_POSITIVE"]
    status_idx = valid_statuses.index(current_status) if current_status in valid_statuses else 0
    new_status = st.selectbox("Update Status:", valid_statuses, index=status_idx)
    
    if st.button("⚡ Update Incident Status", type="primary"):
        try:
            alerts_df = update_alert_status(selected_id, new_status, alerts_df)
            st.session_state["alerts_df"] = alerts_df
            save_alerts(alerts_df, "data/alerts.csv")
            st.success(f"Alert {selected_id} transitioned to {new_status}!")
            st.rerun()
        except Exception as e:
            st.error(f"Error updating status: {e}")

# ---------------------------------------------------------------------------
# Exportable SOC Incident Dossier
# ---------------------------------------------------------------------------
st.markdown("<br>", unsafe_allow_html=True)
notes_content = st.session_state.get(notes_key, 'No extra notes provided')
report_text = f"""================================================================================
CYBERSHIELD SECURITY OPERATIONS CENTER — FORENSIC INCIDENT DOSSIER
================================================================================
Incident ID        : {selected_id}
Threat Category    : {str(alert_record.get('threat_type')).upper()}
MITRE ATT&CK       : {mitre_val}
Severity Level     : {sev} (Composite Risk Score: {alert_record.get('risk_score')}/100)
Investigation State: {alert_record.get('status')}
Timestamp (UTC)    : {alert_record.get('timestamp')}

ENTITY & NETWORK CONTEXT
Source Entity (IP) : {alert_record.get('source_ip')}
Target Victim (IP) : {alert_record.get('target_ip')}
Target Port        : {alert_record.get('destination_port')}
Evidence Events    : {alert_record.get('evidence_count')} records
Confidence Factor  : {alert_record.get('confidence')}

DETECTION LOGIC & REASONING
Detection Narrative: {alert_record.get('reason')}
Risk Breakdown     : {alert_record.get('score_reason')}

RECOMMENDED SOC PLAYBOOK RESPONSE
Action Protocol    : {alert_record.get('suggested_action')}
Analyst Case Notes : {notes_content}
================================================================================
Generated via CyberShield Prototype SOC Platform — Cloud Application Development.
"""

st.download_button(
    label="📄 Download Official Incident Dossier (TXT)",
    data=report_text,
    file_name=f"Incident_Report_{selected_id}.txt",
    mime="text/plain"
)
