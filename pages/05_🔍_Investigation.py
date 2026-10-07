"""
pages/05_🔍_Investigation.py
============================
Investigation Workbench Page for CyberShield SOC Analysts.

Displays:
- Left panel: Alert selector with risk badge & status
- Drill-down panel:
  * Alert details (threat type, IPs, timestamps, evidence count)
  * Interactive Risk Score Gauge chart (Plotly)
  * Detection reason narrative & MITRE ATT&CK alignment
  * Suggested SOC action guidance
  * Correlated raw log events for the source IP
  * Event timeline for the suspect entity
  * Analyst investigation notes with save & triage action buttons
  * Downloadable SOC Incident Report
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

from utils.alert_manager import load_alerts, update_alert_status, save_alerts
from utils.log_parser import load_data, normalize_events

st.set_page_config(
    page_title="Investigation Workbench | CyberShield",
    page_icon="🔍",
    layout="wide",
)

# Custom dark theme styles
st.markdown("""
<style>
.main { background-color: #0a0e1a; }
.stApp { background-color: #0a0e1a; }
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
}
.action-box {
    background: #064e3b;
    border: 1px solid #059669;
    border-radius: 8px;
    padding: 14px;
    color: #a7f3d0;
    margin: 8px 0;
    font-weight: 500;
}
</style>
""", unsafe_allow_html=True)

st.title("🔍 Investigation Workbench")
st.markdown("Deep-dive forensic analysis, log correlation, and incident triage.")

# ---------------------------------------------------------------------------
# Load Alerts & Logs
# ---------------------------------------------------------------------------
alerts_df = load_alerts("data/alerts.csv")
logs_df = pd.DataFrame()
if os.path.exists("data/demo_security_logs.csv"):
    logs_df = load_data("data/demo_security_logs.csv")
    logs_df = normalize_events(logs_df)

if alerts_df.empty:
    st.warning("⚠️ No alerts currently in store. Generate or run detections from the home page first.")
    st.stop()

# ---------------------------------------------------------------------------
# Left Sidebar / Top Filter: Alert Selector
# ---------------------------------------------------------------------------
col_select, col_meta = st.columns([2, 1])

with col_select:
    alert_options = []
    for idx, r in alerts_df.iterrows():
        alert_options.append(f"{r['alert_id']} | {r['threat_type'].upper()} | {r['source_ip']} (Risk: {r.get('risk_score', 'N/A')})")

    selected_option = st.selectbox("Select Incident Alert to Investigate:", alert_options)
    selected_id = selected_option.split(" | ")[0]
    alert_record = alerts_df[alerts_df["alert_id"] == selected_id].iloc[0]

with col_meta:
    st.markdown("<br>", unsafe_allow_html=True)
    sev = alert_record.get("severity", "MEDIUM")
    sev_color = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#3b82f6",
        "LOW": "#22c55e"
    }.get(sev, "#3b82f6")
    st.markdown(
        f'<div style="text-align:right;"><span style="background:{sev_color};color:#fff;padding:6px 14px;border-radius:6px;font-weight:700;font-size:1rem;">{sev} SEVERITY</span></div>',
        unsafe_allow_html=True
    )

st.markdown("---")

# ---------------------------------------------------------------------------
# Alert Drill-down (Two columns: Metadata & Gauge)
# ---------------------------------------------------------------------------
c_details, c_gauge = st.columns([3, 2])

with c_details:
    st.subheader(f"📌 Incident Summary: `{alert_record['alert_id']}`")
    
    info_col1, info_col2 = st.columns(2)
    with info_col1:
        st.markdown(f"**Threat Type:** `{alert_record.get('threat_type', 'N/A')}`")
        st.markdown(f"**Attacker Source IP:** `{alert_record.get('source_ip', 'N/A')}`")
        st.markdown(f"**Target Victim IP:** `{alert_record.get('target_ip', 'N/A')}`")
        st.markdown(f"**Timestamp:** `{alert_record.get('timestamp', 'N/A')}`")
    with info_col2:
        st.markdown(f"**Current Status:** `{alert_record.get('status', 'NEW')}`")
        st.markdown(f"**Evidence Multiplier:** `{alert_record.get('evidence_count', 'N/A')} events`")
        st.markdown(f"**Confidence Factor:** `{float(alert_record.get('confidence', 0.8)):.2f}`")
        dest_port = alert_record.get('destination_port', 'N/A')
        st.markdown(f"**Target Port:** `{dest_port if pd.notna(dest_port) else 'Varied'}`")

    st.markdown("#### 🎯 Detection Narrative & Reason")
    reason_text = alert_record.get("reason", "Automated detection rule triggered.")
    st.markdown(f'<div class="reason-box">{reason_text}</div>', unsafe_allow_html=True)

    st.markdown("#### 🛡️ Recommended SOC Playbook Action")
    action_text = alert_record.get("suggested_action", "Isolate host and perform manual log review.")
    st.markdown(f'<div class="action-box">▶ {action_text}</div>', unsafe_allow_html=True)

with c_gauge:
    st.subheader("📊 Dynamic Risk Assessment")
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
                'line': {'color': "red", 'width': 4},
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

    score_reason = alert_record.get("score_reason", "Deterministic rule weighting applied.")
    st.caption(f"**Scoring breakdown:** {score_reason}")

st.markdown("---")

# ---------------------------------------------------------------------------
# Correlated Log Evidence
# ---------------------------------------------------------------------------
st.subheader(f"📂 Correlated Telemetry for Source: `{alert_record['source_ip']}`")

suspect_ip = alert_record["source_ip"]
if not logs_df.empty and "source_ip" in logs_df.columns:
    related_logs = logs_df[logs_df["source_ip"] == suspect_ip].copy()
    if not related_logs.empty:
        st.write(f"Found **{len(related_logs)}** correlated events matching suspect entity.")
        
        # Timeline mini chart
        if "timestamp" in related_logs.columns and pd.api.types.is_datetime64_any_dtype(related_logs["timestamp"]):
            fig_sub = px.scatter(
                related_logs,
                x="timestamp",
                y="event_type",
                color="status",
                size="bytes" if "bytes" in related_logs.columns else None,
                color_discrete_map={"success": "#22c55e", "failed": "#ef4444", "rejected": "#f59e0b"},
                hover_data=["destination_port", "protocol"]
            )
            fig_sub.update_layout(
                paper_bgcolor="#111827",
                plot_bgcolor="#111827",
                font=dict(color="#e2e8f0"),
                height=220,
                margin=dict(t=10, b=10, l=10, r=10),
                xaxis_title="Time of Occurrence",
                yaxis_title="Activity"
            )
            st.plotly_chart(fig_sub, use_container_width=True)

        # Raw logs table
        display_cols = [c for c in ["timestamp", "source_ip", "destination_ip", "destination_port", "protocol", "event_type", "status", "bytes"] if c in related_logs.columns]
        st.dataframe(related_logs[display_cols].head(30), use_container_width=True)
    else:
        st.info("No raw historical connection events found in the current log stream for this source IP.")
else:
    st.info("Log stream not loaded.")

st.markdown("---")

# ---------------------------------------------------------------------------
# Triage Actions & Analyst Notes
# ---------------------------------------------------------------------------
st.subheader("✍️ Analyst Case Management & Triage")

col_triage1, col_triage2 = st.columns([2, 1])

with col_triage1:
    notes_key = f"notes_{selected_id}"
    analyst_notes = st.text_area(
        "SOC Investigation Notes & Forensic Findings:",
        value=st.session_state.get(notes_key, f"Case opened on {datetime.now().strftime('%Y-%m-%d %H:%M')}. Observed {alert_record['threat_type']} indicators."),
        height=120
    )
    if st.button("💾 Save Case Notes"):
        st.session_state[notes_key] = analyst_notes
        st.success("Case notes saved to session record!")

with col_triage2:
    st.markdown("#### Transition Case Status")
    current_status = alert_record.get("status", "NEW")
    new_status = st.selectbox("Update Status:", ["NEW", "REVIEWING", "RESOLVED", "FALSE_POSITIVE"], index=["NEW", "REVIEWING", "RESOLVED", "FALSE_POSITIVE"].index(current_status) if current_status in ["NEW", "REVIEWING", "RESOLVED", "FALSE_POSITIVE"] else 0)
    
    if st.button("⚡ Update Status"):
        try:
            alerts_df = update_alert_status(selected_id, new_status, alerts_df)
            save_alerts(alerts_df, "data/alerts.csv")
            st.success(f"Alert {selected_id} updated to {new_status}!")
            st.rerun()
        except Exception as e:
            st.error(f"Error updating status: {e}")

# Exportable Incident Report
st.markdown("<br>", unsafe_allow_html=True)
report_text = f"""================================================================================
CYBERSHIELD SECURITY OPERATIONS CENTER — INCIDENT REPORT
================================================================================
Incident ID     : {alert_record.get('alert_id')}
Threat Category : {alert_record.get('threat_type')}
Severity Level  : {alert_record.get('severity')} (Score: {alert_record.get('risk_score')}/100)
Status          : {alert_record.get('status')}
Timestamp       : {alert_record.get('timestamp')}

ENTITY DETAILS
Source Entity   : {alert_record.get('source_ip')}
Target Entity   : {alert_record.get('target_ip')}
Target Port     : {alert_record.get('destination_port')}

TECHNICAL DETECTION
Reason          : {alert_record.get('reason')}
Confidence      : {alert_record.get('confidence')}

ACTION TAKEN / RECOMMENDED PLAYBOOK
Playbook Action : {alert_record.get('suggested_action')}
Analyst Notes   : {st.session_state.get(notes_key, 'None provided')}
================================================================================
Generated via CyberShield Prototype SOC Platform.
"""

st.download_button(
    label="📄 Download SOC Incident Dossier (TXT)",
    data=report_text,
    file_name=f"Incident_Report_{selected_id}.txt",
    mime="text/plain"
)
