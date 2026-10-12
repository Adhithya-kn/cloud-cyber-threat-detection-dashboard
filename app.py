"""
CyberShield — Cloud Cyber Threat Detection Dashboard
Main entry point / Home page
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import os
import io
import sys

# ── Path setup ─────────────────────────────────────────────────────────────
sys.path.insert(0, ".")

# ── Page config (MUST be first Streamlit call) ──────────────────────────────
st.set_page_config(
    page_title="CyberShield Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS — dark SOC theme ─────────────────────────────────────────────
CUSTOM_CSS = """
<style>
/* ── Base ── */
.main { background-color: #0a0e1a; }
.stApp { background-color: #0a0e1a; }
[data-testid="stSidebar"] { background-color: #0d1117; border-right: 1px solid #21262d; }
[data-testid="stSidebar"] * { color: #e2e8f0 !important; }

/* ── Hide default Streamlit decoration ── */
#MainMenu { visibility: hidden; }
footer { visibility: hidden; }

/* ── KPI Cards ── */
.kpi-card {
    background: linear-gradient(135deg, #111827 0%, #1f2937 100%);
    border: 1px solid #374151;
    border-radius: 12px;
    padding: 20px;
    text-align: center;
    box-shadow: 0 4px 6px rgba(0,0,0,0.3);
    margin-bottom: 8px;
}
.kpi-value { font-size: 2.5rem; font-weight: 700; color: #00d4ff; line-height: 1.1; }
.kpi-label { font-size: 0.85rem; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px; }
.kpi-delta-pos { font-size: 0.8rem; color: #22c55e; margin-top: 2px; }
.kpi-delta-neg { font-size: 0.8rem; color: #ef4444; margin-top: 2px; }

/* ── Severity badges ── */
.badge-critical { background:#7f1d1d; color:#fca5a5; padding:2px 8px; border-radius:4px; font-size:0.75rem; font-weight:600; }
.badge-high     { background:#78350f; color:#fcd34d; padding:2px 8px; border-radius:4px; font-size:0.75rem; font-weight:600; }
.badge-medium   { background:#1e3a5f; color:#93c5fd; padding:2px 8px; border-radius:4px; font-size:0.75rem; font-weight:600; }
.badge-low      { background:#064e3b; color:#6ee7b7; padding:2px 8px; border-radius:4px; font-size:0.75rem; font-weight:600; }

/* ── Table ── */
.threat-table { border-collapse:collapse; width:100%; }
.threat-table th { background:#1f2937; color:#9ca3af; padding:8px 12px; text-align:left; font-size:0.8rem; text-transform:uppercase; }
.threat-table td { padding:8px 12px; border-bottom:1px solid #374151; color:#e2e8f0; font-size:0.9rem; }

/* ── Status indicators ── */
.status-ok   { color:#22c55e; font-weight:600; }
.status-warn { color:#f59e0b; font-weight:600; }
.status-err  { color:#ef4444; font-weight:600; }

/* ── Section header ── */
.section-header {
    font-size:1.1rem; font-weight:600; color:#00d4ff;
    border-bottom:1px solid #1e40af; padding-bottom:6px; margin-bottom:14px;
}

/* ── Alert banner ── */
.alert-critical {
    background:rgba(127,29,29,0.3); border:1px solid #ef4444;
    border-radius:8px; padding:12px 16px; margin-bottom:8px;
}
.alert-high {
    background:rgba(120,53,15,0.3); border:1px solid #f97316;
    border-radius:8px; padding:12px 16px; margin-bottom:8px;
}

/* ── Sidebar logo ── */
.sidebar-logo {
    font-size:1.6rem; font-weight:800; color:#00d4ff;
    letter-spacing:0.05em; margin-bottom:4px;
}
.sidebar-tagline { font-size:0.75rem; color:#6b7280; margin-bottom:16px; }

/* ── Report Box ── */
.report-box {
    background: #111827;
    border: 1px solid #374151;
    border-radius: 10px;
    padding: 20px;
    margin-top: 15px;
    font-family: monospace;
    white-space: pre-wrap;
    color: #e2e8f0;
}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# ── Module imports with graceful fallback ───────────────────────────────────
_modules_ok: dict[str, bool] = {}

try:
    from utils.log_parser import load_data, normalize_events, validate_schema, extract_features
    _modules_ok["log_parser"] = True
except Exception:
    _modules_ok["log_parser"] = False

try:
    from detection.rules import run_all_rules
    _modules_ok["rules_engine"] = True
except Exception:
    _modules_ok["rules_engine"] = False

try:
    from detection.anomaly import train_model, detect_anomalies, get_anomaly_detections
    _modules_ok["ml_engine"] = True
except Exception:
    _modules_ok["ml_engine"] = False

try:
    from detection.risk_score import process_all_detections
    _modules_ok["risk_score"] = True
except Exception:
    _modules_ok["risk_score"] = False

try:
    from utils.alert_manager import (
        load_alerts, get_alerts_summary, create_alert,
        add_alert, save_alerts
    )
    _modules_ok["alert_manager"] = True
except Exception:
    _modules_ok["alert_manager"] = False


# ── Unified Pipeline Engine ─────────────────────────────────────────────────
from utils.pipeline import (
    run_pipeline,
    ensure_session_data,
    AVAILABLE_DATASETS,
    DEFAULT_DATASET_NAME,
    DEFAULT_DATASET_PATH,
)

def process_dataframe(df_input: pd.DataFrame, source_name: str = "Uploaded Dataset"):
    """Runs the complete detection and scoring pipeline."""
    return run_pipeline(df_input, source_name)


# ── Ensure Session State Initialized ─────────────────────────────────────────
logs_df, alerts_df, active_name = ensure_session_data()


# ── Sidebar ─────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<div class="sidebar-logo">🛡️ CyberShield</div>', unsafe_allow_html=True)
    st.markdown('<div class="sidebar-tagline">Cloud Cyber Threat Detection</div>', unsafe_allow_html=True)
    st.divider()

    st.markdown("**🗂 SOC Modules**")
    st.info("Explore the dedicated pages:\n- 📊 Overview\n- 📋 Log Monitoring\n- 🚨 Alerts\n- 📈 Analytics\n- 🔍 Investigation")
    st.divider()

    st.markdown("### ☁️ Cloud Architecture Status")
    cloud_port = os.environ.get("PORT", "8501")
    cloud_env = os.environ.get("ENV", "production")
    app_mode = os.environ.get("APP_MODE", "dashboard")
    st.markdown(f"""
    <div style='background:#111827; border:1px solid #1e40af; border-radius:8px; padding:10px; font-size:0.8rem;'>
      <div>🌐 <b>Host:</b> <code>0.0.0.0:{cloud_port}</code></div>
      <div>⚡ <b>Environment:</b> <span style='color:#34d399;'>{cloud_env.upper()}</span></div>
      <div>🚀 <b>Mode:</b> <code>{app_mode}</code></div>
      <div>🛡️ <b>Engine:</b> <span style='color:#00d4ff;'>Heuristics + ML Active</span></div>
    </div>
    """, unsafe_allow_html=True)
    st.divider()

    st.markdown("### 📥 Benchmark Datasets & Upload")

    dataset_options = list(AVAILABLE_DATASETS.keys()) + ["📂 Upload Custom CSV/JSON"]
    current_active = st.session_state.get("active_dataset_name", DEFAULT_DATASET_NAME)
    default_idx = dataset_options.index(current_active) if current_active in dataset_options else 0

    dataset_choice = st.selectbox(
        "Choose Security Telemetry Dataset:",
        dataset_options,
        index=default_idx
    )

    if dataset_choice == "📂 Upload Custom CSV/JSON":
        uploaded_file = st.file_uploader("Upload CSV or JSON Security Log", type=["csv", "json"])
        if uploaded_file is not None:
            if st.button("⚡ Analyze Uploaded File", use_container_width=True, type="primary"):
                with st.spinner("Parsing & analyzing uploaded telemetry..."):
                    try:
                        if uploaded_file.name.endswith(".csv"):
                            uploaded_df = pd.read_csv(uploaded_file)
                        else:
                            uploaded_df = pd.read_json(uploaded_file)
                        process_dataframe(uploaded_df, f"Uploaded: {uploaded_file.name}")
                        st.success(f"Analysis complete for {uploaded_file.name}!")
                        st.rerun()
                    except Exception as err:
                        st.error(f"Error parsing file: {err}")

    else:
        selected_file_path = AVAILABLE_DATASETS.get(dataset_choice)
        if st.button(f"⚡ Load & Analyze Selected", use_container_width=True, type="primary"):
            with st.spinner("Analyzing selected dataset through SOC pipeline..."):
                if selected_file_path and os.path.exists(selected_file_path):
                    chosen_df = pd.read_csv(selected_file_path)
                    process_dataframe(chosen_df, dataset_choice)
                    st.success("Analysis complete!")
                    st.rerun()
                else:
                    st.error(f"File not found: {selected_file_path}")

    st.divider()
    active_badge = st.session_state.get("active_dataset_name", "Default")
    st.markdown(f"**Current Active Data:** `{active_badge}`")

    if st.button("🔄 Reset / Reload Baseline", use_container_width=True):
        st.cache_data.clear()
        if os.path.exists(DEFAULT_DATASET_PATH):
            process_dataframe(pd.read_csv(DEFAULT_DATASET_PATH), DEFAULT_DATASET_NAME)
        st.rerun()

logs_df = st.session_state.get("logs_df", pd.DataFrame())
alerts_df = st.session_state.get("alerts_df", pd.DataFrame())

# ── Main Header ─────────────────────────────────────────────────────────────
st.markdown("""
<div style='text-align:center; padding:15px 0 10px 0;'>
  <span style='font-size:2.8rem; font-weight:900; color:#00d4ff; letter-spacing:0.05em;'>🛡️ CyberShield</span><br>
  <span style='font-size:1.1rem; color:#9ca3af; letter-spacing:0.12em;'>
      CLOUD CYBER THREAT DETECTION & ANALYSIS ENGINE
  </span>
</div>
""", unsafe_allow_html=True)

active_dataset_badge = st.session_state.get("active_dataset_name", "None")
st.markdown(
    f"""<div style='text-align:center; margin-bottom:12px;'>
      <span style='background:#1e3a5f; color:#93c5fd; padding:4px 14px; border-radius:20px; font-size:0.85rem; font-weight:600; margin-right:8px;'>Active Dataset: {active_dataset_badge}</span>
      <span style='background:#064e3b; color:#34d399; padding:4px 14px; border-radius:20px; font-size:0.85rem; font-weight:600;'>Cloud Deployment: Online</span>
      <span style='background:#312e81; color:#c7d2fe; padding:4px 14px; border-radius:20px; font-size:0.85rem; font-weight:600; margin-left:8px;'>Dual-Engine: Rules + ML Isolation Forest</span>
    </div>""",
    unsafe_allow_html=True
)
st.markdown("<hr style='border:1px solid #1e40af; margin:0 0 20px 0;'>", unsafe_allow_html=True)

# ── KPI Row ─────────────────────────────────────────────────────────────────
total_events = len(logs_df)
total_threats = len(alerts_df)

crit_count = 0
high_count = 0
med_count = 0
low_count = 0
if not alerts_df.empty and "severity" in alerts_df.columns:
    crit_count = int((alerts_df["severity"].str.upper() == "CRITICAL").sum())
    high_count = int((alerts_df["severity"].str.upper() == "HIGH").sum())
    med_count = int((alerts_df["severity"].str.upper() == "MEDIUM").sum())
    low_count = int((alerts_df["severity"].str.upper() == "LOW").sum())

c1, c2, c3, c4 = st.columns(4)

def _kpi(col, icon, label, value, color="#00d4ff", delta_text="", delta_pos=True):
    delta_cls = "kpi-delta-pos" if delta_pos else "kpi-delta-neg"
    delta_html = f'<div class="{delta_cls}">{delta_text}</div>' if delta_text else ""
    col.markdown(f"""
    <div class="kpi-card">
      <div style="font-size:1.8rem;">{icon}</div>
      <div class="kpi-value" style="color:{color};">{value:,}</div>
      <div class="kpi-label">{label}</div>
      {delta_html}
    </div>""", unsafe_allow_html=True)

_kpi(c1, "🔵", "Analyzed Log Events", total_events, "#00d4ff", f"Telemetry records")
_kpi(c2, "🟡", "Threats Detected", total_threats, "#f59e0b", f"Total alerts flagged", True)
_kpi(c3, "🔴", "Critical Alerts", crit_count, "#ef4444", "Urgent remediation required", False)
_kpi(c4, "🟠", "High Severity", high_count, "#f97316", f"Priority investigation")

st.markdown("<br>", unsafe_allow_html=True)

# ── Real-Time Automated Threat Intelligence Report ───────────────────────────
st.markdown('<div class="section-header">📄 Automated Threat Intelligence & Analysis Report</div>', unsafe_allow_html=True)

# Generate detailed text report according to the active dataset
report_lines = []
report_lines.append("=" * 80)
report_lines.append(f"CYBERSHIELD THREAT ANALYSIS REPORT — {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
report_lines.append(f"Source Telemetry   : {active_dataset_badge}")
report_lines.append(f"Events Ingested    : {total_events:,}")
report_lines.append(f"Detections Triaged : {total_threats} alerts (Critical: {crit_count}, High: {high_count}, Medium: {med_count}, Low: {low_count})")
report_lines.append("=" * 80)

if total_threats > 0 and not alerts_df.empty:
    report_lines.append("\n[1] EXECUTIVE THREAT SUMMARY:")
    top_threat = alerts_df["threat_type"].mode().iloc[0] if "threat_type" in alerts_df.columns else "N/A"
    top_attacker = alerts_df["source_ip"].mode().iloc[0] if "source_ip" in alerts_df.columns else "N/A"
    avg_risk = int(alerts_df["risk_score"].mean()) if "risk_score" in alerts_df.columns else 0
    report_lines.append(f"  • Primary Threat Category : {top_threat.upper()}")
    report_lines.append(f"  • Top Offending Source IP : {top_attacker}")
    report_lines.append(f"  • Mean Risk Index         : {avg_risk}/100")
    
    report_lines.append("\n[2] INCIDENT BREAKDOWN & FINDINGS:")
    for idx, r in alerts_df.head(10).iterrows():
        aid = r.get("alert_id", f"ALT-{idx+1:03d}")
        sev = r.get("severity", "MEDIUM")
        tt = r.get("threat_type", "Unknown")
        sip = r.get("source_ip", "Unknown")
        score = r.get("risk_score", 0)
        reason = r.get("reason", "Rule threshold exceeded.")
        report_lines.append(f"  [{aid}] [{sev}] {tt.upper()} from {sip} (Risk: {score}) -> {reason}")

    report_lines.append("\n[3] RECOMMENDED REMEDIATION PLAYBOOK:")
    unique_threats = alerts_df["threat_type"].unique() if "threat_type" in alerts_df.columns else []
    for ut in unique_threats:
        action = "Escalate to SOC analyst for inspection."
        if "brute_force" in str(ut).lower():
            action = "Immediately block offending source IP at perimeter firewall. Enforce MFA & account lockout policy."
        elif "port_scan" in str(ut).lower():
            action = "Isolate scanning entity. Review open ingress ports and update IDS drop rules."
        elif "abnormal_traffic" in str(ut).lower():
            action = "Rate-limit connection. Investigate potential data exfiltration and inspect network flow payloads."
        elif "ml_anomaly" in str(ut).lower():
            action = "Correlate host telemetry with process logs to verify outlier behavior."
        report_lines.append(f"  • {str(ut).upper()}: {action}")
else:
    report_lines.append("\n[1] EXECUTIVE THREAT SUMMARY:")
    report_lines.append("  • STATUS: CLEAN / LOW RISK BASELINE")
    report_lines.append("  • No malicious brute-force, port-scans, or abnormal traffic spikes detected.")
    report_lines.append("  • Telemetry adheres to normal operational profile.")

report_lines.append("\n" + "=" * 80)
report_lines.append("END OF REPORT — Generated automatically by CyberShield SOC Platform")

full_report_str = "\n".join(report_lines)

col_rep1, col_rep2 = st.columns([3, 1])
with col_rep1:
    st.markdown(f'<div class="report-box">{full_report_str}</div>', unsafe_allow_html=True)
with col_rep2:
    st.markdown("#### 📥 Export Report")
    st.download_button(
        label="📄 Download Report (TXT)",
        data=full_report_str,
        file_name=f"Threat_Report_{active_dataset_badge.replace(' ', '_')}.txt",
        mime="text/plain",
        use_container_width=True
    )
    if not alerts_df.empty:
        alerts_csv = alerts_df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📊 Download Alerts (CSV)",
            data=alerts_csv,
            file_name=f"Alerts_{active_dataset_badge.replace(' ', '_')}.csv",
            mime="text/csv",
            use_container_width=True
        )

# ── Trend & Detection Breakdown ─────────────────────────────────────────────
st.markdown("<br>", unsafe_allow_html=True)
st.markdown('<div class="section-header">📊 Threat Breakdown & Engine Telemetry</div>', unsafe_allow_html=True)

col_ch1, col_ch2 = st.columns(2)
with col_ch1:
    if not alerts_df.empty and "threat_type" in alerts_df.columns:
        counts = alerts_df["threat_type"].value_counts().reset_index()
        counts.columns = ["threat_type", "count"]
        fig_p = px.pie(
            counts, names="threat_type", values="count", hole=0.45,
            color_discrete_sequence=["#ef4444", "#f97316", "#3b82f6", "#06b6d4"]
        )
        fig_p.update_layout(
            paper_bgcolor="#111827", plot_bgcolor="#111827",
            font=dict(color="#e2e8f0"), height=250, margin=dict(t=10, b=10, l=10, r=10)
        )
        st.plotly_chart(fig_p, use_container_width=True)
    else:
        st.info("No active threats in current dataset.")

with col_ch2:
    if not alerts_df.empty and "risk_score" in alerts_df.columns:
        fig_h = px.histogram(
            alerts_df, x="risk_score", nbins=10,
            color_discrete_sequence=["#00d4ff"]
        )
        fig_h.update_layout(
            paper_bgcolor="#111827", plot_bgcolor="#111827",
            font=dict(color="#e2e8f0"), height=250, margin=dict(t=10, b=10, l=10, r=10),
            xaxis_title="Risk Score (0-100)", yaxis_title="Alert Count"
        )
        st.plotly_chart(fig_h, use_container_width=True)
    else:
        st.info("No risk score distribution available.")

# ── Active Detection Pipeline Engines ─────────────────────────────────────────
st.markdown('<div class="section-header">🖥️ Active Detection Pipeline Engines</div>', unsafe_allow_html=True)
sc1, sc2, sc3, sc4, sc5 = st.columns(5)
core_pipeline_status = [
    (sc1, "📜 Log Parser",      "Schema & Feature Extractor",  _modules_ok.get("log_parser", False)),
    (sc2, "⚙️ Rules Engine",    "Brute Force & Port Scans",    _modules_ok.get("rules_engine", False)),
    (sc3, "🤖 ML Engine",       "Isolation Forest (Sklearn)",  _modules_ok.get("ml_engine", False)),
    (sc4, "🎯 Risk Scorer",     "Weighted CVSS-Style Scoring", _modules_ok.get("risk_score", False)),
    (sc5, "🔔 Alert Manager",   "Triage & Deduplication",      _modules_ok.get("alert_manager", False)),
]
for col, name, subtitle, ok in core_pipeline_status:
    icon = "✅" if ok else "⚠️"
    status_txt = "ONLINE" if ok else "FALLBACK"
    col.markdown(f"""
    <div class="kpi-card" style="padding:14px;">
      <div style="font-size:1.3rem;">{icon}</div>
      <div style="font-size:0.82rem; font-weight:700; color:#e2e8f0; margin-top:4px;">{name}</div>
      <div style="font-size:0.68rem; color:#94a3b8; margin-top:1px;">{subtitle}</div>
      <div style="font-size:0.7rem; color:{'#22c55e' if ok else '#f59e0b'}; margin-top:3px; font-weight:600;">{status_txt}</div>
    </div>""", unsafe_allow_html=True)

st.markdown("<br>")
st.caption("CyberShield · Cloud-Based Cyber Threat Detection Dashboard · Cloud Application Development")


