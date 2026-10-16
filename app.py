"""
CyberShield — Cloud Cyber Threat Detection & Autonomous SOC Platform
Fast, Simple, Demonstration-Ready Security Operations Dashboard
"""

import os
import sys
import io
from datetime import datetime

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

# ── Path setup ─────────────────────────────────────────────────────────────
sys.path.insert(0, ".")

from utils.pipeline import (
    run_pipeline,
    ensure_session_data,
    MITRE_MAP,
)
from utils.alert_manager import update_alert_status, save_alerts

# ── Curated Demonstration Scenarios (Only Two Datasets) ─────────────────────
AVAILABLE_DATASETS = {
    "🟢 Dataset 1: Normal Cloud Activity (Routine Baseline)": "data/dataset_1_normal_baseline.csv",
    "🚨 Dataset 2: Active Cyber Attack Incidents (Intrusions & Threats)": "data/demo_security_logs.csv",
}
DEFAULT_DATASET_NAME = "🚨 Dataset 2: Active Cyber Attack Incidents (Intrusions & Threats)"
DEFAULT_DATASET_PATH = "data/demo_security_logs.csv"

# ── Streamlit Page Configuration ───────────────────────────────────────────
st.set_page_config(
    page_title="CyberShield | Cloud Threat Detection SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom Dark SOC Styling ────────────────────────────────────────────────
CUSTOM_CSS = """
<style>
/* Main Background */
.main, .stApp {
    background-color: #0a0e1a !important;
    color: #e2e8f0;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background-color: #0d1117 !important;
    border-right: 1px solid #1e293b !important;
}
[data-testid="stSidebar"] * {
    color: #e2e8f0 !important;
}

/* Hide Default Streamlit Chrome & Multi-page Nav */
#MainMenu { visibility: hidden; }
footer { visibility: hidden; }
[data-testid="stSidebarNav"] { display: none !important; }

/* KPI Cards */
.kpi-card {
    background: linear-gradient(135deg, #111827 0%, #1a2234 100%);
    border: 1px solid #2d3748;
    border-radius: 12px;
    padding: 16px 14px;
    text-align: center;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.35);
    margin-bottom: 8px;
    transition: transform 0.2s ease, border-color 0.2s ease;
}
.kpi-card:hover {
    border-color: #00d4ff;
    transform: translateY(-2px);
}
.kpi-value {
    font-size: 2.3rem;
    font-weight: 800;
    line-height: 1.1;
    margin-top: 4px;
}
.kpi-label {
    font-size: 0.78rem;
    color: #94a3b8;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-top: 4px;
    font-weight: 600;
}

/* Status Banners */
.status-banner-safe {
    background: rgba(6, 78, 59, 0.45);
    border: 1px solid #10b981;
    border-radius: 10px;
    padding: 14px 20px;
    margin-bottom: 18px;
}
.status-banner-attack {
    background: rgba(127, 29, 29, 0.45);
    border: 1px solid #ef4444;
    border-radius: 10px;
    padding: 14px 20px;
    margin-bottom: 18px;
}

/* Detail & Action Card */
.action-card {
    background: #111827;
    border: 1px solid #374151;
    border-radius: 10px;
    padding: 18px;
    margin-top: 10px;
}

/* Tabs Styling */
.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
}
.stTabs [data-baseweb="tab"] {
    border-radius: 8px 8px 0px 0px;
    padding: 10px 18px;
    background-color: #111827;
    color: #94a3b8;
    font-weight: 600;
}
.stTabs [aria-selected="true"] {
    background-color: #1e3a5f !important;
    color: #00d4ff !important;
}

/* Badges */
.badge-critical { background:#7f1d1d; color:#fca5a5; padding:3px 8px; border-radius:4px; font-weight:700; font-size:0.75rem; }
.badge-high     { background:#78350f; color:#fcd34d; padding:3px 8px; border-radius:4px; font-weight:700; font-size:0.75rem; }
.badge-medium   { background:#1e3a5f; color:#93c5fd; padding:3px 8px; border-radius:4px; font-weight:700; font-size:0.75rem; }
.badge-low      { background:#064e3b; color:#6ee7b7; padding:3px 8px; border-radius:4px; font-weight:700; font-size:0.75rem; }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ── Fast Cached Pipeline Loader ──────────────────────────────────────────────
@st.cache_data(show_spinner=False)
def load_dataset_cached(filepath: str, name: str) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Runs pipeline once per dataset and caches output for instantaneous UI toggling."""
    if not os.path.exists(filepath):
        return pd.DataFrame(), pd.DataFrame()
    raw_df = pd.read_csv(filepath)
    return run_pipeline(raw_df, name)


# ── Sidebar Controls ────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="display:flex; align-items:center; gap:10px; margin-bottom:4px;">
        <span style="font-size:2rem;">🛡️</span>
        <div>
            <div style="font-size:1.4rem; font-weight:800; color:#00d4ff; line-height:1.1;">CyberShield</div>
            <div style="font-size:0.72rem; color:#94a3b8;">Cloud Threat Detection & SOC</div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.divider()

    st.markdown("### 🎯 Select Operational Scenario")
    dataset_keys = list(AVAILABLE_DATASETS.keys())
    
    # Track selection in session state
    current_choice = st.session_state.get("selected_scenario", DEFAULT_DATASET_NAME)
    default_idx = dataset_keys.index(current_choice) if current_choice in dataset_keys else 0

    selected_scenario = st.radio(
        "Demonstration Dataset:",
        dataset_keys,
        index=default_idx,
        help="Switch between clean normal operations and live attack incident telemetry."
    )
    st.session_state["selected_scenario"] = selected_scenario

    st.divider()

    # Real-life Working Group / SOC Team Persona
    st.markdown("### 👥 SOC Team Working System")
    soc_role = st.selectbox(
        "Active Analyst Persona:",
        [
            "🛡️ Lead SOC Analyst",
            "🔍 Threat Hunter",
            "🚨 Incident Commander",
        ],
        index=0,
    )

    defense_policy = st.selectbox(
        "Defense Policy Mode:",
        [
            "⚡ Active Defense",
            "👁️ Passive Monitoring",
        ],
        index=0,
        help="Active Defense enables immediate mitigation actions; Passive Monitoring is read-only."
    )

    st.divider()

    if st.button("🔄 Reload & Reset Baseline", use_container_width=True):
        st.cache_data.clear()
        if "scenario_alerts" in st.session_state:
            st.session_state["scenario_alerts"].clear()
        st.session_state["selected_scenario"] = DEFAULT_DATASET_NAME
        st.rerun()

    st.caption("CyberShield · Cloud SOC Demonstration · Fast & Simplified Platform")


# ── Load Selected Telemetry (Cached & Instant) ─────────────────────────────
target_filepath = AVAILABLE_DATASETS[selected_scenario]

if "scenario_alerts" not in st.session_state:
    st.session_state["scenario_alerts"] = {}

logs_df, cached_alerts = load_dataset_cached(target_filepath, selected_scenario)

if selected_scenario not in st.session_state["scenario_alerts"]:
    st.session_state["scenario_alerts"][selected_scenario] = cached_alerts.copy()

alerts_df = st.session_state["scenario_alerts"][selected_scenario]

# Sync into session_state for any helper references
st.session_state["logs_df"] = logs_df
st.session_state["alerts_df"] = alerts_df
st.session_state["active_dataset_name"] = selected_scenario

# Ensure timestamp parsing
if not logs_df.empty and "timestamp" in logs_df.columns:
    logs_df["timestamp"] = pd.to_datetime(logs_df["timestamp"])
if not alerts_df.empty and "timestamp" in alerts_df.columns:
    alerts_df["timestamp"] = pd.to_datetime(alerts_df["timestamp"])

is_attack_scenario = "Attack" in selected_scenario or "Threats" in selected_scenario or len(alerts_df) > 0


# ── Main Header ─────────────────────────────────────────────────────────────
st.markdown("""
<div style="display:flex; justify-content:space-between; align-items:center; padding:6px 0 16px 0;">
    <div>
        <div style="font-size:2.2rem; font-weight:800; color:#00d4ff; letter-spacing:0.02em;">
            🛡️ Cloud Cyber Threat Detection Dashboard
        </div>
        <div style="font-size:0.95rem; color:#94a3b8;">
            Dual-Engine Detection (Rule Heuristics + Isolation Forest ML) · Real-Time SOC Incident Response
        </div>
    </div>
</div>
""", unsafe_allow_html=True)


# ── Live Operational Status Banner ──────────────────────────────────────────
if not is_attack_scenario or alerts_df.empty:
    st.markdown(f"""
    <div class="status-banner-safe">
        <div style="font-size:1.15rem; font-weight:700; color:#34d399;">
            🟢 OPERATIONAL STATUS: ALL SYSTEMS HEALTHY / SAFE BASELINE
        </div>
        <div style="font-size:0.88rem; color:#cbd5e1; margin-top:3px;">
            Telemetry active ({selected_scenario}). Ingested <b>{len(logs_df):,}</b> event records.
            Zero unauthorized authentication attempts, port scans, or exfiltration spikes detected. Safe operational window.
        </div>
    </div>
    """, unsafe_allow_html=True)
else:
    crit_n = int((alerts_df["severity"] == "CRITICAL").sum()) if "severity" in alerts_df.columns else 0
    high_n = int((alerts_df["severity"] == "HIGH").sum()) if "severity" in alerts_df.columns else 0
    st.markdown(f"""
    <div class="status-banner-attack">
        <div style="font-size:1.15rem; font-weight:700; color:#f87171;">
            🚨 OPERATIONAL STATUS: ACTIVE CYBER INTRUSION DETECTED
        </div>
        <div style="font-size:0.88rem; color:#fecaca; margin-top:3px;">
            Telemetry active ({selected_scenario}). <b>{len(alerts_df)}</b> hostile incidents flagged
            (<b>{crit_n} Critical</b>, <b>{high_n} High</b>). Brute-force credential stuffing and port reconnaissance identified. SOC team response protocol engaged.
        </div>
    </div>
    """, unsafe_allow_html=True)


# ── KPI Cards Row ───────────────────────────────────────────────────────────
total_events = len(logs_df)
total_threats = len(alerts_df)

crit_count = 0
high_count = 0
med_count = 0
avg_risk = 0

if not alerts_df.empty:
    if "severity" in alerts_df.columns:
        crit_count = int((alerts_df["severity"] == "CRITICAL").sum())
        high_count = int((alerts_df["severity"] == "HIGH").sum())
        med_count = int((alerts_df["severity"] == "MEDIUM").sum())
    if "risk_score" in alerts_df.columns:
        avg_risk = int(alerts_df["risk_score"].mean())

k1, k2, k3, k4, k5 = st.columns(5)

def render_kpi(col, icon, value, label, color="#00d4ff"):
    col.markdown(f"""
    <div class="kpi-card">
        <div style="font-size:1.4rem;">{icon}</div>
        <div class="kpi-value" style="color:{color};">{value}</div>
        <div class="kpi-label">{label}</div>
    </div>
    """, unsafe_allow_html=True)

render_kpi(k1, "🔵", f"{total_events:,}", "Analyzed Telemetry", "#00d4ff")
render_kpi(k2, "🟡", f"{total_threats:,}", "Threats Detected", "#f59e0b" if total_threats > 0 else "#10b981")
render_kpi(k3, "🔴", f"{crit_count:,}", "Critical Alerts", "#ef4444" if crit_count > 0 else "#10b981")
render_kpi(k4, "🟠", f"{high_count:,}", "High Priority", "#f97316" if high_count > 0 else "#10b981")
render_kpi(k5, "🎯", f"{avg_risk}/100", "Mean Risk Score", "#ef4444" if avg_risk >= 70 else ("#f59e0b" if avg_risk > 0 else "#10b981"))

st.markdown("<br>", unsafe_allow_html=True)


# ── Analytic Graphs Section ────────────────────────────────────────────────
st.markdown("### 📊 Analytic Graphs (System Dynamic Visualizations)")

g_col1, g_col2 = st.columns([1, 1])

# Chart 1: Threat Type Distribution
with g_col1:
    if not alerts_df.empty and "threat_type" in alerts_df.columns:
        type_counts = alerts_df["threat_type"].value_counts().reset_index()
        type_counts.columns = ["Threat Category", "Count"]
        fig_donut = px.pie(
            type_counts,
            names="Threat Category",
            values="Count",
            hole=0.5,
            title="🎯 Threat Categories Flagged by Engine",
            color_discrete_sequence=["#ef4444", "#f97316", "#3b82f6", "#a855f7", "#10b981"],
        )
        fig_donut.update_layout(
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            font=dict(color="#e2e8f0"),
            height=280,
            margin=dict(t=40, b=10, l=10, r=10),
            legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5),
        )
        st.plotly_chart(fig_donut, use_container_width=True)
    else:
        # Normal dataset baseline chart
        clean_df = pd.DataFrame({
            "Traffic Classification": ["Authorized Web & Cloud Traffic", "Administrative SSH", "Routine DNS Queries"],
            "Count": [180, 70, 50]
        })
        fig_clean = px.pie(
            clean_df,
            names="Traffic Classification",
            values="Count",
            hole=0.5,
            title="🟢 Operational Traffic Breakdown (Baseline Safe)",
            color_discrete_sequence=["#10b981", "#34d399", "#6ee7b7"],
        )
        fig_clean.update_layout(
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            font=dict(color="#e2e8f0"),
            height=280,
            margin=dict(t=40, b=10, l=10, r=10),
            legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5),
        )
        st.plotly_chart(fig_clean, use_container_width=True)

# Chart 2: Threat Severity & Risk Index
with g_col2:
    if not alerts_df.empty and "severity" in alerts_df.columns:
        sev_counts = alerts_df["severity"].value_counts().reset_index()
        sev_counts.columns = ["Severity", "Alerts"]
        sev_color_map = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#3b82f6", "LOW": "#10b981"}
        fig_sev = px.bar(
            sev_counts,
            x="Severity",
            y="Alerts",
            color="Severity",
            title="⚠️ Threat Severity Breakdown (CVSS-Aligned)",
            color_discrete_map=sev_color_map,
            text_auto=True,
        )
        fig_sev.update_layout(
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            font=dict(color="#e2e8f0"),
            height=280,
            margin=dict(t=40, b=10, l=10, r=10),
            showlegend=False,
            xaxis=dict(gridcolor="#1f2937"),
            yaxis=dict(gridcolor="#1f2937"),
        )
        st.plotly_chart(fig_sev, use_container_width=True)
    else:
        # Normal dataset zero risk status
        fig_clean_bar = go.Figure(go.Indicator(
            mode="gauge+number",
            value=0,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "🟢 Threat Risk Gauge (0-100)", 'font': {'color': '#e2e8f0', 'size': 16}},
            gauge={
                'axis': {'range': [0, 100], 'tickcolor': "#94a3b8"},
                'bar': {'color': "#10b981"},
                'steps': [
                    {'range': [0, 30], 'color': "rgba(16, 185, 129, 0.2)"},
                    {'range': [30, 70], 'color': "rgba(245, 158, 11, 0.2)"},
                    {'range': [70, 100], 'color': "rgba(239, 68, 68, 0.2)"},
                ],
            }
        ))
        fig_clean_bar.update_layout(
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            font=dict(color="#e2e8f0"),
            height=280,
            margin=dict(t=40, b=10, l=30, r=30),
        )
        st.plotly_chart(fig_clean_bar, use_container_width=True)

# Chart 3 & 4 Row: Timeline & Offending Entities
g_col3, g_col4 = st.columns([1, 1])

# Chart 3: Security Telemetry Timeline & Attack Spikes
with g_col3:
    if not logs_df.empty and "timestamp" in logs_df.columns:
        try:
            ts_series = pd.to_datetime(logs_df["timestamp"], errors="coerce").dropna()
            if not ts_series.empty:
                timeline_counts = ts_series.dt.floor("1min").value_counts().sort_index()
                logs_df_time = timeline_counts.reset_index()
                logs_df_time.columns = ["timestamp", "Event Frequency"]
            else:
                logs_df_time = pd.DataFrame(columns=["timestamp", "Event Frequency"])
        except Exception:
            logs_df_time = pd.DataFrame(columns=["timestamp", "Event Frequency"])

        if not logs_df_time.empty:
            fig_time = px.area(
                logs_df_time,
                x="timestamp",
                y="Event Frequency",
                title="📈 Telemetry Ingestion Timeline & Spike Detection",
                color_discrete_sequence=["#00d4ff" if not is_attack_scenario else "#ef4444"],
            )
            fig_time.update_layout(
                paper_bgcolor="#111827",
                plot_bgcolor="#111827",
                font=dict(color="#e2e8f0"),
                height=250,
                margin=dict(t=40, b=10, l=10, r=10),
                xaxis=dict(gridcolor="#1f2937", title="Timeline (UTC)"),
                yaxis=dict(gridcolor="#1f2937", title="Events / Minute"),
            )
            st.plotly_chart(fig_time, use_container_width=True)
        else:
            st.info("No timeline events to display.")

# Chart 4: Top Targeted Cloud Ports or Top Offending IPs
with g_col4:
    if not alerts_df.empty and "source_ip" in alerts_df.columns:
        top_attackers = alerts_df["source_ip"].value_counts().head(5).reset_index()
        top_attackers.columns = ["Hostile Source IP", "Alerts Triggered"]
        fig_att = px.bar(
            top_attackers,
            x="Alerts Triggered",
            y="Hostile Source IP",
            orientation="h",
            title="🚨 Top Hostile Source IPs Detected",
            color="Alerts Triggered",
            color_continuous_scale="Reds",
        )
        fig_att.update_layout(
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            font=dict(color="#e2e8f0"),
            height=250,
            margin=dict(t=40, b=10, l=10, r=10),
            xaxis=dict(gridcolor="#1f2937"),
            yaxis=dict(gridcolor="#1f2937", autorange="reversed"),
            coloraxis_showscale=False,
        )
        st.plotly_chart(fig_att, use_container_width=True)
    else:
        # Normal dataset port usage
        port_counts = logs_df["destination_port"].value_counts().head(5).reset_index() if "destination_port" in logs_df.columns else pd.DataFrame()
        if not port_counts.empty:
            port_counts.columns = ["Port", "Count"]
            port_counts["Port"] = port_counts["Port"].astype(str)
            fig_port = px.bar(
                port_counts,
                x="Port",
                y="Count",
                title="🌐 Cloud Ingress Ports In Routine Use",
                color_discrete_sequence=["#10b981"],
            )
            fig_port.update_layout(
                paper_bgcolor="#111827",
                plot_bgcolor="#111827",
                font=dict(color="#e2e8f0"),
                height=250,
                margin=dict(t=40, b=10, l=10, r=10),
                xaxis=dict(gridcolor="#1f2937"),
                yaxis=dict(gridcolor="#1f2937"),
            )
            st.plotly_chart(fig_port, use_container_width=True)

st.markdown("<br>", unsafe_allow_html=True)


# ── Interactive Tables Section ──────────────────────────────────────────────
st.markdown("### 📋 Interactive Security Tables & SOC Operations")
st.caption("Select and filter alerts, logs, and incident remediation actions according to requirements.")

tab_alerts, tab_logs, tab_report = st.tabs([
    "🚨 Detected Threat Alerts Table & Triage",
    "📋 Cloud Security Activity Logs Table",
    "📄 Executive Threat Intelligence Summary",
])


# ── TAB 1: Detected Threat Alerts Table ─────────────────────────────────────
with tab_alerts:
    if alerts_df.empty:
        st.success("✅ **No threat alerts detected in current telemetry.** All system metrics conform to authorized cloud operational baselines.")
    else:
        # Filter controls directly above alerts table
        col_f1, col_f2, col_f3 = st.columns([1, 1, 1.5])
        with col_f1:
            severity_filter = st.selectbox(
                "Filter by Severity:",
                ["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
                key="tab1_sev_filter",
            )
        with col_f2:
            threat_type_filter = st.selectbox(
                "Filter by Threat Category:",
                ["All Categories", "brute_force", "port_scan", "abnormal_traffic", "ml_anomaly"],
                key="tab1_type_filter",
            )
        with col_f3:
            search_ip = st.text_input(
                "🔍 Search by Hostile IP:",
                placeholder="e.g. 185.220 or 192.168",
                key="search_alert_ip",
            )

        filtered_alerts = alerts_df.copy()
        
        if severity_filter != "All Severities" and "severity" in filtered_alerts.columns:
            filtered_alerts = filtered_alerts[filtered_alerts["severity"].str.upper() == severity_filter.upper()]

        if threat_type_filter != "All Categories" and "threat_type" in filtered_alerts.columns:
            filtered_alerts = filtered_alerts[filtered_alerts["threat_type"].str.lower() == threat_type_filter.lower()]

        if search_ip and "source_ip" in filtered_alerts.columns:
            filtered_alerts = filtered_alerts[filtered_alerts["source_ip"].astype(str).str.contains(search_ip, case=False, na=False)]

        st.caption(f"Showing **{len(filtered_alerts)} of {len(alerts_df)}** threat alerts:")

        # Display Clean Interactive Table
        display_cols = [c for c in [
            "alert_id", "timestamp", "threat_type", "severity", "risk_score",
            "source_ip", "destination_port", "protocol", "status", "suggested_action"
        ] if c in filtered_alerts.columns]

        st.dataframe(
            filtered_alerts[display_cols],
            use_container_width=True,
            hide_index=True,
            column_config={
                "alert_id": st.column_config.TextColumn("Alert ID", width="small"),
                "timestamp": st.column_config.DatetimeColumn("Detected At", format="YYYY-MM-DD HH:mm:ss"),
                "threat_type": st.column_config.TextColumn("Threat Category"),
                "severity": st.column_config.TextColumn("Severity"),
                "risk_score": st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100, format="%d"),
                "source_ip": st.column_config.TextColumn("Hostile Source IP"),
                "destination_port": st.column_config.NumberColumn("Target Port", format="%d"),
                "protocol": st.column_config.TextColumn("Protocol"),
                "status": st.column_config.TextColumn("Status"),
                "suggested_action": st.column_config.TextColumn("Recommended Playbook Action"),
            }
        )

        # Incident Drill-Down & Real-Life SOC Action
        st.markdown("#### 🛠️ Real-Life Incident Remediation & SOC Team Action")
        alert_ids = filtered_alerts["alert_id"].tolist() if not filtered_alerts.empty else alerts_df["alert_id"].tolist()
        
        if alert_ids:
            selected_aid = st.selectbox("Select Alert to Inspect & Mitigate:", alert_ids, key="selected_alert_inspect")
            selected_row = alerts_df[alerts_df["alert_id"] == selected_aid].iloc[0]

            act_col1, act_col2 = st.columns([2, 1])
            with act_col1:
                target_port_val = selected_row.get("destination_port")
                if pd.notna(target_port_val) and str(target_port_val).lower() != "none":
                    try:
                        port_str = f"{int(float(target_port_val))} ({selected_row.get('protocol', 'TCP')})"
                    except Exception:
                        port_str = f"{target_port_val}"
                else:
                    port_str = "N/A"

                st.markdown(f"""
                <div class="action-card">
                    <div style="font-size:1.1rem; font-weight:700; color:#00d4ff;">
                        [{selected_row.get('alert_id', 'ALT')}] {str(selected_row.get('threat_type', 'Threat')).upper()} INCIDENT
                    </div>
                    <div style="font-size:0.85rem; color:#94a3b8; margin-top:2px;">
                        MITRE ATT&CK: <b>{selected_row.get('mitre_attack', 'T1110 - Brute Force')}</b> &nbsp;|&nbsp; Current Status: <b style="color:#00d4ff;">{selected_row.get('status', 'NEW')}</b>
                    </div>
                    <hr style="border-color:#374151; margin:8px 0;">
                    <div style="font-size:0.9rem;">
                        <b>Offending Host:</b> <code>{selected_row.get('source_ip', 'N/A')}</code> &nbsp; | &nbsp;
                        <b>Target Port:</b> <code>{port_str}</code> &nbsp; | &nbsp;
                        <b>Risk Score:</b> <span style="color:#ef4444; font-weight:700;">{selected_row.get('risk_score', 0)}/100</span>
                    </div>
                    <div style="font-size:0.85rem; color:#cbd5e1; margin-top:8px;">
                        <b>Root Cause Narrative:</b> {selected_row.get('reason', 'Threshold exceeded')}
                    </div>
                    <div style="font-size:0.85rem; color:#93c5fd; margin-top:6px;">
                        <b>Playbook Recommendation:</b> {selected_row.get('suggested_action', 'Isolate IP at firewall.')}
                    </div>
                </div>
                """, unsafe_allow_html=True)

            with act_col2:
                st.markdown("**⚡ Team Defense Mitigation Action:**")
                st.caption(f"Acting as: **{soc_role}**")
                
                is_passive = "Passive" in defense_policy
                if is_passive:
                    st.info("👁️ Read-only Monitoring active. Switch defense policy in sidebar to execute countermeasures.")

                if st.button("⛔ Deploy Perimeter Firewall Block", use_container_width=True, type="primary", disabled=is_passive):
                    updated_alerts = update_alert_status(selected_aid, "MITIGATED", alerts_df)
                    st.session_state["scenario_alerts"][selected_scenario] = updated_alerts
                    st.session_state["alerts_df"] = updated_alerts
                    st.success(f"Firewall drop rule applied to {selected_row.get('source_ip')}! Status: MITIGATED.")
                    st.rerun()

                if st.button("🔒 Force MFA & User Lockout", use_container_width=True, disabled=is_passive):
                    updated_alerts = update_alert_status(selected_aid, "INVESTIGATING", alerts_df)
                    st.session_state["scenario_alerts"][selected_scenario] = updated_alerts
                    st.session_state["alerts_df"] = updated_alerts
                    st.info(f"Account lockout and MFA challenge enforced! Status: INVESTIGATING.")
                    st.rerun()

                if st.button("✅ Mark Incident Resolved", use_container_width=True, disabled=is_passive):
                    updated_alerts = update_alert_status(selected_aid, "RESOLVED", alerts_df)
                    st.session_state["scenario_alerts"][selected_scenario] = updated_alerts
                    st.session_state["alerts_df"] = updated_alerts
                    st.success(f"Alert {selected_aid} marked as RESOLVED.")
                    st.rerun()


# ── TAB 2: Cloud Security Activity Logs Table ──────────────────────────────
with tab_logs:
    if logs_df.empty:
        st.info("No logs loaded.")
    else:
        st.markdown(f"**Total Ingested Log Telemetry:** `{len(logs_df):,}` events")
        
        f_col1, f_col2 = st.columns([1, 1])
        with f_col1:
            available_events = ["All Event Types"] + sorted(list(logs_df["event_type"].dropna().unique())) if "event_type" in logs_df.columns else ["All Event Types"]
            event_choice = st.selectbox("Filter by Event Type:", available_events, key="filter_event_type")

        with f_col2:
            search_log_user = st.text_input("🔍 Search by User or IP:", placeholder="e.g. admin, root, 192.168", key="search_log_user")

        filtered_logs = logs_df.copy()
        if event_choice != "All Event Types" and "event_type" in filtered_logs.columns:
            filtered_logs = filtered_logs[filtered_logs["event_type"] == event_choice]

        if search_log_user:
            cond = pd.Series([False] * len(filtered_logs), index=filtered_logs.index)
            if "user" in filtered_logs.columns:
                cond = cond | filtered_logs["user"].astype(str).str.contains(search_log_user, case=False, na=False)
            if "source_ip" in filtered_logs.columns:
                cond = cond | filtered_logs["source_ip"].astype(str).str.contains(search_log_user, case=False, na=False)
            filtered_logs = filtered_logs[cond]

        st.caption(f"Displaying {len(filtered_logs):,} matching log telemetry records:")

        log_display_cols = [c for c in [
            "timestamp", "source_ip", "destination_ip", "source_port", "destination_port",
            "protocol", "user", "event_type", "status", "bytes"
        ] if c in filtered_logs.columns]

        st.dataframe(
            filtered_logs[log_display_cols].head(300),
            use_container_width=True,
            hide_index=True,
            column_config={
                "timestamp": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss"),
                "source_ip": st.column_config.TextColumn("Source IP"),
                "destination_ip": st.column_config.TextColumn("Target IP"),
                "destination_port": st.column_config.NumberColumn("Port", format="%d"),
                "event_type": st.column_config.TextColumn("Event Type"),
                "status": st.column_config.TextColumn("Status"),
                "bytes": st.column_config.NumberColumn("Bytes", format="%d"),
            }
        )


# ── TAB 3: Executive Threat Intelligence Summary ───────────────────────────
with tab_report:
    st.markdown("#### 📄 Executive SOC Threat Intelligence Dossier")
    st.markdown(f"**Generated:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}` &nbsp;|&nbsp; **Telemetry Source:** `{selected_scenario}`")

    rep_col1, rep_col2 = st.columns([2, 1])

    with rep_col1:
        if is_attack_scenario and not alerts_df.empty:
            top_threat = alerts_df["threat_type"].mode().iloc[0] if "threat_type" in alerts_df.columns else "brute_force"
            top_attacker = alerts_df["source_ip"].mode().iloc[0] if "source_ip" in alerts_df.columns else "Unknown"
            st.markdown(f"""
            <div class="action-card">
                <h4 style="color:#ef4444; margin-top:0;">🚨 Executive Incident Summary: ACTIVE ATTACK</h4>
                <p>During the evaluated telemetry window, CyberShield identified <b>{len(alerts_df)}</b> high-confidence security alerts.</p>
                <ul>
                    <li><b>Predominant Attack Vector:</b> {str(top_threat).upper()}</li>
                    <li><b>Primary Threat Actor (Hostile IP):</b> <code>{top_attacker}</code></li>
                    <li><b>Mean Severity Risk Index:</b> {avg_risk}/100</li>
                    <li><b>Dual Detection Validation:</b> Deterministic rules identified repeated SSH credential-stuffing and network service sweeps. Isolation Forest anomaly detection confirmed abnormal traffic exfiltration.</li>
                </ul>
                <h5 style="color:#00d4ff;">Recommended Immediate Actions:</h5>
                <ol>
                    <li>Block hostile IPs (<code>{top_attacker}</code>) at perimeter AWS Security Groups / VPC Network ACLs.</li>
                    <li>Enforce Multi-Factor Authentication (MFA) and temporary lockout on targeted administrative accounts.</li>
                    <li>Review open ingress ports (SSH Port 22, RDP Port 3389) and restrict to authorized bastion jump-hosts.</li>
                </ol>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="action-card">
                <h4 style="color:#34d399; margin-top:0;">🟢 Executive Incident Summary: CLEAN BASELINE</h4>
                <p>Telemetry review indicates <b>safe operational status</b> across all monitored cloud instances.</p>
                <ul>
                    <li><b>Ingested Telemetry Events:</b> {len(logs_df):,}</li>
                    <li><b>Intrusion Alerts Flagged:</b> 0</li>
                    <li><b>Perimeter Status:</b> Authorized API calls and routine user sessions verified.</li>
                </ul>
                <p style="color:#94a3b8;">No remediation or firewall changes required at this time.</p>
            </div>
            """, unsafe_allow_html=True)

    with rep_col2:
        st.markdown("**📥 Export SOC Artifacts**")
        
        # Prepare text report
        txt_lines = [
            "=" * 70,
            f"CYBERSHIELD SOC THREAT INTELLIGENCE SUMMARY",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Scenario : {selected_scenario}",
            f"Events   : {len(logs_df):,}",
            f"Alerts   : {len(alerts_df)}",
            "=" * 70,
        ]
        if not alerts_df.empty:
            for _, r in alerts_df.iterrows():
                txt_lines.append(f"[{r.get('alert_id')}] [{r.get('severity')}] {r.get('threat_type')} from {r.get('source_ip')} -> Risk: {r.get('risk_score')}")
        else:
            txt_lines.append("Status: Clean operational baseline. Zero threats detected.")
        txt_report = "\n".join(txt_lines)

        st.download_button(
            label="📄 Download Summary Report (TXT)",
            data=txt_report,
            file_name=f"Threat_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
            use_container_width=True,
        )

        if not alerts_df.empty:
            csv_alerts = alerts_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="📊 Export Alerts Telemetry (CSV)",
                data=csv_alerts,
                file_name=f"Threat_Alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True,
            )

st.markdown("<hr style='border:1px solid #1e293b; margin:25px 0 10px 0;'>", unsafe_allow_html=True)
st.caption("CyberShield · Cloud-Based Cyber Threat Detection & Autonomous SOC Platform · Cloud Application Development")
