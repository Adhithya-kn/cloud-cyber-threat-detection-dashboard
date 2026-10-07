"""
pages/04_📈_Analytics.py
========================
Threat Analytics & Intelligence Page for CyberShield Dashboard.

Displays:
- Top-level attack distribution (pie/bar)
- Severity & risk score histograms
- Top attacker source IPs
- Threat timeline over time
- Port targeting heatmap / distribution
- Protocol breakdown
"""

import sys
import os
sys.path.insert(0, ".")

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta

from utils.alert_manager import load_alerts
from utils.log_parser import load_data, normalize_events

st.set_page_config(
    page_title="Threat Analytics | CyberShield",
    page_icon="📈",
    layout="wide",
)

# Custom SOC Dark styling
st.markdown("""
<style>
.main { background-color: #0a0e1a; }
.stApp { background-color: #0a0e1a; }
.metric-box {
    background: linear-gradient(135deg, #111827 0%, #1f2937 100%);
    border: 1px solid #374151;
    border-radius: 10px;
    padding: 16px;
    text-align: center;
}
.metric-val { font-size: 2rem; font-weight: 700; color: #00d4ff; }
.metric-lbl { font-size: 0.85rem; color: #9ca3af; text-transform: uppercase; }
</style>
""", unsafe_allow_html=True)

st.title("📈 Threat Analytics & Intelligence")
st.markdown("Detailed breakdown of attack surfaces, threat distributions, and anomaly signatures.")

# ---------------------------------------------------------------------------
# Data Loading
# ---------------------------------------------------------------------------
def get_analytics_data():
    if "alerts_df" in st.session_state and not st.session_state["alerts_df"].empty:
        alerts_df = st.session_state["alerts_df"].copy()
    else:
        alerts_df = load_alerts("data/alerts.csv")

    if "logs_df" in st.session_state and not st.session_state["logs_df"].empty:
        logs_df = st.session_state["logs_df"].copy()
    elif os.path.exists("data/demo_security_logs.csv"):
        logs_df = load_data("data/demo_security_logs.csv")
        logs_df = normalize_events(logs_df)
    else:
        logs_df = pd.DataFrame()

    return alerts_df, logs_df

alerts_df, logs_df = get_analytics_data()

# Ensure timestamp is datetime
if not alerts_df.empty and "timestamp" in alerts_df.columns:
    alerts_df["timestamp"] = pd.to_datetime(alerts_df["timestamp"], errors="coerce")

# ---------------------------------------------------------------------------
# Filter bar
# ---------------------------------------------------------------------------
col_f1, col_f2 = st.columns([2, 2])
with col_f1:
    time_filter = st.selectbox("Time Horizon", ["All Time (Last 24h)", "Past 6 Hours", "Past 1 Hour"])
with col_f2:
    selected_severities = st.multiselect(
        "Filter Severities",
        options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    )

filtered_alerts = alerts_df.copy()

# Apply time filter
if time_filter != "All Time (Last 24h)" and "timestamp" in filtered_alerts.columns and not filtered_alerts.empty:
    hrs = 6 if "6" in time_filter else 1
    cutoff = datetime.now() - timedelta(hours=hrs)
    filtered_alerts = filtered_alerts[filtered_alerts["timestamp"] >= cutoff]

# Apply severity filter case-insensitively
if selected_severities and "severity" in filtered_alerts.columns:
    filtered_alerts = filtered_alerts[filtered_alerts["severity"].astype(str).str.upper().isin([s.upper() for s in selected_severities])]

# ---------------------------------------------------------------------------
# Row 1: Key Metrics
# ---------------------------------------------------------------------------
top_threat = str(filtered_alerts["threat_type"].mode().iloc[0]).upper() if not filtered_alerts.empty and "threat_type" in filtered_alerts.columns else "NONE"
top_ip = filtered_alerts["source_ip"].mode().iloc[0] if not filtered_alerts.empty and "source_ip" in filtered_alerts.columns else "NONE"
avg_risk = int(filtered_alerts["risk_score"].mean()) if not filtered_alerts.empty and "risk_score" in filtered_alerts.columns else 0

m1, m2, m3, m4 = st.columns(4)
with m1:
    st.markdown(f'<div class="metric-box"><div class="metric-val">{len(filtered_alerts)}</div><div class="metric-lbl">Active Detections</div></div>', unsafe_allow_html=True)
with m2:
    st.markdown(f'<div class="metric-box"><div class="metric-val" style="color:#ef4444;">{top_threat}</div><div class="metric-lbl">Most Frequent Threat</div></div>', unsafe_allow_html=True)
with m3:
    st.markdown(f'<div class="metric-box"><div class="metric-val" style="color:#f59e0b;">{top_ip}</div><div class="metric-lbl">Primary Offender IP</div></div>', unsafe_allow_html=True)
with m4:
    st.markdown(f'<div class="metric-box"><div class="metric-val" style="color:#10b981;">{avg_risk}/100</div><div class="metric-lbl">Mean Risk Index</div></div>', unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Executive Threat Intelligence Summary Report Box
# ---------------------------------------------------------------------------
with st.expander("📄 View Threat Intelligence & Analytical Report", expanded=True):
    r_lines = []
    r_lines.append(f"THREAT ANALYTICS REPORT — Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    r_lines.append(f"Time Horizon Filter   : {time_filter}")
    r_lines.append(f"Severity Filter       : {', '.join(selected_severities) if selected_severities else 'ALL'}")
    r_lines.append(f"Total Threat Matches  : {len(filtered_alerts)} incidents")
    if not filtered_alerts.empty:
        r_lines.append(f"Primary Attack Vector : {top_threat}")
        r_lines.append(f"Chief Source IP       : {top_ip}")
        r_lines.append(f"Average Threat Score  : {avg_risk} / 100")
        if "threat_type" in filtered_alerts.columns:
            t_counts = filtered_alerts["threat_type"].value_counts().to_dict()
            r_lines.append(f"Vectors Breakdown     : {', '.join([f'{k}: {v}' for k, v in t_counts.items()])}")
    else:
        r_lines.append("No security anomalies or attack vectors meet the selected filter criteria.")
    r_str = "\n".join(r_lines)
    st.markdown(f'<div style="background:#111827;border:1px solid #374151;border-radius:8px;padding:14px;color:#e2e8f0;font-family:monospace;white-space:pre-wrap;">{r_str}</div>', unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Row 2: Charts (Threat Type & Severity Distribution & Risk Score Histogram)
# ---------------------------------------------------------------------------
c1, c2, c3 = st.columns(3)

color_palette = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#3b82f6",
    "LOW": "#22c55e",
    "brute_force": "#dc2626",
    "port_scan": "#f59e0b",
    "abnormal_traffic": "#8b5cf6",
    "ml_anomaly": "#06b6d4"
}

with c1:
    st.subheader("🎯 Attack Distribution")
    if not filtered_alerts.empty and "threat_type" in filtered_alerts.columns:
        threat_counts = filtered_alerts["threat_type"].value_counts().reset_index()
        threat_counts.columns = ["threat_type", "count"]
        fig_pie = px.pie(
            threat_counts,
            names="threat_type",
            values="count",
            hole=0.45,
            color="threat_type",
            color_discrete_map=color_palette,
        )
        fig_pie.update_layout(
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            font=dict(color="#e2e8f0"),
            showlegend=True,
            margin=dict(t=10, b=10, l=10, r=10)
        )
        st.plotly_chart(fig_pie, use_container_width=True)
    else:
        st.info("No data available.")

with c2:
    st.subheader("🛡️ Severity Breakdown")
    if not filtered_alerts.empty and "severity" in filtered_alerts.columns:
        sev_counts = filtered_alerts["severity"].value_counts().reset_index()
        sev_counts.columns = ["severity", "count"]
        fig_sev = px.bar(
            sev_counts,
            x="severity",
            y="count",
            color="severity",
            color_discrete_map=color_palette,
        )
        fig_sev.update_layout(
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            font=dict(color="#e2e8f0"),
            showlegend=False,
            margin=dict(t=10, b=10, l=10, r=10),
            xaxis_title="",
            yaxis_title="Count"
        )
        st.plotly_chart(fig_sev, use_container_width=True)
    else:
        st.info("No data available.")

with c3:
    st.subheader("📊 Risk Score Distribution")
    if not filtered_alerts.empty and "risk_score" in filtered_alerts.columns:
        fig_hist = px.histogram(
            filtered_alerts,
            x="risk_score",
            nbins=15,
            color_discrete_sequence=["#00d4ff"]
        )
        fig_hist.update_layout(
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            font=dict(color="#e2e8f0"),
            margin=dict(t=10, b=10, l=10, r=10),
            xaxis_title="Risk Score (0-100)",
            yaxis_title="Frequency"
        )
        st.plotly_chart(fig_hist, use_container_width=True)
    else:
        st.info("No data available.")

# ---------------------------------------------------------------------------
# Row 3: Top Attacker IPs & Timeline
# ---------------------------------------------------------------------------
col_ip, col_time = st.columns([1, 1])

with col_ip:
    st.subheader("🚨 Top Source IPs by Alerts")
    if not filtered_alerts.empty and "source_ip" in filtered_alerts.columns:
        ip_counts = filtered_alerts["source_ip"].value_counts().head(8).reset_index()
        ip_counts.columns = ["source_ip", "alert_count"]
        fig_ip = px.bar(
            ip_counts,
            y="source_ip",
            x="alert_count",
            orientation="h",
            color="alert_count",
            color_continuous_scale="Reds",
        )
        fig_ip.update_layout(
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            font=dict(color="#e2e8f0"),
            coloraxis_showscale=False,
            margin=dict(t=10, b=10, l=10, r=10),
            yaxis=dict(autorange="reversed"),
            xaxis_title="Alert Count",
            yaxis_title="Source IP"
        )
        st.plotly_chart(fig_ip, use_container_width=True)
    else:
        st.info("No IP data available.")

with col_time:
    st.subheader("⏱️ Threat Frequency Timeline")
    if not filtered_alerts.empty and "timestamp" in filtered_alerts.columns:
        df_time = filtered_alerts.dropna(subset=["timestamp"]).copy()
        df_time["hour"] = df_time["timestamp"].dt.floor("h")
        time_trend = df_time.groupby(["hour", "threat_type"]).size().reset_index(name="count")
        
        fig_timeline = px.area(
            time_trend,
            x="hour",
            y="count",
            color="threat_type",
            color_discrete_map=color_palette,
        )
        fig_timeline.update_layout(
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            font=dict(color="#e2e8f0"),
            margin=dict(t=10, b=10, l=10, r=10),
            xaxis_title="Time",
            yaxis_title="Detections"
        )
        st.plotly_chart(fig_timeline, use_container_width=True)
    else:
        st.info("No timeline data available.")

# ---------------------------------------------------------------------------
# Row 4: Network telemetry breakdown (from logs)
# ---------------------------------------------------------------------------
if not logs_df.empty:
    st.markdown("---")
    st.subheader("🌐 Network Telemetry & Port Distribution")
    col_p1, col_p2 = st.columns(2)
    
    with col_p1:
        if "protocol" in logs_df.columns:
            proto_df = logs_df["protocol"].value_counts().reset_index()
            proto_df.columns = ["protocol", "events"]
            fig_proto = px.bar(
                proto_df,
                x="protocol",
                y="events",
                color="events",
                color_continuous_scale="Teal",
            )
            fig_proto.update_layout(
                paper_bgcolor="#111827",
                plot_bgcolor="#111827",
                font=dict(color="#e2e8f0"),
                coloraxis_showscale=False,
                margin=dict(t=10, b=10, l=10, r=10),
                xaxis_title="Protocol",
                yaxis_title="Observed Flows"
            )
            st.plotly_chart(fig_proto, use_container_width=True)

    with col_p2:
        if "destination_port" in logs_df.columns:
            ports_df = logs_df["destination_port"].value_counts().head(10).reset_index()
            ports_df.columns = ["destination_port", "frequency"]
            ports_df["destination_port"] = ports_df["destination_port"].astype(str)
            fig_ports = px.bar(
                ports_df,
                x="destination_port",
                y="frequency",
                color="frequency",
                color_continuous_scale="Purples",
            )
            fig_ports.update_layout(
                paper_bgcolor="#111827",
                plot_bgcolor="#111827",
                font=dict(color="#e2e8f0"),
                coloraxis_showscale=False,
                margin=dict(t=10, b=10, l=10, r=10),
                xaxis_title="Destination Port",
                yaxis_title="Connection Count"
            )
            st.plotly_chart(fig_ports, use_container_width=True)
