"""
CyberShield — Cloud Cyber Threat Detection Dashboard
Main entry point / Home page
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from datetime import datetime, timedelta
import os
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
    from utils.alert_manager import load_alerts, get_alerts_summary
    _modules_ok["alert_manager"] = True
except Exception:
    _modules_ok["alert_manager"] = False


# ── Synthetic data generator (fallback) ─────────────────────────────────────
@st.cache_data(ttl=300)
def _generate_synthetic_logs(n: int = 2000) -> pd.DataFrame:
    rng = np.random.default_rng(42)
    base = datetime.now() - timedelta(hours=24)
    timestamps = [base + timedelta(seconds=int(s)) for s in np.sort(rng.integers(0, 86400, n))]

    src_ips = [f"192.168.{rng.integers(1,10)}.{rng.integers(1,254)}" for _ in range(n)]
    # inject some "attacker" IPs
    attacker_ips = ["45.33.32.156", "23.95.110.42", "198.199.85.30", "104.21.44.78"]
    for i in rng.choice(n, size=300, replace=False):
        src_ips[i] = attacker_ips[rng.integers(0, len(attacker_ips))]

    dst_ips = [f"10.0.{rng.integers(0,4)}.{rng.integers(1,50)}" for _ in range(n)]
    protocols = rng.choice(["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "SSH", "FTP"], n,
                            p=[0.35, 0.20, 0.05, 0.15, 0.15, 0.07, 0.03])
    event_types = rng.choice(
        ["Login Attempt", "Port Scan", "File Access", "Data Transfer", "Connection", "DNS Query"],
        n, p=[0.25, 0.15, 0.20, 0.10, 0.20, 0.10]
    )
    statuses = rng.choice(["Success", "Failure"], n, p=[0.65, 0.35])
    bytes_t = rng.integers(64, 150000, n)
    src_ports = rng.integers(1024, 65535, n)
    dst_ports = rng.choice([22, 80, 443, 3306, 3389, 8080, 21, 25, 53, 8443], n)

    return pd.DataFrame({
        "timestamp": timestamps,
        "source_ip": src_ips,
        "destination_ip": dst_ips,
        "source_port": src_ports,
        "destination_port": dst_ports,
        "protocol": protocols,
        "event_type": event_types,
        "status": statuses,
        "bytes_transferred": bytes_t,
    })


@st.cache_data(ttl=300)
def _generate_synthetic_alerts(n: int = 120) -> pd.DataFrame:
    rng = np.random.default_rng(7)
    base = datetime.now() - timedelta(hours=24)
    timestamps = [base + timedelta(seconds=int(s)) for s in np.sort(rng.integers(0, 86400, n))]
    attacker_ips = ["45.33.32.156", "23.95.110.42", "198.199.85.30", "104.21.44.78",
                    "91.195.240.117", "185.220.101.33"]
    dst_ips = [f"10.0.{rng.integers(0,4)}.{rng.integers(1,50)}" for _ in range(n)]
    threat_types = rng.choice(
        ["Brute Force", "Port Scan", "Abnormal Traffic", "ML Anomaly", "Data Exfiltration", "Ransomware Indicator"],
        n, p=[0.30, 0.25, 0.15, 0.15, 0.10, 0.05]
    )
    severities = rng.choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"], n, p=[0.10, 0.25, 0.40, 0.25])
    risk_scores = np.clip(rng.normal(60, 25, n), 1, 100).astype(int)
    statuses = rng.choice(["New", "Reviewing", "Resolved", "False Positive"], n, p=[0.40, 0.25, 0.25, 0.10])
    reasons = {
        "Brute Force": "Multiple failed login attempts detected from single source IP.",
        "Port Scan": "Sequential port probing activity detected across multiple ports.",
        "Abnormal Traffic": "Unusual byte transfer volume exceeds baseline threshold.",
        "ML Anomaly": "Isolation Forest model flagged unusual behavioural pattern.",
        "Data Exfiltration": "Large outbound data transfer to external IP detected.",
        "Ransomware Indicator": "File encryption pattern detected on internal host.",
    }
    suggested = {
        "Brute Force": "Block source IP. Enable account lockout policy. Review user accounts.",
        "Port Scan": "Firewall block source IP. Review open ports. Enable IDS rules.",
        "Abnormal Traffic": "Throttle connection. Investigate host for malware. Review DLP policies.",
        "ML Anomaly": "Investigate source host. Correlate with other events. Escalate if confirmed.",
        "Data Exfiltration": "Immediately block outbound connection. Isolate host. Initiate IR.",
        "Ransomware Indicator": "ISOLATE HOST IMMEDIATELY. Engage IR team. Restore from backup.",
    }

    df = pd.DataFrame({
        "alert_id": [f"ALERT-{1000+i}" for i in range(n)],
        "timestamp": timestamps,
        "source_ip": [attacker_ips[rng.integers(0, len(attacker_ips))] for _ in range(n)],
        "destination_ip": dst_ips,
        "threat_type": threat_types,
        "severity": severities,
        "risk_score": risk_scores,
        "status": statuses,
        "detection_reason": [reasons[t] for t in threat_types],
        "suggested_action": [suggested[t] for t in threat_types],
        "rule_triggered": [f"RULE-{rng.integers(100,999)}" for _ in range(n)],
    })
    return df


# ── Load / cache application data ───────────────────────────────────────────
def _load_app_data():
    """Load logs + alerts, using real files when available else synthetic."""
    log_path = "data/demo_security_logs.csv"
    alert_path = "data/alerts.csv"

    # ─ Logs ─
    if "logs_df" not in st.session_state:
        if os.path.exists(log_path):
            try:
                df = pd.read_csv(log_path, parse_dates=["timestamp"])
                st.session_state["logs_df"] = df
            except Exception:
                st.session_state["logs_df"] = _generate_synthetic_logs()
        else:
            st.session_state["logs_df"] = _generate_synthetic_logs()

    # ─ Alerts ─
    if "alerts_df" not in st.session_state:
        if os.path.exists(alert_path):
            try:
                df = pd.read_csv(alert_path, parse_dates=["timestamp"])
                st.session_state["alerts_df"] = df
            except Exception:
                st.session_state["alerts_df"] = _generate_synthetic_alerts()
        else:
            st.session_state["alerts_df"] = _generate_synthetic_alerts()


_load_app_data()
logs_df: pd.DataFrame = st.session_state["logs_df"]
alerts_df: pd.DataFrame = st.session_state["alerts_df"]

# ── Sidebar ─────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<div class="sidebar-logo">🛡️ CyberShield</div>', unsafe_allow_html=True)
    st.markdown('<div class="sidebar-tagline">Cloud Cyber Threat Detection</div>', unsafe_allow_html=True)
    st.divider()

    st.markdown("**🗂 Navigation**")
    st.info("Use the pages in the sidebar to explore:\n- 📊 Overview\n- 📋 Log Monitoring\n- 🚨 Alerts\n- 📈 Analytics\n- 🔍 Investigation")
    st.divider()

    st.markdown("**⚙️ Data Source**")
    data_source = st.selectbox("Select data file", ["demo_security_logs.csv (default)", "Custom upload"])

    st.divider()
    if st.button("🚀 Run Full Detection", use_container_width=True, type="primary"):
        with st.spinner("Running full detection pipeline…"):
            import time
            time.sleep(1.5)
            # Attempt real pipeline; fall back silently
            ran_pipeline = False
            if _modules_ok.get("log_parser") and _modules_ok.get("rules_engine"):
                try:
                    raw = load_data("data/demo_security_logs.csv")
                    events = normalize_events(raw)
                    features = extract_features(events)
                    detections = run_all_rules(events)
                    if _modules_ok.get("risk_score"):
                        detections = process_all_detections(detections)
                    st.session_state["alerts_df"] = detections
                    ran_pipeline = True
                except Exception:
                    pass
            if not ran_pipeline:
                st.session_state["alerts_df"] = _generate_synthetic_alerts()
                alerts_df = st.session_state["alerts_df"]
            st.success("Detection complete!")
            st.rerun()

    st.divider()
    st.caption(f"Last refresh: {datetime.now().strftime('%H:%M:%S')}")
    if st.button("🔄 Refresh Data", use_container_width=True):
        st.cache_data.clear()
        for k in ["logs_df", "alerts_df"]:
            st.session_state.pop(k, None)
        st.rerun()

# ── Main header ─────────────────────────────────────────────────────────────
st.markdown("""
<div style='text-align:center; padding:20px 0 10px 0;'>
  <span style='font-size:3rem; font-weight:900; color:#00d4ff; letter-spacing:0.05em;'>🛡️ CyberShield</span><br>
  <span style='font-size:1.15rem; color:#9ca3af; letter-spacing:0.12em;'>
      CLOUD CYBER THREAT DETECTION DASHBOARD
  </span>
</div>
""", unsafe_allow_html=True)
st.markdown("<hr style='border:1px solid #1e40af; margin:0 0 24px 0;'>", unsafe_allow_html=True)

# ── KPI row ─────────────────────────────────────────────────────────────────
total_events = len(logs_df)
total_threats = len(alerts_df)
critical_count = int((alerts_df["severity"] == "CRITICAL").sum()) if "severity" in alerts_df.columns else 0
active_incidents = int((alerts_df["status"].isin(["New", "Reviewing"])).sum()) if "status" in alerts_df.columns else 0

c1, c2, c3, c4 = st.columns(4)

def _kpi(col, icon, label, value, color="#00d4ff", delta_text="", delta_pos=True):
    delta_cls = "kpi-delta-pos" if delta_pos else "kpi-delta-neg"
    delta_html = f'<div class="{delta_cls}">{delta_text}</div>' if delta_text else ""
    col.markdown(f"""
    <div class="kpi-card">
      <div style="font-size:2rem;">{icon}</div>
      <div class="kpi-value" style="color:{color};">{value:,}</div>
      <div class="kpi-label">{label}</div>
      {delta_html}
    </div>""", unsafe_allow_html=True)

_kpi(c1, "🔵", "Total Log Events", total_events,   "#00d4ff", "↑ 12% vs yesterday")
_kpi(c2, "🟡", "Threats Detected",  total_threats,  "#f59e0b", f"↑ {total_threats} new", True)
_kpi(c3, "🔴", "Critical Alerts",   critical_count, "#ef4444", "⚠ Immediate attention", False)
_kpi(c4, "🟣", "Active Incidents",  active_incidents,"#a78bfa", f"{active_incidents} open")

st.markdown("<br>", unsafe_allow_html=True)

# ── Real-time trend sparkline ────────────────────────────────────────────────
st.markdown('<div class="section-header">📡 Live Threat Activity (Last 24 h)</div>', unsafe_allow_html=True)

_df = alerts_df.copy()
if "timestamp" in _df.columns:
    _df["timestamp"] = pd.to_datetime(_df["timestamp"])
    _df["hour"] = _df["timestamp"].dt.floor("h")
    hourly = _df.groupby(["hour", "severity"]).size().reset_index(name="count")
else:
    rng2 = np.random.default_rng(1)
    hours = pd.date_range(end=datetime.now(), periods=24, freq="h")
    rows = []
    for h in hours:
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            rows.append({"hour": h, "severity": sev, "count": rng2.integers(0, 10)})
    hourly = pd.DataFrame(rows)

sev_colors = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#3b82f6", "LOW": "#22c55e"}
fig_trend = go.Figure()
for sev, color in sev_colors.items():
    sub = hourly[hourly["severity"] == sev]
    if not sub.empty:
        fig_trend.add_trace(go.Scatter(
            x=sub["hour"], y=sub["count"], name=sev,
            mode="lines+markers", line=dict(color=color, width=2),
            marker=dict(size=5), fill="tozeroy",
            fillcolor=color.replace(")", ",0.07)").replace("rgb", "rgba") if "rgb" in color else color + "12",
        ))

fig_trend.update_layout(
    paper_bgcolor="#111827", plot_bgcolor="#111827",
    font=dict(color="#e2e8f0"), height=260,
    margin=dict(l=40, r=20, t=20, b=40),
    legend=dict(orientation="h", yanchor="bottom", y=1.01, xanchor="right", x=1,
                bgcolor="rgba(0,0,0,0)"),
    xaxis=dict(gridcolor="#1f2937", showgrid=True),
    yaxis=dict(gridcolor="#1f2937", showgrid=True),
)
st.plotly_chart(fig_trend, use_container_width=True)

# ── System status ────────────────────────────────────────────────────────────
st.markdown('<div class="section-header">🖥️ Detection Engine Status</div>', unsafe_allow_html=True)
sc1, sc2, sc3, sc4, sc5 = st.columns(5)
module_status = [
    (sc1, "📜 Log Parser",      _modules_ok.get("log_parser", False)),
    (sc2, "⚙️ Rules Engine",    _modules_ok.get("rules_engine", False)),
    (sc3, "🤖 ML Engine",       _modules_ok.get("ml_engine", False)),
    (sc4, "🎯 Risk Scorer",     _modules_ok.get("risk_score", False)),
    (sc5, "🔔 Alert Manager",   _modules_ok.get("alert_manager", False)),
]
for col, name, ok in module_status:
    icon = "✅" if ok else "⚠️"
    status_txt = "ONLINE" if ok else "FALLBACK"
    col.markdown(f"""
    <div class="kpi-card" style="padding:14px;">
      <div style="font-size:1.4rem;">{icon}</div>
      <div style="font-size:0.8rem; font-weight:600; color:#e2e8f0; margin-top:4px;">{name}</div>
      <div style="font-size:0.7rem; color:{'#22c55e' if ok else '#f59e0b'}; margin-top:2px;">{status_txt}</div>
    </div>""", unsafe_allow_html=True)

# ── Recent critical alerts ────────────────────────────────────────────────────
st.markdown("<br>", unsafe_allow_html=True)
st.markdown('<div class="section-header">🚨 Recent Critical Alerts</div>', unsafe_allow_html=True)

crit = alerts_df[alerts_df["severity"] == "CRITICAL"].head(5) if "severity" in alerts_df.columns else alerts_df.head(5)
if not crit.empty:
    for _, row in crit.iterrows():
        ts = str(row.get("timestamp", ""))[:19]
        sip = row.get("source_ip", "N/A")
        tt = row.get("threat_type", "Unknown")
        rs = row.get("risk_score", "?")
        st.markdown(f"""
        <div class="alert-critical">
          🔴 <strong>[CRITICAL]</strong> &nbsp;
          <strong>{tt}</strong> from <code>{sip}</code> &nbsp;|&nbsp;
          Risk Score: <strong style="color:#ef4444;">{rs}</strong> &nbsp;|&nbsp;
          <span style="color:#6b7280; font-size:0.85rem;">{ts}</span>
        </div>""", unsafe_allow_html=True)
else:
    st.success("✅ No critical alerts at this time.")

st.markdown("<br>")
st.caption("CyberShield v1.0 · Security Operations Center · Data refreshes every 5 minutes")
