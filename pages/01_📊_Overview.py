"""
Page 1 — Overview Dashboard
KPI cards, trend charts, severity donut, top threats, recent alerts
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import os
import sys

sys.path.insert(0, ".")

st.set_page_config(page_title="Overview | CyberShield", page_icon="📊", layout="wide")

# ── CSS (shared) ────────────────────────────────────────────────────────────
st.markdown("""<style>
.main{background:#0a0e1a;} .stApp{background:#0a0e1a;}
#MainMenu{visibility:hidden;} footer{visibility:hidden;} header{visibility:hidden;}
[data-testid="stSidebar"]{background:#0d1117;border-right:1px solid #21262d;}
.kpi-card{background:linear-gradient(135deg,#111827 0%,#1f2937 100%);border:1px solid #374151;
  border-radius:12px;padding:20px;text-align:center;box-shadow:0 4px 6px rgba(0,0,0,0.3);}
.kpi-value{font-size:2.5rem;font-weight:700;color:#00d4ff;line-height:1.1;}
.kpi-label{font-size:0.85rem;color:#9ca3af;text-transform:uppercase;letter-spacing:0.05em;margin-top:4px;}
.section-hdr{font-size:1.1rem;font-weight:600;color:#00d4ff;
  border-bottom:1px solid #1e40af;padding-bottom:6px;margin-bottom:14px;}
.badge-critical{background:#7f1d1d;color:#fca5a5;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600;}
.badge-high{background:#78350f;color:#fcd34d;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600;}
.badge-medium{background:#1e3a5f;color:#93c5fd;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600;}
.badge-low{background:#064e3b;color:#6ee7b7;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600;}
</style>""", unsafe_allow_html=True)

CHART_LAYOUT = dict(
    paper_bgcolor="#111827", plot_bgcolor="#111827",
    font=dict(color="#e2e8f0"), margin=dict(l=40, r=20, t=40, b=40),
    legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color="#e2e8f0")),
)
SEV_COLORS = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#3b82f6", "LOW": "#22c55e"}


# ── Synthetic generators ─────────────────────────────────────────────────────
@st.cache_data(ttl=300)
def _gen_logs(n=2000):
    rng = np.random.default_rng(42)
    base = datetime.now() - timedelta(hours=24)
    ts = [base + timedelta(seconds=int(s)) for s in np.sort(rng.integers(0, 86400, n))]
    attackers = ["45.33.32.156", "23.95.110.42", "198.199.85.30", "104.21.44.78"]
    src = [f"192.168.{rng.integers(1,10)}.{rng.integers(1,254)}" for _ in range(n)]
    for i in rng.choice(n, 300, replace=False): src[i] = attackers[rng.integers(0, 4)]
    et = rng.choice(["Login Attempt","Port Scan","File Access","Data Transfer","Connection","DNS Query"],
                    n, p=[0.25,0.15,0.20,0.10,0.20,0.10])
    st2 = rng.choice(["Success","Failure"], n, p=[0.65,0.35])
    proto = rng.choice(["TCP","UDP","ICMP","HTTP","HTTPS","SSH","FTP"], n,
                       p=[0.35,0.20,0.05,0.15,0.15,0.07,0.03])
    return pd.DataFrame({"timestamp":ts,"source_ip":src,
        "destination_ip":[f"10.0.{rng.integers(0,4)}.{rng.integers(1,50)}" for _ in range(n)],
        "source_port":rng.integers(1024,65535,n),
        "destination_port":rng.choice([22,80,443,3306,3389,8080,21,25,53],n),
        "protocol":proto,"event_type":et,"status":st2,
        "bytes_transferred":rng.integers(64,150000,n)})


@st.cache_data(ttl=300)
def _gen_alerts(n=120):
    rng = np.random.default_rng(7)
    base = datetime.now() - timedelta(hours=24)
    ts = [base + timedelta(seconds=int(s)) for s in np.sort(rng.integers(0, 86400, n))]
    attackers = ["45.33.32.156","23.95.110.42","198.199.85.30","104.21.44.78","91.195.240.117","185.220.101.33"]
    tt = rng.choice(["Brute Force","Port Scan","Abnormal Traffic","ML Anomaly","Data Exfiltration","Ransomware Indicator"],
                    n, p=[0.30,0.25,0.15,0.15,0.10,0.05])
    sev = rng.choice(["CRITICAL","HIGH","MEDIUM","LOW"], n, p=[0.10,0.25,0.40,0.25])
    reasons = {
        "Brute Force":"Multiple failed login attempts detected from single source IP.",
        "Port Scan":"Sequential port probing activity detected.",
        "Abnormal Traffic":"Unusual byte transfer volume exceeds baseline threshold.",
        "ML Anomaly":"Isolation Forest model flagged unusual behavioural pattern.",
        "Data Exfiltration":"Large outbound data transfer to external IP detected.",
        "Ransomware Indicator":"File encryption pattern detected on internal host.",
    }
    suggested = {
        "Brute Force":"Block source IP. Enable account lockout policy.",
        "Port Scan":"Firewall block source IP. Review open ports.",
        "Abnormal Traffic":"Throttle connection. Investigate host for malware.",
        "ML Anomaly":"Investigate source host. Correlate with other events.",
        "Data Exfiltration":"Immediately block outbound connection. Isolate host.",
        "Ransomware Indicator":"ISOLATE HOST IMMEDIATELY. Engage IR team.",
    }
    return pd.DataFrame({
        "alert_id":[f"ALERT-{1000+i}" for i in range(n)],
        "timestamp":ts,
        "source_ip":[attackers[rng.integers(0,len(attackers))] for _ in range(n)],
        "destination_ip":[f"10.0.{rng.integers(0,4)}.{rng.integers(1,50)}" for _ in range(n)],
        "threat_type":tt,"severity":sev,
        "risk_score":np.clip(rng.normal(60,25,n),1,100).astype(int),
        "status":rng.choice(["New","Reviewing","Resolved","False Positive"],n,p=[0.40,0.25,0.25,0.10]),
        "detection_reason":[reasons[t] for t in tt],
        "suggested_action":[suggested[t] for t in tt],
    })


def _load():
    logs = st.session_state.get("logs_df")
    if logs is None:
        p = "data/demo_security_logs.csv"
        if os.path.exists(p):
            try: logs = pd.read_csv(p, parse_dates=["timestamp"])
            except: logs = _gen_logs()
        else: logs = _gen_logs()
        st.session_state["logs_df"] = logs

    alerts = st.session_state.get("alerts_df")
    if alerts is None:
        p = "data/alerts.csv"
        if os.path.exists(p):
            try: alerts = pd.read_csv(p, parse_dates=["timestamp"])
            except: alerts = _gen_alerts()
        else: alerts = _gen_alerts()
        st.session_state["alerts_df"] = alerts
    return logs, alerts


# ── Page ─────────────────────────────────────────────────────────────────────
st.markdown("# 📊 Overview — Threat Intelligence Dashboard")
st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC")
st.markdown("---")

with st.spinner("Loading threat intelligence data…"):
    logs, alerts = _load()

logs["timestamp"] = pd.to_datetime(logs["timestamp"])
alerts["timestamp"] = pd.to_datetime(alerts["timestamp"])

# ── ROW 1 — KPIs ─────────────────────────────────────────────────────────────
total_events   = len(logs)
total_threats  = len(alerts)
crit_count     = int((alerts["severity"] == "CRITICAL").sum())
active_inc     = int(alerts["status"].isin(["New","Reviewing"]).sum())

c1, c2, c3, c4 = st.columns(4)
def _kpi(col, icon, label, val, color):
    col.markdown(f"""
    <div class="kpi-card">
      <div style="font-size:1.8rem;">{icon}</div>
      <div class="kpi-value" style="color:{color};">{val:,}</div>
      <div class="kpi-label">{label}</div>
    </div>""", unsafe_allow_html=True)

_kpi(c1,"🔵","Total Events",      total_events,  "#00d4ff")
_kpi(c2,"🟡","Threats Detected",  total_threats,  "#f59e0b")
_kpi(c3,"🔴","Critical Alerts",   crit_count,     "#ef4444")
_kpi(c4,"🟣","Active Incidents",  active_inc,     "#a78bfa")

st.markdown("<br>", unsafe_allow_html=True)

# ── ROW 2 — Trend + Donut ────────────────────────────────────────────────────
col_l, col_r = st.columns([3, 2])

with col_l:
    st.markdown('<div class="section-hdr">📈 Threat Activity Over Time</div>', unsafe_allow_html=True)
    alerts["hour"] = alerts["timestamp"].dt.floor("h")
    hourly = alerts.groupby(["hour","severity"]).size().reset_index(name="count")

    fig_line = go.Figure()
    for sev, color in SEV_COLORS.items():
        sub = hourly[hourly["severity"]==sev]
        if not sub.empty:
            fig_line.add_trace(go.Scatter(
                x=sub["hour"], y=sub["count"], name=sev,
                mode="lines+markers", line=dict(color=color, width=2),
                marker=dict(size=4),
            ))
    fig_line.update_layout(**CHART_LAYOUT, height=320,
        xaxis=dict(gridcolor="#1f2937"), yaxis=dict(gridcolor="#1f2937"),
        title=dict(text="Events per hour by severity", font=dict(size=12, color="#9ca3af")))
    st.plotly_chart(fig_line, use_container_width=True)

with col_r:
    st.markdown('<div class="section-hdr">🥧 Severity Distribution</div>', unsafe_allow_html=True)
    sev_counts = alerts["severity"].value_counts().reindex(["CRITICAL","HIGH","MEDIUM","LOW"], fill_value=0)
    fig_donut = go.Figure(go.Pie(
        labels=sev_counts.index.tolist(),
        values=sev_counts.values.tolist(),
        hole=0.55,
        marker=dict(colors=[SEV_COLORS[s] for s in sev_counts.index],
                    line=dict(color="#111827", width=2)),
        textinfo="label+percent",
        textfont=dict(color="#e2e8f0"),
    ))
    fig_donut.update_layout(**CHART_LAYOUT, height=320,
        title=dict(text="Alert severity breakdown", font=dict(size=12, color="#9ca3af")),
        showlegend=True)
    st.plotly_chart(fig_donut, use_container_width=True)

# ── ROW 3 — Top Threats + Recent Alerts ─────────────────────────────────────
col_l2, col_r2 = st.columns([3, 2])

with col_l2:
    st.markdown('<div class="section-hdr">🔥 Top Threat Types</div>', unsafe_allow_html=True)
    tt_counts = alerts["threat_type"].value_counts().reset_index()
    tt_counts.columns = ["threat_type","count"]
    # colour by dominant severity
    tt_sev = alerts.groupby("threat_type")["severity"].agg(lambda x: x.value_counts().index[0]).reset_index()
    tt_counts = tt_counts.merge(tt_sev, on="threat_type", how="left")
    tt_counts["color"] = tt_counts["severity"].map(SEV_COLORS).fillna("#6b7280")

    fig_bar = go.Figure(go.Bar(
        x=tt_counts["count"], y=tt_counts["threat_type"],
        orientation="h",
        marker=dict(color=tt_counts["color"], line=dict(color="rgba(0,0,0,0)")),
        text=tt_counts["count"], textposition="outside",
        textfont=dict(color="#e2e8f0"),
    ))
    fig_bar.update_layout(**CHART_LAYOUT, height=320,
        xaxis=dict(gridcolor="#1f2937", showgrid=True),
        yaxis=dict(gridcolor="rgba(0,0,0,0)"),
        title=dict(text="Threat type frequency", font=dict(size=12, color="#9ca3af")))
    st.plotly_chart(fig_bar, use_container_width=True)

with col_r2:
    st.markdown('<div class="section-hdr">⏱ Recent Alerts</div>', unsafe_allow_html=True)
    recent = alerts.sort_values("timestamp", ascending=False).head(8)
    sev_badge = {
        "CRITICAL": "badge-critical",
        "HIGH":     "badge-high",
        "MEDIUM":   "badge-medium",
        "LOW":      "badge-low",
    }
    rows_html = ""
    for _, r in recent.iterrows():
        ts  = str(r["timestamp"])[:16]
        sev = r.get("severity","LOW")
        tt  = r.get("threat_type","Unknown")
        sip = r.get("source_ip","N/A")
        rs  = r.get("risk_score","?")
        badge = sev_badge.get(sev,"badge-low")
        rows_html += f"""
        <tr>
          <td>{ts}</td>
          <td><span class="{badge}">{sev}</span></td>
          <td>{tt}</td>
          <td style="color:#f59e0b;font-weight:600;">{rs}</td>
        </tr>"""

    st.markdown(f"""
    <table style="width:100%;border-collapse:collapse;">
      <thead>
        <tr style="background:#1f2937;">
          <th style="padding:8px;color:#9ca3af;font-size:.75rem;text-align:left;">TIME</th>
          <th style="padding:8px;color:#9ca3af;font-size:.75rem;text-align:left;">SEV</th>
          <th style="padding:8px;color:#9ca3af;font-size:.75rem;text-align:left;">THREAT</th>
          <th style="padding:8px;color:#9ca3af;font-size:.75rem;text-align:left;">SCORE</th>
        </tr>
      </thead>
      <tbody style="font-size:.85rem;color:#e2e8f0;">
        {rows_html}
      </tbody>
    </table>""", unsafe_allow_html=True)

# ── System status bar ─────────────────────────────────────────────────────────
st.markdown("<br>", unsafe_allow_html=True)
st.markdown('<div class="section-hdr">🖥️ System Module Status</div>', unsafe_allow_html=True)

mods = {
    "Rules Engine":   True,
    "ML Engine":      os.path.exists("models"),
    "Alert Store":    os.path.exists("data/alerts.csv"),
    "Log Parser":     True,
    "Risk Scorer":    True,
}
sc = st.columns(len(mods))
for (name, ok), col in zip(mods.items(), sc):
    icon = "✅" if ok else "⚠️"
    col.markdown(f"""
    <div class="kpi-card" style="padding:12px;">
      <div style="font-size:1.3rem;">{icon}</div>
      <div style="font-size:.8rem;font-weight:600;color:#e2e8f0;margin-top:4px;">{name}</div>
      <div style="font-size:.7rem;color:{'#22c55e' if ok else '#f59e0b'};margin-top:2px;">
        {'ONLINE' if ok else 'STANDBY'}
      </div>
    </div>""", unsafe_allow_html=True)
