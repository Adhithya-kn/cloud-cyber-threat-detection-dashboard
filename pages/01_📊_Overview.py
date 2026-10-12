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


from utils.pipeline import (
    ensure_session_data,
    run_pipeline,
    AVAILABLE_DATASETS,
    DEFAULT_DATASET_NAME,
    DEFAULT_DATASET_PATH,
)

# ── Sidebar Dataset Switcher ────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<div style="font-size:1.4rem;font-weight:800;color:#00d4ff;">🛡️ CyberShield</div>', unsafe_allow_html=True)
    st.caption("SOC Threat Intelligence Overview")
    st.divider()

    st.markdown("### 📥 Switch Telemetry Dataset")
    ds_options = list(AVAILABLE_DATASETS.keys())
    curr_ds = st.session_state.get("active_dataset_name", DEFAULT_DATASET_NAME)
    curr_idx = ds_options.index(curr_ds) if curr_ds in ds_options else 0
    sel_ds = st.selectbox("Active Dataset:", ds_options, index=curr_idx, key="overview_dataset_select")

    if sel_ds != curr_ds:
        fpath = AVAILABLE_DATASETS.get(sel_ds)
        if fpath and os.path.exists(fpath):
            run_pipeline(pd.read_csv(fpath), sel_ds)
            st.rerun()

    st.divider()
    st.markdown(f"**Current Data:** `{st.session_state.get('active_dataset_name', 'Benchmark')}`")
    st.markdown(f"**Events Ingested:** `{len(st.session_state.get('logs_df', [])):,}`")
    st.markdown(f"**Alerts Triggered:** `{len(st.session_state.get('alerts_df', [])):,}`")
    st.divider()

    if st.button("🔄 Reload Default Benchmark", use_container_width=True, key="overview_reset_btn"):
        if os.path.exists(DEFAULT_DATASET_PATH):
            run_pipeline(pd.read_csv(DEFAULT_DATASET_PATH), DEFAULT_DATASET_NAME)
            st.rerun()

def _load():
    logs, alerts, _ = ensure_session_data()
    return logs.copy(), alerts.copy()


# ── Page ─────────────────────────────────────────────────────────────────────
st.markdown("# 📊 Overview — Threat Intelligence Dashboard")
st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC")
st.markdown("---")

with st.spinner("Loading threat intelligence data…"):
    logs, alerts = _load()

logs["timestamp"] = pd.to_datetime(logs["timestamp"])
if not alerts.empty and "timestamp" in alerts.columns:
    alerts["timestamp"] = pd.to_datetime(alerts["timestamp"])

# ── ROW 1 — KPIs ─────────────────────────────────────────────────────────────
total_events   = len(logs)
total_threats  = len(alerts)
crit_count     = int((alerts["severity"].astype(str).str.upper() == "CRITICAL").sum()) if "severity" in alerts.columns else 0
active_inc     = int(alerts["status"].astype(str).str.upper().isin(["NEW","REVIEWING","UNDER REVIEW"]).sum()) if "status" in alerts.columns else 0

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
