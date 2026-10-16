"""
Page 3 — Alert Management Center
Alert table, expandable detail with risk gauge, bulk actions, and triage report
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from datetime import datetime, timedelta
import os, sys

sys.path.insert(0, ".")

st.set_page_config(page_title="Alerts | CyberShield", page_icon="🚨", layout="wide")

st.markdown("""<style>
.main{background:#0a0e1a;} .stApp{background:#0a0e1a;}
#MainMenu{visibility:hidden;} footer{visibility:hidden;}
[data-testid="stSidebar"]{background:#0d1117;border-right:1px solid #21262d;}
.kpi-card{background:linear-gradient(135deg,#111827 0%,#1f2937 100%);border:1px solid #374151;
  border-radius:12px;padding:18px;text-align:center;box-shadow:0 4px 6px rgba(0,0,0,0.3);}
.kpi-value{font-size:2rem;font-weight:700;color:#00d4ff;}
.kpi-label{font-size:.8rem;color:#9ca3af;text-transform:uppercase;letter-spacing:.05em;}
.section-hdr{font-size:1.05rem;font-weight:600;color:#00d4ff;
  border-bottom:1px solid #1e40af;padding-bottom:6px;margin-bottom:14px;}
.badge-critical{background:#7f1d1d;color:#fca5a5;padding:3px 10px;border-radius:4px;font-size:.78rem;font-weight:700;}
.badge-high{background:#78350f;color:#fcd34d;padding:3px 10px;border-radius:4px;font-size:.78rem;font-weight:700;}
.badge-medium{background:#1e3a5f;color:#93c5fd;padding:3px 10px;border-radius:4px;font-size:.78rem;font-weight:700;}
.badge-low{background:#064e3b;color:#6ee7b7;padding:3px 10px;border-radius:4px;font-size:.78rem;font-weight:700;}
.detail-box{background:#111827;border:1px solid #374151;border-radius:10px;padding:16px;margin-bottom:10px;}
.suggest-box{background:rgba(30,64,175,.25);border:1px solid #1e40af;border-radius:8px;
  padding:12px 16px;color:#93c5fd;margin-top:8px;}
.reason-box{background:rgba(120,53,15,.25);border:1px solid #78350f;border-radius:8px;
  padding:12px 16px;color:#fcd34d;margin-top:8px;}
.report-summary-box{
  background:#111827;border:1px solid #374151;border-radius:8px;padding:14px;
  color:#e2e8f0;font-family:monospace;white-space:pre-wrap;
}
</style>""", unsafe_allow_html=True)

CHART_LAYOUT = dict(
    paper_bgcolor="#111827", plot_bgcolor="#111827",
    font=dict(color="#e2e8f0"), margin=dict(l=20,r=20,t=20,b=20),
)
SEV_COLORS = {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#3b82f6","LOW":"#22c55e"}
SEV_BADGE  = {"CRITICAL":"badge-critical","HIGH":"badge-high","MEDIUM":"badge-medium","LOW":"badge-low"}

from utils.pipeline import (
    ensure_session_data,
    run_pipeline,
    AVAILABLE_DATASETS,
    DEFAULT_DATASET_NAME,
    DEFAULT_DATASET_PATH,
)

def _load_alerts():
    _, alerts, _ = ensure_session_data()
    return alerts.copy()

with st.spinner("Loading alerts…"):
    alerts = _load_alerts()

if alerts.empty:
    st.info("ℹ️ No active alerts in the current dataset (normal baseline traffic).")
    if st.button("⚡ Load CIC-IDS2017 Intrusion Benchmark", type="primary"):
        if os.path.exists(DEFAULT_DATASET_PATH):
            run_pipeline(pd.read_csv(DEFAULT_DATASET_PATH), DEFAULT_DATASET_NAME)
            st.rerun()
    st.stop()

# Normalize columns
if "timestamp" in alerts.columns:
    alerts["timestamp"] = pd.to_datetime(alerts["timestamp"], errors="coerce")
if "destination_ip" not in alerts.columns and "target_ip" in alerts.columns:
    alerts["destination_ip"] = alerts["target_ip"]

# ── Sidebar filters ───────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<div style="font-size:1.4rem;font-weight:800;color:#00d4ff;">🛡️ CyberShield</div>', unsafe_allow_html=True)
    st.caption("Alert Management Center")
    st.divider()

    st.markdown("### 📥 Switch Telemetry Dataset")
    ds_options = list(AVAILABLE_DATASETS.keys())
    curr_ds = st.session_state.get("active_dataset_name", DEFAULT_DATASET_NAME)
    curr_idx = ds_options.index(curr_ds) if curr_ds in ds_options else 0
    sel_ds = st.selectbox("Active Dataset:", ds_options, index=curr_idx, key="alerts_dataset_select")

    if sel_ds != curr_ds:
        fpath = AVAILABLE_DATASETS.get(sel_ds)
        if fpath and os.path.exists(fpath):
            run_pipeline(pd.read_csv(fpath), sel_ds)
            st.rerun()

    st.divider()
    st.markdown("## 🚨 Alert Filters")
    st.divider()

    # Dynamic severity options
    avail_sevs = sorted([str(x).upper() for x in alerts["severity"].dropna().unique().tolist()])
    sel_sev = st.multiselect("🔴 Severity", avail_sevs, default=avail_sevs)

    # Dynamic threat types
    avail_tts = sorted([str(x) for x in alerts["threat_type"].dropna().unique().tolist()])
    sel_tt = st.multiselect("🎯 Threat Type", avail_tts, default=[], placeholder="All threat types")

    # Dynamic statuses
    avail_st = sorted(list(set([str(x).upper() for x in alerts["status"].dropna().unique().tolist()] + ["NEW", "REVIEWING", "RESOLVED", "FALSE_POSITIVE"])))
    sel_st = st.multiselect("📌 Status", avail_st, default=[], placeholder="All statuses")

    min_score, max_score = st.slider("⚠️ Risk Score range", 0, 100, (0, 100))
    st.divider()
    hours_back = st.selectbox("⏱ Time window", ["Last 1 hour","Last 6 hours","Last 24 hours","All Time"], index=3)
    time_map = {"Last 1 hour":1,"Last 6 hours":6,"Last 24 hours":24,"All Time":None}
    hrs = time_map[hours_back]

# ── Apply filters robustly ─────────────────────────────────────────────────────
filt = alerts.copy()

if sel_sev and "severity" in filt.columns:
    filt = filt[filt["severity"].astype(str).str.upper().isin(sel_sev)]

if sel_tt and "threat_type" in filt.columns:
    filt = filt[filt["threat_type"].astype(str).isin(sel_tt)]

if sel_st and "status" in filt.columns:
    filt = filt[filt["status"].astype(str).str.upper().isin([s.upper() for s in sel_st])]

if "risk_score" in filt.columns:
    filt = filt[(filt["risk_score"] >= min_score) & (filt["risk_score"] <= max_score)]

if hrs and "timestamp" in filt.columns:
    cutoff = datetime.now() - timedelta(hours=hrs)
    filt = filt[filt["timestamp"] >= cutoff]

if "timestamp" in filt.columns:
    filt = filt.sort_values("timestamp", ascending=False).reset_index(drop=True)

# ── Page header ───────────────────────────────────────────────────────────────
st.markdown("# 🚨 Alert Management Center")
active_name = st.session_state.get("active_dataset_name", "Current Telemetry")
st.caption(f"Showing {len(filt):,} alerts · Filtered from {len(alerts):,} total · Dataset: {active_name}")
st.markdown("---")

# ── Summary KPI cards ─────────────────────────────────────────────────────────
status_col = alerts["status"].astype(str).str.upper() if "status" in alerts.columns else pd.Series([])
new_cnt  = int(status_col.isin(["NEW"]).sum())
rev_cnt  = int(status_col.isin(["REVIEWING", "UNDER REVIEW"]).sum())
res_cnt  = int(status_col.isin(["RESOLVED"]).sum())
fp_cnt   = int(status_col.isin(["FALSE POSITIVE", "FALSE_POSITIVE"]).sum())

k1,k2,k3,k4 = st.columns(4)
def _kpi(col, icon, label, val, color):
    col.markdown(f"""
    <div class="kpi-card">
      <div style="font-size:1.8rem;">{icon}</div>
      <div class="kpi-value" style="color:{color};">{val:,}</div>
      <div class="kpi-label">{label}</div>
    </div>""", unsafe_allow_html=True)

_kpi(k1,"🔴","New Alerts",      new_cnt,  "#ef4444")
_kpi(k2,"🟡","Under Review",    rev_cnt,  "#f59e0b")
_kpi(k3,"✅","Resolved",        res_cnt,  "#22c55e")
_kpi(k4,"⚪","False Positives", fp_cnt,   "#6b7280")

st.markdown("<br>", unsafe_allow_html=True)

# ── Alert Triage Summary Report ───────────────────────────────────────────────
with st.expander("📄 View Filtered Alert Triage Report", expanded=True):
    rep_lines = []
    rep_lines.append(f"ALERT TRIAGE & INCIDENT REPORT — {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    rep_lines.append(f"Telemetry Dataset     : {active_name}")
    rep_lines.append(f"Filtered Alert Total  : {len(filt):,} incidents")
    if not filt.empty:
        c_sev = filt["severity"].value_counts().to_dict()
        rep_lines.append(f"Severity Distribution : {', '.join([f'{k}: {v}' for k,v in c_sev.items()])}")
        top_atk = filt["source_ip"].mode().iloc[0] if "source_ip" in filt.columns else "N/A"
        rep_lines.append(f"Primary Offender IP   : {top_atk}")
        avg_r = int(filt["risk_score"].mean()) if "risk_score" in filt.columns else 0
        rep_lines.append(f"Average Risk Score    : {avg_r}/100")
    else:
        rep_lines.append("No alerts meet the current filter thresholds.")
    
    rep_str = "\n".join(rep_lines)
    st.markdown(f'<div class="report-summary-box">{rep_str}</div>', unsafe_allow_html=True)

# ── Bulk actions ──────────────────────────────────────────────────────────────
ba1, ba2, _ = st.columns([2,2,6])
with ba1:
    if st.button("✅ Mark Filtered as Resolved", use_container_width=True):
        if "alerts_df" in st.session_state and not filt.empty:
            idx = st.session_state["alerts_df"].index[
                st.session_state["alerts_df"]["alert_id"].isin(filt["alert_id"])]
            st.session_state["alerts_df"].loc[idx, "status"] = "RESOLVED"
            try:
                from utils.alert_manager import save_alerts
                save_alerts(st.session_state["alerts_df"], "data/alerts.csv")
            except Exception:
                pass
        st.success(f"Marked {len(filt)} alerts as Resolved.")
        st.rerun()
with ba2:
    csv_data = filt.to_csv(index=False).encode()
    st.download_button("📥 Export Alerts CSV", data=csv_data,
                        file_name=f"alerts_export_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                        mime="text/csv", use_container_width=True)

# ── Main alerts table ─────────────────────────────────────────────────────────
st.markdown('<div class="section-hdr">📋 Alert Table</div>', unsafe_allow_html=True)

PAGE = 20
total_pages = max(1, (len(filt)-1)//PAGE+1)
pg = st.number_input("Page", 1, total_pages, 1, label_visibility="collapsed")
page_df = filt.iloc[(pg-1)*PAGE : pg*PAGE].copy()

avail_tbl_cols = [c for c in ["alert_id","timestamp","threat_type","source_ip","destination_ip",
                              "severity","risk_score","status"] if c in page_df.columns]

if not page_df.empty:
    st.dataframe(
        page_df[avail_tbl_cols],
        use_container_width=True, height=340,
        column_config={
            "alert_id":    st.column_config.TextColumn("Alert ID"),
            "timestamp":   st.column_config.DatetimeColumn("Time", format="YYYY-MM-DD HH:mm"),
            "risk_score":  st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100, format="%d"),
            "severity":    st.column_config.TextColumn("Severity"),
            "status":      st.column_config.TextColumn("Status"),
        }
    )
else:
    st.info("No alerts match the current filter selection.")

st.caption(f"Page {pg}/{total_pages} · {len(filt)} alerts match filters")

# ── Alert detail inspector ────────────────────────────────────────────────────
st.markdown("<br>", unsafe_allow_html=True)
st.markdown('<div class="section-hdr">🔎 Alert Detail Inspector</div>', unsafe_allow_html=True)

alert_ids = filt["alert_id"].tolist() if "alert_id" in filt.columns else []
if alert_ids:
    sel_id = st.selectbox("Select Alert ID to Inspect", alert_ids)
    row = filt[filt["alert_id"]==sel_id].iloc[0]

    sev   = str(row.get("severity","LOW")).upper()
    badge = SEV_BADGE.get(sev,"badge-low")
    color = SEV_COLORS.get(sev,"#6b7280")
    rs    = int(row.get("risk_score", 50))
    tt    = row.get("threat_type","Unknown")
    ts    = str(row.get("timestamp",""))[:19]
    sip   = row.get("source_ip","N/A")
    dip   = row.get("destination_ip") or row.get("target_ip") or "N/A"
    reason = row.get("reason") or row.get("detection_reason") or "Rule threshold exceeded."
    action = row.get("suggested_action","Isolate host and perform manual log review.")
    status = row.get("status","NEW")

    left_col, right_col = st.columns([3,2])

    with left_col:
        st.markdown(f"""
        <div class="detail-box">
          <div style="font-size:1.4rem;font-weight:800;color:#e2e8f0;margin-bottom:10px;">
            {sel_id} &nbsp;<span class="{badge}">{sev}</span>
          </div>
          <table style="width:100%;font-size:.9rem;border-collapse:collapse;">
            <tr><td style="color:#9ca3af;padding:5px 8px;">Threat Category</td>
                <td style="color:#f59e0b;font-weight:600;">{tt}</td></tr>
            <tr><td style="color:#9ca3af;padding:5px 8px;">Offending IP</td>
                <td style="color:#e2e8f0;"><code>{sip}</code></td></tr>
            <tr><td style="color:#9ca3af;padding:5px 8px;">Target Victim IP</td>
                <td style="color:#e2e8f0;"><code>{dip}</code></td></tr>
            <tr><td style="color:#9ca3af;padding:5px 8px;">Incident Timestamp</td>
                <td style="color:#e2e8f0;">{ts}</td></tr>
            <tr><td style="color:#9ca3af;padding:5px 8px;">Investigation Status</td>
                <td style="color:#22c55e;font-weight:600;">{status}</td></tr>
          </table>
          <div class="reason-box">
            <strong>🔍 Detection Evidence & Reason</strong><br>{reason}
          </div>
          <div class="suggest-box">
            <strong>💡 Recommended Playbook Action</strong><br>{action}
          </div>
        </div>""", unsafe_allow_html=True)

    with right_col:
        # Risk gauge
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=rs,
            gauge={
                "axis": {"range": [0, 100], "tickcolor": "#6b7280"},
                "bar":  {"color": color},
                "steps": [
                    {"range": [0,  30], "color": "#064e3b"},
                    {"range": [30, 60], "color": "#1e3a5f"},
                    {"range": [60, 80], "color": "#78350f"},
                    {"range": [80,100], "color": "#7f1d1d"},
                ],
                "threshold": {"line":{"color":"#fff","width":3}, "thickness":0.75, "value":rs},
                "bgcolor": "#111827",
                "bordercolor": "#374151",
            },
            title={"text": "Composite Risk Score (0-100)", "font": {"color": "#9ca3af", "size": 14}},
            number={"font": {"color": "#e2e8f0", "size": 40}},
        ))
        fig_gauge.update_layout(**CHART_LAYOUT, height=270)
        st.plotly_chart(fig_gauge, use_container_width=True)

    # Status update
    ua1, ua2 = st.columns([2,4])
    with ua1:
        cur_st_upper = str(status).upper()
        status_choices = ["NEW","REVIEWING","RESOLVED","FALSE_POSITIVE"]
        idx_choice = status_choices.index(cur_st_upper) if cur_st_upper in status_choices else 0
        new_status = st.selectbox("Update Status", status_choices, index=idx_choice)
    with ua2:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("💾 Save Status", use_container_width=False):
            if "alerts_df" in st.session_state:
                mask = st.session_state["alerts_df"]["alert_id"] == sel_id
                st.session_state["alerts_df"].loc[mask, "status"] = new_status
                try:
                    from utils.alert_manager import save_alerts
                    save_alerts(st.session_state["alerts_df"], "data/alerts.csv")
                except Exception:
                    pass
            st.success(f"Alert {sel_id} status updated to **{new_status}**")
            st.rerun()
else:
    st.info("No alerts match the current filters.")
