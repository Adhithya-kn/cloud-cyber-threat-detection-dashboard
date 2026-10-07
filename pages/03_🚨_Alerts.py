"""
Page 3 — Alert Management Center
Alert table, expandable detail with risk gauge, bulk actions
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
#MainMenu{visibility:hidden;} footer{visibility:hidden;} header{visibility:hidden;}
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
</style>""", unsafe_allow_html=True)

CHART_LAYOUT = dict(
    paper_bgcolor="#111827", plot_bgcolor="#111827",
    font=dict(color="#e2e8f0"), margin=dict(l=20,r=20,t=20,b=20),
)
SEV_COLORS = {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#3b82f6","LOW":"#22c55e"}
SEV_BADGE  = {"CRITICAL":"badge-critical","HIGH":"badge-high","MEDIUM":"badge-medium","LOW":"badge-low"}


# ── Synthetic alert generator ─────────────────────────────────────────────────
@st.cache_data(ttl=300)
def _gen_alerts(n=150):
    rng = np.random.default_rng(7)
    base = datetime.now() - timedelta(hours=24)
    ts = [base + timedelta(seconds=int(s)) for s in np.sort(rng.integers(0, 86400, n))]
    attackers = ["45.33.32.156","23.95.110.42","198.199.85.30","104.21.44.78",
                 "91.195.240.117","185.220.101.33","5.188.86.172","194.165.16.76"]
    tt = rng.choice(
        ["Brute Force","Port Scan","Abnormal Traffic","ML Anomaly","Data Exfiltration","Ransomware Indicator"],
        n, p=[0.28,0.22,0.18,0.15,0.12,0.05])
    sev = rng.choice(["CRITICAL","HIGH","MEDIUM","LOW"], n, p=[0.12,0.26,0.38,0.24])
    reasons = {
        "Brute Force":"Multiple failed login attempts detected (>10 in 60s) from single source IP.",
        "Port Scan":"Sequential port probing activity detected across >50 ports within 30 seconds.",
        "Abnormal Traffic":"Byte transfer volume (>100 MB) exceeds 3σ above baseline for this source IP.",
        "ML Anomaly":"Isolation Forest model confidence 0.94 — strong deviation from normal behaviour.",
        "Data Exfiltration":"Large outbound data transfer (>500 MB) to unknown external IP detected.",
        "Ransomware Indicator":"File encryption pattern + shadow copy deletion detected on internal host.",
    }
    actions = {
        "Brute Force":"Block source IP at firewall. Enable account lockout. Audit affected accounts.",
        "Port Scan":"Block source IP. Enable IDS/IPS rules. Review firewall ACLs.",
        "Abnormal Traffic":"Throttle or kill connection. Investigate host for malware. Review DLP policy.",
        "ML Anomaly":"Investigate source host logs. Cross-correlate events. Escalate if confirmed.",
        "Data Exfiltration":"IMMEDIATELY block outbound connection. Isolate host. Initiate IR plan.",
        "Ransomware Indicator":"ISOLATE HOST NOW. Engage IR team immediately. Restore from clean backup.",
    }
    return pd.DataFrame({
        "alert_id":  [f"ALERT-{1000+i}" for i in range(n)],
        "timestamp": ts,
        "source_ip": [attackers[rng.integers(0,len(attackers))] for _ in range(n)],
        "destination_ip": [f"10.0.{rng.integers(0,4)}.{rng.integers(1,50)}" for _ in range(n)],
        "threat_type": tt,
        "severity":  sev,
        "risk_score": np.clip(rng.normal(62, 24, n), 1, 100).astype(int),
        "status":    rng.choice(["New","Reviewing","Resolved","False Positive"], n,
                                 p=[0.40,0.25,0.25,0.10]),
        "detection_reason":  [reasons[t] for t in tt],
        "suggested_action":  [actions[t]  for t in tt],
        "rule_triggered":    [f"RULE-{rng.integers(100,999)}" for _ in range(n)],
    })


def _load_alerts():
    if "alerts_df" in st.session_state:
        return st.session_state["alerts_df"].copy()
    p = "data/alerts.csv"
    if os.path.exists(p):
        try:
            df = pd.read_csv(p, parse_dates=["timestamp"])
            st.session_state["alerts_df"] = df
            return df.copy()
        except Exception:
            pass
    df = _gen_alerts()
    st.session_state["alerts_df"] = df
    return df.copy()


with st.spinner("Loading alerts…"):
    alerts = _load_alerts()

alerts["timestamp"] = pd.to_datetime(alerts["timestamp"])

# ── Sidebar filters ───────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🚨 Alert Filters")
    st.divider()

    sel_sev = st.multiselect("🔴 Severity", ["CRITICAL","HIGH","MEDIUM","LOW"],
                              default=["CRITICAL","HIGH","MEDIUM","LOW"])
    sel_tt  = st.multiselect("🎯 Threat Type", sorted(alerts["threat_type"].unique()),
                              default=[], placeholder="All types")
    sel_st  = st.multiselect("📌 Status", ["New","Reviewing","Resolved","False Positive"],
                              default=[], placeholder="All statuses")
    min_score, max_score = st.slider("⚠️ Risk Score range", 0, 100, (0, 100))
    st.divider()
    hours_back = st.selectbox("⏱ Time window", ["Last 1 hour","Last 6 hours","Last 24 hours","All Time"],
                               index=3)
    time_map = {"Last 1 hour":1,"Last 6 hours":6,"Last 24 hours":24,"All Time":None}
    hrs = time_map[hours_back]


# ── Apply filters ─────────────────────────────────────────────────────────────
filt = alerts.copy()
if sel_sev:  filt = filt[filt["severity"].isin(sel_sev)]
if sel_tt:   filt = filt[filt["threat_type"].isin(sel_tt)]
if sel_st:   filt = filt[filt["status"].isin(sel_st)]
filt = filt[(filt["risk_score"] >= min_score) & (filt["risk_score"] <= max_score)]
if hrs:
    cutoff = datetime.now() - timedelta(hours=hrs)
    filt = filt[filt["timestamp"] >= cutoff]

filt = filt.sort_values("timestamp", ascending=False).reset_index(drop=True)

# ── Page header ───────────────────────────────────────────────────────────────
st.markdown("# 🚨 Alert Management Center")
st.caption(f"Showing {len(filt):,} alerts · {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
st.markdown("---")

# ── Summary KPI cards ─────────────────────────────────────────────────────────
status_col = alerts["status"].astype(str).str.upper()
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

# ── Bulk actions ──────────────────────────────────────────────────────────────
ba1, ba2, ba3 = st.columns([2,2,6])
with ba1:
    if st.button("✅ Mark All Resolved", use_container_width=True):
        if "alerts_df" in st.session_state:
            idx = st.session_state["alerts_df"].index[
                st.session_state["alerts_df"]["alert_id"].isin(filt["alert_id"])]
            st.session_state["alerts_df"].loc[idx, "status"] = "Resolved"
        st.success(f"Marked {len(filt)} alerts as Resolved.")
        st.rerun()
with ba2:
    csv_data = filt.to_csv(index=False).encode()
    st.download_button("📥 Export Alerts", data=csv_data,
                        file_name="alerts_export.csv", mime="text/csv", use_container_width=True)

# ── Main alerts table ─────────────────────────────────────────────────────────
st.markdown('<div class="section-hdr">📋 Alert Table</div>', unsafe_allow_html=True)

PAGE = 20
total_pages = max(1, (len(filt)-1)//PAGE+1)
pg = st.number_input("Page", 1, total_pages, 1, label_visibility="collapsed")
page_df = filt.iloc[(pg-1)*PAGE : pg*PAGE]

if "destination_ip" not in page_df.columns:
    page_df["destination_ip"] = page_df["target_ip"] if "target_ip" in page_df.columns else "unknown"

avail_tbl_cols = [c for c in ["alert_id","timestamp","threat_type","source_ip","destination_ip",
                              "severity","risk_score","status"] if c in page_df.columns]

st.dataframe(
    page_df[avail_tbl_cols],
    use_container_width=True, height=340,
    column_config={
        "alert_id":    st.column_config.TextColumn("Alert ID"),
        "timestamp":   st.column_config.DatetimeColumn("Time", format="YYYY-MM-DD HH:mm"),
        "risk_score":  st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100,
                                                         format="%d"),
        "severity":    st.column_config.TextColumn("Severity"),
        "status":      st.column_config.TextColumn("Status"),
    }
)
st.caption(f"Page {pg}/{total_pages} · {len(filt)} alerts")

# ── Alert detail expandable ───────────────────────────────────────────────────
st.markdown("<br>", unsafe_allow_html=True)
st.markdown('<div class="section-hdr">🔎 Alert Detail Inspector</div>', unsafe_allow_html=True)

alert_ids = filt["alert_id"].tolist()
if alert_ids:
    sel_id = st.selectbox("Select Alert ID", alert_ids)
    row = filt[filt["alert_id"]==sel_id].iloc[0]

    sev   = row.get("severity","LOW")
    badge = SEV_BADGE.get(sev,"badge-low")
    color = SEV_COLORS.get(sev,"#6b7280")
    rs    = int(row.get("risk_score", 50))
    tt    = row.get("threat_type","Unknown")
    ts    = str(row.get("timestamp",""))[:19]
    sip   = row.get("source_ip","N/A")
    dip   = row.get("destination_ip","N/A")
    reason = row.get("detection_reason","No details available.")
    action = row.get("suggested_action","No action suggested.")
    rule   = row.get("rule_triggered","N/A")
    status = row.get("status","New")

    left_col, right_col = st.columns([3,2])

    with left_col:
        st.markdown(f"""
        <div class="detail-box">
          <div style="font-size:1.4rem;font-weight:800;color:#e2e8f0;margin-bottom:10px;">
            {sel_id} &nbsp;<span class="{badge}">{sev}</span>
          </div>
          <table style="width:100%;font-size:.9rem;border-collapse:collapse;">
            <tr><td style="color:#9ca3af;padding:5px 8px;">Threat Type</td>
                <td style="color:#f59e0b;font-weight:600;">{tt}</td></tr>
            <tr><td style="color:#9ca3af;padding:5px 8px;">Source IP</td>
                <td style="color:#e2e8f0;"><code>{sip}</code></td></tr>
            <tr><td style="color:#9ca3af;padding:5px 8px;">Target IP</td>
                <td style="color:#e2e8f0;"><code>{dip}</code></td></tr>
            <tr><td style="color:#9ca3af;padding:5px 8px;">Timestamp</td>
                <td style="color:#e2e8f0;">{ts}</td></tr>
            <tr><td style="color:#9ca3af;padding:5px 8px;">Rule Triggered</td>
                <td style="color:#a78bfa;">{rule}</td></tr>
            <tr><td style="color:#9ca3af;padding:5px 8px;">Current Status</td>
                <td style="color:#22c55e;font-weight:600;">{status}</td></tr>
          </table>
          <div class="reason-box">
            <strong>🔍 Detection Reason</strong><br>{reason}
          </div>
          <div class="suggest-box">
            <strong>💡 Suggested Action</strong><br>{action}
          </div>
        </div>""", unsafe_allow_html=True)

    with right_col:
        # Risk gauge
        gauge_color = color
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=rs,
            delta={"reference": 50, "increasing": {"color": "#ef4444"}, "decreasing": {"color": "#22c55e"}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": "#6b7280"},
                "bar":  {"color": gauge_color},
                "steps": [
                    {"range": [0,  25], "color": "#064e3b"},
                    {"range": [25, 50], "color": "#1e3a5f"},
                    {"range": [50, 75], "color": "#78350f"},
                    {"range": [75,100], "color": "#7f1d1d"},
                ],
                "threshold": {"line":{"color":"#fff","width":3}, "thickness":0.75, "value":rs},
                "bgcolor": "#111827",
                "bordercolor": "#374151",
            },
            title={"text": "Risk Score", "font": {"color": "#9ca3af", "size": 14}},
            number={"font": {"color": "#e2e8f0", "size": 40}},
        ))
        fig_gauge.update_layout(**CHART_LAYOUT, height=300)
        st.plotly_chart(fig_gauge, use_container_width=True)

    # ── Status update ─────────────────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    ua1, ua2 = st.columns([2,4])
    with ua1:
        new_status = st.selectbox("Update Status", ["New","Reviewing","Resolved","False Positive"],
                                   index=["New","Reviewing","Resolved","False Positive"].index(status)
                                   if status in ["New","Reviewing","Resolved","False Positive"] else 0)
    with ua2:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("💾 Save Status", use_container_width=False):
            if "alerts_df" in st.session_state:
                mask = st.session_state["alerts_df"]["alert_id"] == sel_id
                st.session_state["alerts_df"].loc[mask, "status"] = new_status
            st.success(f"Alert {sel_id} status updated to **{new_status}**")
            st.rerun()
else:
    st.info("No alerts match the current filters.")
