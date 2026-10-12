"""
Page 2 — Log Monitoring
Searchable / filterable security event stream with conditional formatting
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import os, io, sys

sys.path.insert(0, ".")

st.set_page_config(page_title="Log Monitoring | CyberShield", page_icon="📋", layout="wide")

st.markdown("""<style>
.main{background:#0a0e1a;} .stApp{background:#0a0e1a;}
#MainMenu{visibility:hidden;} footer{visibility:hidden;}
[data-testid="stSidebar"]{background:#0d1117;border-right:1px solid #21262d;}
.kpi-card{background:linear-gradient(135deg,#111827 0%,#1f2937 100%);border:1px solid #374151;
  border-radius:12px;padding:18px;text-align:center;box-shadow:0 4px 6px rgba(0,0,0,0.3);}
.kpi-value{font-size:2rem;font-weight:700;color:#00d4ff;}
.kpi-label{font-size:.8rem;color:#9ca3af;text-transform:uppercase;letter-spacing:.05em;margin-top:4px;}
.section-hdr{font-size:1.1rem;font-weight:600;color:#00d4ff;
  border-bottom:1px solid #1e40af;padding-bottom:6px;margin-bottom:14px;}
.report-summary-box{
  background:#111827;border:1px solid #374151;border-radius:8px;padding:14px;
  color:#e2e8f0;font-family:monospace;white-space:pre-wrap;
}
</style>""", unsafe_allow_html=True)

CHART_LAYOUT = dict(
    paper_bgcolor="#111827", plot_bgcolor="#111827",
    font=dict(color="#e2e8f0"), margin=dict(l=40,r=20,t=30,b=40),
)

from utils.pipeline import (
    ensure_session_data,
    run_pipeline,
    AVAILABLE_DATASETS,
    DEFAULT_DATASET_NAME,
    DEFAULT_DATASET_PATH,
)

def _load_logs():
    logs, _, _ = ensure_session_data()
    return logs.copy()

# ── Load data ────────────────────────────────────────────────────────────────
with st.spinner("Loading log data…"):
    logs = _load_logs()

if logs.empty:
    st.info("⚠️ No logs available. Please select a benchmark dataset.")
    if st.button("⚡ Load CIC-IDS2017 Intrusion Benchmark", type="primary"):
        if os.path.exists(DEFAULT_DATASET_PATH):
            run_pipeline(pd.read_csv(DEFAULT_DATASET_PATH), DEFAULT_DATASET_NAME)
            st.rerun()
    st.stop()

# Ensure timestamp is datetime
logs["timestamp"] = pd.to_datetime(logs["timestamp"], errors="coerce")
logs = logs.dropna(subset=["timestamp"]).sort_values("timestamp", ascending=False).reset_index(drop=True)

# ── Sidebar filters ──────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<div style="font-size:1.4rem;font-weight:800;color:#00d4ff;">🛡️ CyberShield</div>', unsafe_allow_html=True)
    st.caption("Live Log Stream & Telemetry")
    st.divider()

    st.markdown("### 📥 Switch Telemetry Dataset")
    ds_options = list(AVAILABLE_DATASETS.keys())
    curr_ds = st.session_state.get("active_dataset_name", DEFAULT_DATASET_NAME)
    curr_idx = ds_options.index(curr_ds) if curr_ds in ds_options else 0
    sel_ds = st.selectbox("Active Dataset:", ds_options, index=curr_idx, key="logs_dataset_select")

    if sel_ds != curr_ds:
        fpath = AVAILABLE_DATASETS.get(sel_ds)
        if fpath and os.path.exists(fpath):
            run_pipeline(pd.read_csv(fpath), sel_ds)
            st.rerun()

    st.divider()
    st.markdown("## 🔍 Log Stream Filters")
    st.divider()

    min_ts = logs["timestamp"].min().date() if not logs.empty else datetime.now().date()
    max_ts = logs["timestamp"].max().date() if not logs.empty else datetime.now().date()

    date_range = st.date_input("📅 Date range",
        value=(min_ts, max_ts),
        min_value=min_ts, max_value=max_ts)

    # Event types from data
    avail_events = sorted([str(x) for x in logs["event_type"].dropna().unique().tolist()])
    sel_events = st.multiselect("📌 Event type", options=avail_events, default=[], placeholder="All event types")

    # Dynamic status options based on actual values in current dataset
    raw_statuses = [str(x) for x in logs["status"].dropna().unique().tolist()]
    status_options = ["All"] + sorted(list(set(raw_statuses)))
    sel_status = st.selectbox("✅ Status", status_options)

    # Protocols
    avail_protocols = sorted([str(x) for x in logs["protocol"].dropna().unique().tolist()]) if "protocol" in logs.columns else []
    sel_proto = st.multiselect("🔌 Protocol", options=avail_protocols, default=[], placeholder="All protocols")

    src_ip_filter = st.text_input("🌐 Source IP (contains)", placeholder="e.g. 192.168 or 45.33")

    st.divider()
    active_dataset = st.session_state.get("active_dataset_name", "Active Stream")
    st.caption(f"Active dataset: `{active_dataset}`")
    st.caption(f"Total records in dataset: {len(logs):,}")


# ── Apply filters robustly ────────────────────────────────────────────────────
filtered = logs.copy()

# Date filter
if isinstance(date_range, (list, tuple)):
    if len(date_range) == 2:
        d0, d1 = date_range
        filtered = filtered[(filtered["timestamp"].dt.date >= d0) & (filtered["timestamp"].dt.date <= d1)]
    elif len(date_range) == 1:
        d0 = date_range[0]
        filtered = filtered[filtered["timestamp"].dt.date == d0]

# Event type filter
if sel_events:
    filtered = filtered[filtered["event_type"].astype(str).isin(sel_events)]

# Status filter (case-insensitive and exact match compatible)
if sel_status != "All":
    filtered = filtered[filtered["status"].astype(str).str.lower() == sel_status.lower()]

# Protocol filter
if sel_proto and "protocol" in filtered.columns:
    filtered = filtered[filtered["protocol"].astype(str).isin(sel_proto)]

# Source IP filter
if src_ip_filter.strip() and "source_ip" in filtered.columns:
    filtered = filtered[filtered["source_ip"].astype(str).str.contains(src_ip_filter.strip(), case=False, na=False)]

# ── Page header ──────────────────────────────────────────────────────────────
st.markdown("# 📋 Log Monitoring & Telemetry Stream")
st.caption(f"Displaying {len(filtered):,} matching logs · Filtered from {len(logs):,} total · Dataset: {active_dataset}")
st.markdown("---")

# ── Metrics row with exact Success / Failure analytics ────────────────────────
total_ev   = len(filtered)
status_series = filtered["status"].astype(str).str.lower() if "status" in filtered.columns else pd.Series([])

success_cnt = int(status_series.isin(["success", "ok"]).sum())
fail_cnt    = int(status_series.isin(["failed", "failure", "rejected", "error"]).sum())
other_cnt   = total_ev - (success_cnt + fail_cnt)

success_rate = round(success_cnt / max(total_ev, 1) * 100, 1)
fail_rate    = round(fail_cnt / max(total_ev, 1) * 100, 1)
uniq_src     = filtered["source_ip"].nunique() if "source_ip" in filtered.columns else 0

m1, m2, m3, m4 = st.columns(4)
def _metric(col, icon, label, val, sublabel="", color="#00d4ff"):
    col.markdown(f"""
    <div class="kpi-card">
      <div style="font-size:1.5rem;">{icon}</div>
      <div class="kpi-value" style="color:{color};">{val}</div>
      <div class="kpi-label">{label}</div>
      <div style="font-size:0.75rem; color:#9ca3af; margin-top:2px;">{sublabel}</div>
    </div>""", unsafe_allow_html=True)

_metric(m1, "📋", "Matching Events", f"{total_ev:,}", f"of {len(logs):,} in dataset")
_metric(m2, "✅", "Success Events",  f"{success_cnt:,}", f"{success_rate}% success rate", "#22c55e")
_metric(m3, "❌", "Failed / Rejected", f"{fail_cnt:,}", f"{fail_rate}% failure rate", "#ef4444" if fail_cnt > 0 else "#22c55e")
_metric(m4, "🌐", "Unique Source IPs", f"{uniq_src:,}", "Distinct senders", "#a78bfa")

st.markdown("<br>", unsafe_allow_html=True)

# ── Live Telemetry Analysis Report (Answers exactly what user requested) ─────
with st.expander("📄 View Filtered Telemetry Stream Report", expanded=True):
    rep_lines = []
    rep_lines.append(f"FILTERED LOG TELEMETRY REPORT — Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    rep_lines.append(f"Applied Filter Status : {sel_status.upper()}")
    rep_lines.append(f"Applied Date Range    : {date_range}")
    rep_lines.append(f"Event Types Filtered  : {sel_events if sel_events else 'ALL'}")
    rep_lines.append(f"Total Matches         : {total_ev:,} records")
    rep_lines.append(f"Success Count (Rate)  : {success_cnt:,} ({success_rate}%)")
    rep_lines.append(f"Failure Count (Rate)  : {fail_cnt:,} ({fail_rate}%)")
    if other_cnt > 0:
        rep_lines.append(f"Other Statuses Count  : {other_cnt:,}")
    if not filtered.empty and "source_ip" in filtered.columns:
        top_talkers = filtered["source_ip"].value_counts().head(3).to_dict()
        rep_lines.append(f"Top Active Source IPs : {', '.join([f'{k} ({v} events)' for k, v in top_talkers.items()])}")
    
    rep_text = "\n".join(rep_lines)
    st.markdown(f'<div class="report-summary-box">{rep_text}</div>', unsafe_allow_html=True)

# ── Text search across all columns ────────────────────────────────────────────
col_search, col_btn = st.columns([5, 1])
with col_search:
    global_search = st.text_input("🔍 Quick search table", placeholder="Filter by IP, port, protocol, user, or event type…")

if global_search.strip():
    mask = filtered.apply(lambda row: row.astype(str).str.contains(global_search.strip(), case=False, na=False).any(), axis=1)
    filtered = filtered[mask]

# ── Data table with pagination and styling ────────────────────────────────────
st.markdown('<div class="section-hdr">📊 Security Event Table</div>', unsafe_allow_html=True)

PAGE_SIZE = 50
total_pages = max(1, (len(filtered) - 1) // PAGE_SIZE + 1)
page_col, exp_col = st.columns([4, 1])

with page_col:
    page_num = st.number_input("Page selector", min_value=1, max_value=total_pages, value=1, step=1, label_visibility="collapsed")
with exp_col:
    csv_bytes = filtered.to_csv(index=False).encode()
    st.download_button("📥 Export Filtered CSV", data=csv_bytes, file_name=f"filtered_logs_{sel_status}.csv", mime="text/csv", use_container_width=True)

start_idx = (page_num - 1) * PAGE_SIZE
page_df = filtered.iloc[start_idx: start_idx + PAGE_SIZE].copy()

# Column formatting
DISPLAY_COLS = ["timestamp","source_ip","destination_ip","source_port",
                "destination_port","protocol","user","event_type","status","bytes","bytes_transferred"]
avail_cols = [c for c in DISPLAY_COLS if c in page_df.columns]
display_df = page_df[avail_cols].copy()
if "timestamp" in display_df.columns:
    display_df["timestamp"] = display_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

def _color_status(val):
    v = str(val).lower()
    if v in ["failure", "failed", "rejected"]:
        return "background-color:#450a0a;color:#fca5a5;font-weight:600;"
    elif v in ["success", "ok"]:
        return "background-color:#052e16;color:#86efac;font-weight:600;"
    return ""

def _color_bytes(val):
    try:
        v = int(val)
        if v > 10000000: return "color:#ef4444;font-weight:700;" # > 10MB
        if v > 100000: return "color:#f97316;font-weight:600;"
    except: pass
    return ""

byte_col = "bytes" if "bytes" in display_df.columns else ("bytes_transferred" if "bytes_transferred" in display_df.columns else None)

def _style_df(styler):
    if "status" in display_df.columns:
        styler = styler.map(_color_status, subset=["status"])
    if byte_col:
        styler = styler.map(_color_bytes, subset=[byte_col])
        styler = styler.format({byte_col: "{:,}"})
    return styler

if not display_df.empty:
    st.dataframe(display_df.style.pipe(_style_df), use_container_width=True, height=450)
else:
    st.info(f"No records match status = '{sel_status}' and the selected criteria.")

st.caption(f"Displaying page {page_num} of {total_pages} · {len(filtered):,} records match current filter criteria")

# ── Event distribution timeline & Top failers ─────────────────────────────────
if not filtered.empty:
    st.markdown("<br>", unsafe_allow_html=True)
    c_tl, c_fail = st.columns([3, 2])
    
    with c_tl:
        st.markdown('<div class="section-hdr">📈 Event Stream Frequency</div>', unsafe_allow_html=True)
        time_copy = filtered.copy()
        time_copy["bucket"] = time_copy["timestamp"].dt.floor("15min")
        tl_counts = time_copy.groupby(["bucket", "status"]).size().reset_index(name="count")
        
        fig_tl = px.bar(
            tl_counts, x="bucket", y="count", color="status",
            color_discrete_map={"success": "#22c55e", "failed": "#ef4444", "rejected": "#f59e0b", "Failure": "#ef4444", "Success": "#22c55e"}
        )
        fig_tl.update_layout(
            paper_bgcolor="#111827", plot_bgcolor="#111827",
            font=dict(color="#e2e8f0"), height=260, margin=dict(t=10, b=10, l=10, r=10),
            xaxis_title="Time Window", yaxis_title="Events"
        )
        st.plotly_chart(fig_tl, use_container_width=True)

    with c_fail:
        st.markdown('<div class="section-hdr">🔴 Top Failure / Rejected Sources</div>', unsafe_allow_html=True)
        fail_events = filtered[filtered["status"].astype(str).str.lower().isin(["failed", "failure", "rejected"])]
        if not fail_events.empty and "source_ip" in fail_events.columns:
            fail_sources = fail_events["source_ip"].value_counts().head(8).reset_index()
            fail_sources.columns = ["source_ip", "failures"]
            fig_fail = px.bar(
                fail_sources, y="source_ip", x="failures", orientation="h",
                color="failures", color_continuous_scale="Reds"
            )
            fig_fail.update_layout(
                paper_bgcolor="#111827", plot_bgcolor="#111827",
                font=dict(color="#e2e8f0"), height=260, margin=dict(t=10, b=10, l=10, r=10),
                coloraxis_showscale=False, yaxis=dict(autorange="reversed")
            )
            st.plotly_chart(fig_fail, use_container_width=True)
        else:
            st.success("✅ Zero failed or rejected events in current selection!")
