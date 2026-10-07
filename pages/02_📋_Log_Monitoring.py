"""
Page 2 — Log Monitoring
Searchable / filterable security event stream with conditional formatting
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from datetime import datetime, timedelta
import os, io, sys

sys.path.insert(0, ".")

st.set_page_config(page_title="Log Monitoring | CyberShield", page_icon="📋", layout="wide")

st.markdown("""<style>
.main{background:#0a0e1a;} .stApp{background:#0a0e1a;}
#MainMenu{visibility:hidden;} footer{visibility:hidden;} header{visibility:hidden;}
[data-testid="stSidebar"]{background:#0d1117;border-right:1px solid #21262d;}
.kpi-card{background:linear-gradient(135deg,#111827 0%,#1f2937 100%);border:1px solid #374151;
  border-radius:12px;padding:18px;text-align:center;box-shadow:0 4px 6px rgba(0,0,0,0.3);}
.kpi-value{font-size:2rem;font-weight:700;color:#00d4ff;}
.kpi-label{font-size:.8rem;color:#9ca3af;text-transform:uppercase;letter-spacing:.05em;margin-top:4px;}
.section-hdr{font-size:1.1rem;font-weight:600;color:#00d4ff;
  border-bottom:1px solid #1e40af;padding-bottom:6px;margin-bottom:14px;}
</style>""", unsafe_allow_html=True)

CHART_LAYOUT = dict(
    paper_bgcolor="#111827", plot_bgcolor="#111827",
    font=dict(color="#e2e8f0"), margin=dict(l=40,r=20,t=30,b=40),
)


@st.cache_data(ttl=300)
def _gen_logs(n=3000):
    rng = np.random.default_rng(42)
    base = datetime.now() - timedelta(hours=48)
    ts = [base + timedelta(seconds=int(s)) for s in np.sort(rng.integers(0, 172800, n))]
    attackers = ["45.33.32.156","23.95.110.42","198.199.85.30","104.21.44.78"]
    src = [f"192.168.{rng.integers(1,10)}.{rng.integers(1,254)}" for _ in range(n)]
    for i in rng.choice(n, 400, replace=False): src[i] = attackers[rng.integers(0,4)]
    et = rng.choice(["Login Attempt","Port Scan","File Access","Data Transfer","Connection","DNS Query"],
                    n, p=[0.25,0.15,0.20,0.10,0.20,0.10])
    return pd.DataFrame({
        "timestamp":ts,
        "source_ip":src,
        "destination_ip":[f"10.0.{rng.integers(0,4)}.{rng.integers(1,50)}" for _ in range(n)],
        "source_port":rng.integers(1024,65535,n),
        "destination_port":rng.choice([22,80,443,3306,3389,8080,21,25,53,8443],n),
        "protocol":rng.choice(["TCP","UDP","ICMP","HTTP","HTTPS","SSH","FTP"],n,
                               p=[0.35,0.20,0.05,0.15,0.15,0.07,0.03]),
        "event_type":et,
        "status":rng.choice(["Success","Failure"],n,p=[0.65,0.35]),
        "bytes_transferred":rng.integers(64,150000,n),
    })


def _load_logs():
    if "logs_df" in st.session_state:
        return st.session_state["logs_df"]
    p = "data/demo_security_logs.csv"
    if os.path.exists(p):
        try:
            df = pd.read_csv(p, parse_dates=["timestamp"])
            st.session_state["logs_df"] = df
            return df
        except Exception:
            pass
    df = _gen_logs()
    st.session_state["logs_df"] = df
    return df


# ── Load data ────────────────────────────────────────────────────────────────
with st.spinner("Loading log data…"):
    logs = _load_logs()

logs["timestamp"] = pd.to_datetime(logs["timestamp"])
logs = logs.sort_values("timestamp", ascending=False).reset_index(drop=True)

# ── Sidebar filters ──────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔍 Log Filters")
    st.divider()

    min_ts = logs["timestamp"].min().to_pydatetime()
    max_ts = logs["timestamp"].max().to_pydatetime()

    date_range = st.date_input("📅 Date range",
        value=(min_ts.date(), max_ts.date()),
        min_value=min_ts.date(), max_value=max_ts.date())

    event_types = ["All"] + sorted(logs["event_type"].unique().tolist())
    sel_events = st.multiselect("📌 Event type", options=event_types[1:],
                                 default=[], placeholder="All event types")

    sel_status = st.selectbox("✅ Status", ["All","Success","Failure"])

    protocols = sorted(logs["protocol"].unique().tolist())
    sel_proto = st.multiselect("🔌 Protocol", options=protocols, default=[],
                                placeholder="All protocols")

    src_ip_filter = st.text_input("🌐 Source IP (contains)", placeholder="e.g. 45.33")

    st.divider()
    st.caption(f"Total records: {len(logs):,}")


# ── Apply filters ─────────────────────────────────────────────────────────────
filtered = logs.copy()

if isinstance(date_range, (list, tuple)) and len(date_range) == 2:
    d0, d1 = date_range
    filtered = filtered[
        (filtered["timestamp"].dt.date >= d0) &
        (filtered["timestamp"].dt.date <= d1)
    ]

if sel_events:
    filtered = filtered[filtered["event_type"].isin(sel_events)]

if sel_status != "All":
    filtered = filtered[filtered["status"] == sel_status]

if sel_proto:
    filtered = filtered[filtered["protocol"].isin(sel_proto)]

if src_ip_filter.strip():
    filtered = filtered[filtered["source_ip"].str.contains(src_ip_filter.strip(), na=False)]

# ── Page header ──────────────────────────────────────────────────────────────
st.markdown("# 📋 Log Monitoring — Security Event Stream")
st.caption(f"Showing {len(filtered):,} events · filtered from {len(logs):,} total · {datetime.now().strftime('%H:%M:%S')}")
st.markdown("---")

# ── Metrics row ───────────────────────────────────────────────────────────────
total_ev    = len(filtered)
fail_count  = int((filtered["status"]=="Failure").sum())
fail_rate   = round(fail_count / max(total_ev, 1) * 100, 1)
uniq_src    = filtered["source_ip"].nunique()

m1, m2, m3, m4 = st.columns(4)
def _metric(col, icon, label, val, color="#00d4ff"):
    col.markdown(f"""
    <div class="kpi-card">
      <div style="font-size:1.5rem;">{icon}</div>
      <div class="kpi-value" style="color:{color};">{val}</div>
      <div class="kpi-label">{label}</div>
    </div>""", unsafe_allow_html=True)

_metric(m1,"📋","Total Events",     f"{total_ev:,}")
_metric(m2,"✅","Filtered Events",  f"{total_ev:,}",    "#22c55e")
_metric(m3,"❌","Failure Rate",     f"{fail_rate}%",    "#ef4444")
_metric(m4,"🌐","Unique Source IPs",f"{uniq_src:,}",    "#a78bfa")

st.markdown("<br>", unsafe_allow_html=True)

# ── Text search across full dataframe ────────────────────────────────────────
col_search, col_btn = st.columns([5, 1])
with col_search:
    global_search = st.text_input("🔍 Search all columns", placeholder="Search IPs, ports, protocols…", label_visibility="collapsed")
with col_btn:
    st.markdown("<br>", unsafe_allow_html=True)

if global_search.strip():
    mask = filtered.apply(lambda row: row.astype(str).str.contains(global_search.strip(), case=False, na=False).any(), axis=1)
    filtered = filtered[mask]

# ── Paginated data table ──────────────────────────────────────────────────────
st.markdown('<div class="section-hdr">📊 Security Event Table</div>', unsafe_allow_html=True)

PAGE_SIZE = 50
total_pages = max(1, (len(filtered) - 1) // PAGE_SIZE + 1)
page_col, exp_col, sus_col = st.columns([3, 1, 1])

with page_col:
    page_num = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1,
                                label_visibility="collapsed")
with exp_col:
    csv_bytes = filtered.to_csv(index=False).encode()
    st.download_button("📥 Export CSV", data=csv_bytes, file_name="filtered_logs.csv",
                        mime="text/csv", use_container_width=True)
with sus_col:
    if st.button("⚠️ Flag Page", use_container_width=True):
        st.warning("Selected page flagged as suspicious.")

start_idx = (page_num - 1) * PAGE_SIZE
page_df = filtered.iloc[start_idx: start_idx + PAGE_SIZE].copy()

# ── Conditional formatting via style ─────────────────────────────────────────
DISPLAY_COLS = ["timestamp","source_ip","destination_ip","source_port",
                "destination_port","protocol","event_type","status","bytes_transferred"]
avail_cols = [c for c in DISPLAY_COLS if c in page_df.columns]
display_df = page_df[avail_cols].copy()
display_df["timestamp"] = display_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

def _color_status(val):
    if val == "Failure":
        return "background-color:#3b0000;color:#fca5a5;font-weight:600;"
    elif val == "Success":
        return "background-color:#003b1f;color:#6ee7b7;font-weight:600;"
    return ""

def _color_bytes(val):
    try:
        v = int(val)
        if v > 100000: return "color:#ef4444;font-weight:600;"
        if v > 50000:  return "color:#f97316;"
    except: pass
    return ""

# ── Table display ─────────────────────────────────────────
byte_target = "bytes" if "bytes" in display_df.columns else ("bytes_transferred" if "bytes_transferred" in display_df.columns else None)

def _style_df(styler):
    if "status" in display_df.columns:
        styler = styler.map(_color_status, subset=["status"])
    if byte_target:
        styler = styler.map(_color_bytes, subset=[byte_target])
        styler = styler.format({byte_target: "{:,}"})
    return styler

st.dataframe(display_df.style.pipe(_style_df), use_container_width=True, height=450)

st.caption(f"Page {page_num} of {total_pages} · {len(filtered):,} matching events")

# ── Event timeline mini-chart ─────────────────────────────────────────────────
st.markdown("<br>", unsafe_allow_html=True)
st.markdown('<div class="section-hdr">📈 Event Timeline</div>', unsafe_allow_html=True)

timeline_df = filtered.copy()
timeline_df["bucket"] = timeline_df["timestamp"].dt.floor("30min")
tl = timeline_df.groupby(["bucket","event_type"]).size().reset_index(name="count")

ET_COLORS = {
    "Login Attempt":   "#ef4444",
    "Port Scan":       "#f97316",
    "File Access":     "#3b82f6",
    "Data Transfer":   "#a78bfa",
    "Connection":      "#22c55e",
    "DNS Query":       "#06b6d4",
}

fig_tl = go.Figure()
for et in tl["event_type"].unique():
    sub = tl[tl["event_type"]==et]
    color = ET_COLORS.get(et, "#6b7280")
    fig_tl.add_trace(go.Bar(
        x=sub["bucket"], y=sub["count"], name=et,
        marker_color=color, opacity=0.85,
    ))
fig_tl.update_layout(**CHART_LAYOUT, height=240, barmode="stack",
    xaxis=dict(gridcolor="#1f2937"),
    yaxis=dict(gridcolor="#1f2937", title="Event count"),
    legend=dict(orientation="h", yanchor="bottom", y=1, xanchor="right", x=1,
                bgcolor="rgba(0,0,0,0)"))
st.plotly_chart(fig_tl, use_container_width=True)

# ── Failure hotspot table ─────────────────────────────────────────────────────
st.markdown('<div class="section-hdr">🔴 Top Failure Source IPs</div>', unsafe_allow_html=True)
fail_df = filtered[filtered["status"]=="Failure"]
top_fail = (fail_df.groupby("source_ip")
            .agg(failure_count=("status","count"),
                 distinct_ports=("destination_port","nunique"),
                 protocols=("protocol", lambda x: ", ".join(x.unique()[:3])))
            .reset_index()
            .sort_values("failure_count", ascending=False)
            .head(10))

if not top_fail.empty:
    st.dataframe(top_fail, use_container_width=True, height=280,
                 column_config={
                     "failure_count": st.column_config.ProgressColumn(
                         "Failure Count", min_value=0, max_value=int(top_fail["failure_count"].max())),
                 })
else:
    st.info("No failure events in current filter.")
