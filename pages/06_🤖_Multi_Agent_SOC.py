"""
pages/06_🤖_Multi_Agent_SOC.py
==============================
CyberShield Multi-Agent Autonomous SOC Command & Orchestration Center.
Visualizes agent fleets, annotated execution traces, MITRE ATT&CK correlation,
and cloud incident mitigation playbooks.
"""

import os
import sys
import time
from datetime import datetime, timezone
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Path setup
sys.path.insert(0, ".")

from orchestration import get_orchestrator, OrchestrationSession

# Page Config
st.set_page_config(
    page_title="Multi-Agent SOC | CyberShield",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom SOC Dark CSS
SOC_CSS = """
<style>
.main { background-color: #0a0e1a; }
.stApp { background-color: #0a0e1a; }

.agent-card {
    background: linear-gradient(135deg, #111827 0%, #1e293b 100%);
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 16px;
    margin-bottom: 12px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.4);
    transition: transform 0.2s ease, border-color 0.2s ease;
}
.agent-card:hover {
    border-color: #00d4ff;
    transform: translateY(-2px);
}
.agent-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
}
.agent-name {
    font-size: 1.05rem;
    font-weight: 700;
    color: #f8fafc;
}
.agent-role {
    font-size: 0.78rem;
    color: #94a3b8;
    margin-bottom: 8px;
}
.agent-pill {
    padding: 3px 10px;
    border-radius: 9999px;
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}
.pill-active   { background: #064e3b; color: #34d399; border: 1px solid #059669; }
.pill-threat   { background: #7f1d1d; color: #fca5a5; border: 1px solid #dc2626; }
.pill-clean    { background: #1e3a5f; color: #60a5fa; border: 1px solid #2563eb; }
.pill-standby  { background: #374151; color: #d1d5db; border: 1px solid #4b5563; }

.trace-step-box {
    background: #0f172a;
    border-left: 4px solid #00d4ff;
    border-radius: 0 8px 8px 0;
    padding: 14px 18px;
    margin-bottom: 12px;
    border-top: 1px solid #1e293b;
    border-right: 1px solid #1e293b;
    border-bottom: 1px solid #1e293b;
}
.trace-title {
    font-size: 0.95rem;
    font-weight: 700;
    color: #38bdf8;
    display: flex;
    justify-content: space-between;
    align-items: center;
}
.trace-annotation {
    color: #e2e8f0;
    font-size: 0.88rem;
    line-height: 1.5;
    margin-top: 6px;
    background: #1e293b;
    padding: 10px 14px;
    border-radius: 6px;
    border: 1px solid #334155;
}
.playbook-card {
    background: #111827;
    border: 1px solid #dc2626;
    border-radius: 8px;
    padding: 14px;
    margin-bottom: 12px;
}
.code-block {
    background: #020617;
    border: 1px solid #1e293b;
    border-radius: 6px;
    padding: 8px 12px;
    font-family: monospace;
    font-size: 0.82rem;
    color: #38bdf8;
    overflow-x: auto;
}
</style>
"""
st.markdown(SOC_CSS, unsafe_allow_html=True)

# ── Title & Cloud Banner ─────────────────────────────────────────────────────
st.markdown("""
<div style='margin-bottom: 16px;'>
  <div style='font-size:2.4rem; font-weight:800; color:#00d4ff; display:flex; align-items:center; gap:10px;'>
    🤖 Multi-Agent Autonomous SOC Orchestrator
  </div>
  <div style='font-size:1.0rem; color:#94a3b8;'>
    Cloud Application Security Operations Center · Autonomous Detection, ML Anomaly Oracle & Incident Response
  </div>
</div>
""", unsafe_allow_html=True)

# Retrieve current orchestrator
orch = get_orchestrator()

# Session State Cache for Orchestration
if "orchestration_session" not in st.session_state:
    # Run initial orchestration on active dataset or demo logs
    init_data = st.session_state.get("logs_df", pd.DataFrame())
    if init_data.empty and os.path.exists("data/demo_security_logs.csv"):
        init_data = pd.read_csv("data/demo_security_logs.csv")
    
    if not init_data.empty:
        st.session_state["orchestration_session"] = orch.run_pipeline(
            init_data,
            dataset_name=st.session_state.get("active_dataset_name", "Baseline Cloud Telemetry"),
            persist_alerts=False
        )
    else:
        st.session_state["orchestration_session"] = None

session: OrchestrationSession = st.session_state.get("orchestration_session")

# ── Top Control & Scenario Trigger Bar ────────────────────────────────────────
with st.container():
    c_ctrl1, c_ctrl2, c_ctrl3 = st.columns([2, 1.5, 1])
    with c_ctrl1:
        st.markdown(f"**Active Session:** `{session.session_id if session else 'None'}` · **Dataset:** `{session.dataset_name if session else 'None'}`")
    with c_ctrl2:
        scenario = st.selectbox(
            "Attack Simulation Scenario:",
            [
                "Current Active Dataset",
                "Simulate SSH Brute Force Infiltration",
                "Simulate Lateral Port Scan Reconnaissance",
                "Simulate High-Volume Data Exfiltration",
                "Simulate Multi-Vector Cloud Breach",
            ],
            label_visibility="collapsed",
        )
    with c_ctrl3:
        if st.button("⚡ Run Multi-Agent Triage", type="primary", use_container_width=True):
            with st.spinner("Dispatching agents across pipeline..."):
                # Determine dataframe
                if scenario == "Simulate SSH Brute Force Infiltration" and os.path.exists("data/dataset_2_bruteforce_attack.csv"):
                    sim_df = pd.read_csv("data/dataset_2_bruteforce_attack.csv")
                    s_name = "SSH Brute-Force Incident"
                elif scenario == "Simulate Multi-Vector Cloud Breach" and os.path.exists("data/dataset_3_multivector_breach.csv"):
                    sim_df = pd.read_csv("data/dataset_3_multivector_breach.csv")
                    s_name = "Multi-Vector Breach Incident"
                elif os.path.exists("data/demo_security_logs.csv"):
                    sim_df = pd.read_csv("data/demo_security_logs.csv")
                    s_name = "Full Demo Telemetry"
                else:
                    sim_df = st.session_state.get("logs_df", pd.DataFrame())
                    s_name = "Current Dataset"

                new_session = orch.run_pipeline(sim_df, dataset_name=s_name, persist_alerts=True)
                st.session_state["orchestration_session"] = new_session
                st.session_state["logs_df"] = new_session.enriched_df
                st.session_state["alerts_df"] = new_session.alerts_df
                st.session_state["active_dataset_name"] = s_name
                st.success(f"Multi-Agent Orchestration complete in {new_session.total_latency_ms:.1f}ms!")
                st.rerun()

st.divider()

# ── Section 1: Autonomous Agent Fleet Grid ────────────────────────────────────
st.markdown("### 🛡️ Autonomous Agent Fleet")
st.caption("Five specialized agents collaborate in an orchestrated pipeline to detect, verify, triage, and contain threats.")

f1, f2, f3, f4, f5 = st.columns(5)
fleet_cols = [f1, f2, f3, f4, f5]

if session and session.agent_stats:
    agent_keys = ["agent_alpha", "agent_beta", "agent_gamma", "agent_delta", "agent_epsilon"]
    for idx, key in enumerate(agent_keys):
        info = session.agent_stats.get(key, {})
        col = fleet_cols[idx]
        
        status = info.get("status", "STANDBY")
        pill_class = "pill-active" if status in ["SUCCESS", "MITIGATIONS_DISPATCHED"] else ("pill-threat" if status == "THREATS_DETECTED" else "pill-clean")
        
        with col:
            st.markdown(f"""
            <div class="agent-card">
              <div class="agent-header">
                <span style="font-size:1.6rem;">{info.get('icon', '🤖')}</span>
                <span class="agent-pill {pill_class}">{status}</span>
              </div>
              <div class="agent-name">{info.get('name', key)}</div>
              <div class="agent-role">{info.get('role', '')}</div>
              <div style="font-size:0.75rem; color:#64748b; margin-top:8px;">
                ⏱ Latency: <b style="color:#38bdf8;">{info.get('last_latency_ms', 0)} ms</b>
              </div>
            </div>
            """, unsafe_allow_html=True)
            
            with st.expander("Assigned Rules"):
                for r in info.get("rules", []):
                    st.markdown(f"- `{r}`")

st.markdown("<br>", unsafe_allow_html=True)

# ── Section 2: Step-by-Step Annotated Execution Trace ─────────────────────────
st.markdown("### 📋 Step-by-Step Annotated Execution Trace")
st.caption("Full verifiable audit trail. Every single algorithmic decision, heuristic evaluation, and ML prediction is annotated with confidence scores and evidence.")

if session and session.step_annotations:
    for step in session.step_annotations:
        status_color = "#10b981" if step.status in ["SUCCESS", "CLEAN"] else ("#ef4444" if step.status == "THREATS_DETECTED" else "#8b5cf6")
        
        st.markdown(f"""
        <div class="trace-step-box" style="border-left-color: {status_color};">
          <div class="trace-title">
            <span>
              <span style="font-size:1.1rem; margin-right:6px;">{step.agent_icon}</span>
              <b>Step {step.step_number}:</b> {step.agent_name}
            </span>
            <span style="font-size:0.8rem; color:#94a3b8;">
              <span style="background:#1e293b; padding:2px 8px; border-radius:4px; margin-right:8px; border:1px solid #334155;">{step.rule_category}</span>
              <span style="color:{status_color}; font-weight:700;">{step.status}</span>
              · ⏱ {step.execution_time_ms:.1f}ms
              · Confidence: <b style="color:#00d4ff;">{int(step.confidence * 100)}%</b>
            </span>
          </div>
          <div class="trace-annotation">
            💡 <b>Step Annotation & Rationale:</b><br>
            {step.annotation}
          </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Expandable evidence metrics
        with st.expander(f"🔍 Inspect Step {step.step_number} Telemetry Evidence ({step.agent_id})"):
            c_ev1, c_ev2 = st.columns([2, 1])
            with c_ev1:
                st.json(step.evidence)
            with c_ev2:
                st.markdown(f"**Step Timestamp:** `{step.timestamp} UTC`")
                st.markdown(f"**Agent ID:** `{step.agent_id}`")
                st.markdown(f"**Engine Confidence:** `{step.confidence:.2f}`")

st.markdown("<br>", unsafe_allow_html=True)

# ── Section 3: MITRE ATT&CK Matrix & Threat Distribution ──────────────────────
st.markdown("### 🎯 MITRE ATT&CK Cloud Matrix Correlation")
col_mitre1, col_mitre2 = st.columns([3, 2])

with col_mitre1:
    if session and not session.alerts_df.empty:
        # Build MITRE tactical summary
        mitre_data = []
        for idx, row in session.alerts_df.iterrows():
            mitre_data.append({
                "Tactic": row.get("mitre_tactic", "Initial Access"),
                "Technique": f"{row.get('mitre_technique_id', 'T1110')} - {row.get('threat_type', 'threat').upper()}",
                "Severity": row.get("severity", "MEDIUM"),
                "Source IP": row.get("source_ip", "unknown"),
                "Risk Score": row.get("risk_score", 50),
            })
        m_df = pd.DataFrame(mitre_data)
        
        fig_m = px.treemap(
            m_df,
            path=["Tactic", "Technique", "Severity"],
            values="Risk Score",
            color="Severity",
            color_discrete_map={"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#10b981"},
            title="MITRE ATT&CK Enterprise Matrix Threat Distribution"
        )
        fig_m.update_layout(
            paper_bgcolor="#111827",
            plot_bgcolor="#111827",
            font=dict(color="#e2e8f0"),
            height=320,
            margin=dict(t=30, b=10, l=10, r=10),
        )
        st.plotly_chart(fig_m, use_container_width=True)
    else:
        st.info("No active threats detected. MITRE ATT&CK matrix clear.")

with col_mitre2:
    if session:
        st.markdown("#### 🤝 Multi-Agent Consensus Summary")
        cs = session.consensus_summary
        st.markdown(f"- **Total Triaged Threats:** `{cs.get('total_threats', 0)}`")
        st.markdown(f"- **Consensus Offending IPs:** `{', '.join(cs.get('consensus_ips', [])) or 'None'}`")
        st.markdown(f"- **Tactics Identified:** `{', '.join(cs.get('mitre_tactics', [])) or 'None'}`")
        st.markdown(f"- **Orchestration Confidence:** `{int(cs.get('orchestration_confidence', 0.95)*100)}%`")
        st.markdown(f"- **Total Orchestration Latency:** `{session.total_latency_ms:.1f} ms`")
        
        # Risk gauge chart
        fig_g = go.Figure(go.Indicator(
            mode="gauge+number",
            value=int(cs.get('orchestration_confidence', 0.95) * 100),
            title={'text': "Consensus Confidence", 'font': {'color': '#e2e8f0'}},
            gauge={
                'axis': {'range': [0, 100], 'tickcolor': "#94a3b8"},
                'bar': {'color': "#00d4ff"},
                'steps': [
                    {'range': [0, 50], 'color': "#374151"},
                    {'range': [50, 80], 'color': "#1e3a5f"},
                    {'range': [80, 100], 'color': "#064e3b"}
                ],
            }
        ))
        fig_g.update_layout(paper_bgcolor="#111827", font=dict(color="#e2e8f0"), height=200, margin=dict(t=20, b=10, l=10, r=10))
        st.plotly_chart(fig_g, use_container_width=True)

st.markdown("<br>", unsafe_allow_html=True)

# ── Section 4: Autonomous Cloud Incident Mitigation Console ──────────────────
st.markdown("### ⚡ Autonomous Cloud Incident Mitigation Console")
st.caption("Formulated by Agent-Epsilon (Autonomous Responder). Actionable CLI containment playbooks ready for perimeter cloud firewall execution.")

if session and session.playbooks:
    for pb in session.playbooks:
        with st.container():
            st.markdown(f"""
            <div class="playbook-card">
              <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="font-weight:700; color:#ef4444; font-size:1.0rem;">
                  🚨 Incident Containment Playbook: {pb.get('incident_id')}
                </span>
                <span style="background:#7f1d1d; color:#fca5a5; padding:2px 8px; border-radius:4px; font-size:0.75rem; font-weight:700;">
                  {pb.get('severity')} · Risk {pb.get('risk_score')}/100
                </span>
              </div>
              <div style="font-size:0.85rem; color:#94a3b8; margin:6px 0;">
                Target Offender: <b style="color:#f8fafc;">{pb.get('offending_ip')}</b> · 
                Attack Vector: <b style="color:#f8fafc;">{pb.get('threat_type').upper()}</b> · 
                MITRE Technique: <b style="color:#38bdf8;">{pb.get('mitre_technique')}</b>
              </div>
            </div>
            """, unsafe_allow_html=True)
            
            p_cols = st.columns([3, 1])
            with p_cols[0]:
                for act in pb.get("actions", []):
                    st.markdown(f"**Action: {act.get('type')}** ({act.get('provider')})")
                    st.markdown(f"<div class='code-block'>{act.get('command')}</div>", unsafe_allow_html=True)
                    st.caption(act.get("description"))
            
            with p_cols[1]:
                st.markdown("<br>", unsafe_allow_html=True)
                if st.button(f"🛡️ Execute Containment", key=f"btn_mit_{pb.get('incident_id')}", use_container_width=True, type="secondary"):
                    st.toast(f"✅ Perimeter Block Rule dispatched for {pb.get('offending_ip')} via Cloud WAF!")
                    st.success(f"Containment active! Offender {pb.get('offending_ip')} dropped at cloud edge.")

else:
    st.success("✅ Clean Posture: No high-severity threats currently requiring autonomous cloud mitigation.")

st.markdown("<br>")
st.caption("CyberShield Multi-Agent SOC Module · Cloud Application Development Microproject")
