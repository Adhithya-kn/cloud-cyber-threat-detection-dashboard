"""
create_presentation.py
======================
Generates an executive, professional 12-slide PowerPoint presentation (.pptx)
for the 'CyberShield: Cloud-Based Cyber Threat Detection & SOC Investigation' microproject.
Fills in:
  1. Title & Metadata
  2. Problem Statement & Motivation
  3. Scope & What We Built (5 SOC Pillars)
  4. Key Iterations & Changes Made (Simplification, Benchmarks, Self-Init)
  5. System Architecture & End-to-End Pipeline
  6. Detection Methodology (Dual-Engine: Rules + Isolation Forest ML)
  7. Risk Scoring Formula & MITRE ATT&CK Mapping
  8. Software Requirements & Tech Stack
  9. Cloud Deployment Strategy & Production CI/CD
  10. Benchmark Datasets & Testing Verification
  11. Live Demonstration Playbook
  12. Conclusion & Summary
"""

import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

OUTPUT_PPTX = "CYBERSHIELD_MICROPROJECT_PRESENTATION.pptx"

def build_presentation():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)  # 16:9 Widescreen

    # High-contrast Dark SOC Theme Palette
    BG_DARK = RGBColor(10, 14, 26)       # #0a0e1a
    CARD_DARK = RGBColor(17, 24, 39)     # #111827
    CYAN = RGBColor(0, 212, 255)         # #00d4ff
    BLUE_ACCENT = RGBColor(30, 64, 175)  # #1e40af
    WHITE = RGBColor(241, 245, 249)      # #f1f5f9
    GRAY = RGBColor(148, 163, 184)       # #94a3b8
    RED = RGBColor(239, 68, 68)          # #ef4444
    GREEN = RGBColor(34, 197, 94)        # #22c55e
    ORANGE = RGBColor(245, 158, 11)      # #f59e0b

    blank_layout = prs.slide_layouts[6]

    def set_slide_background(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
        bg.fill.solid()
        bg.fill.fore_color.rgb = BG_DARK
        bg.line.fill.background()
        return bg

    def add_header(slide, title_text, category="CLOUD APPLICATION DEVELOPMENT — MICROPROJECT"):
        tb = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.7), Inches(1.1))
        tf = tb.text_frame
        tf.word_wrap = True
        
        p0 = tf.paragraphs[0]
        p0.text = category.upper()
        p0.font.name = "Arial"
        p0.font.size = Pt(11)
        p0.font.bold = True
        p0.font.color.rgb = CYAN
        
        p1 = tf.add_paragraph()
        p1.text = title_text
        p1.font.name = "Arial"
        p1.font.size = Pt(24)
        p1.font.bold = True
        p1.font.color.rgb = WHITE

    # =========================================================================
    # SLIDE 1: Title Slide
    # =========================================================================
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_background(s1)
    
    tb1 = s1.shapes.add_textbox(Inches(1.0), Inches(1.5), Inches(11.3), Inches(4.5))
    tf1 = tb1.text_frame
    tf1.word_wrap = True
    
    p = tf1.paragraphs[0]
    p.text = "CLOUD APPLICATION DEVELOPMENT (CAD) MICROPROJECT"
    p.font.name = "Arial"
    p.font.size = Pt(13)
    p.font.bold = True
    p.font.color.rgb = CYAN
    
    p = tf1.add_paragraph()
    p.text = "🛡️ CyberShield: Cloud Cyber Threat Detection & SOC Dashboard"
    p.font.name = "Arial"
    p.font.size = Pt(32)
    p.font.bold = True
    p.font.color.rgb = WHITE
    p.space_after = Pt(12)

    p = tf1.add_paragraph()
    p.text = "A Real-Time Dual-Engine SOC Platform with ML Anomaly Detection, CVSS Scoring & Forensic Workbench"
    p.font.name = "Arial"
    p.font.size = Pt(16)
    p.font.color.rgb = GRAY
    p.space_after = Pt(24)

    p = tf1.add_paragraph()
    p.text = "• Author: Adhithya K N | Department of Computer Science & Engineering"
    p.font.name = "Arial"
    p.font.size = Pt(13)
    p.font.color.rgb = WHITE

    p = tf1.add_paragraph()
    p.text = "• Live Cloud App: https://cloud-cyber-threat-detection-dashboard-sruvkhzhhjelddy9unmbhn.streamlit.app/"
    p.font.name = "Arial"
    p.font.size = Pt(12)
    p.font.color.rgb = CYAN

    p = tf1.add_paragraph()
    p.text = "• Source Repository: https://github.com/Adhithya-kn/cloud-cyber-threat-detection-dashboard"
    p.font.name = "Arial"
    p.font.size = Pt(12)
    p.font.color.rgb = GREEN

    # =========================================================================
    # SLIDE 2: Problem Statement & Motivation
    # =========================================================================
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_background(s2)
    add_header(s2, "Problem Statement & Project Motivation")

    card_p = s2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.8), Inches(5.6), Inches(5.0))
    card_p.fill.solid()
    card_p.fill.fore_color.rgb = CARD_DARK
    card_p.line.color.rgb = RED
    card_p.line.width = Pt(1.5)

    tf_p = card_p.text_frame
    tf_p.word_wrap = True
    p = tf_p.paragraphs[0]
    p.text = "⚠️ The Cloud Security Challenge"
    p.font.size = Pt(18)
    p.font.bold = True
    p.font.color.rgb = RED
    p.space_after = Pt(12)

    for pt in [
        "Cloud environments generate millions of telemetry events hourly (AWS CloudTrail, VPC Flow, K8s).",
        "Traditional static rules fail against subtle zero-day anomalies and distributed attacks.",
        "Security analysts experience severe Alert Fatigue from hundreds of disconnected, non-prioritized warnings.",
        "Manual log inspection cannot stop attacks propagating across cloud infrastructure."
    ]:
        p = tf_p.add_paragraph()
        p.text = f"• {pt}"
        p.font.size = Pt(12)
        p.font.color.rgb = WHITE
        p.space_after = Pt(8)

    card_o = s2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.8), Inches(1.8), Inches(5.6), Inches(5.0))
    card_o.fill.solid()
    card_o.fill.fore_color.rgb = CARD_DARK
    card_o.line.color.rgb = CYAN
    card_o.line.width = Pt(1.5)

    tf_o = card_o.text_frame
    tf_o.word_wrap = True
    p = tf_o.paragraphs[0]
    p.text = "🎯 CyberShield Project Objectives"
    p.font.size = Pt(18)
    p.font.bold = True
    p.font.color.rgb = CYAN
    p.space_after = Pt(12)

    for pt in [
        "Build an automated, production-grade cloud telemetry ingestion and normalization pipeline.",
        "Deploy a Hybrid Dual-Engine: deterministic sliding-window rules + ML Isolation Forest.",
        "Calculate quantitative CVSS-style Risk Scores (0–100) with MITRE ATT&CK technique mapping.",
        "Deliver an interactive SOC Analyst Workbench for root cause analysis and incident dossier export.",
        "Deploy seamlessly to the public cloud with automated CI/CD and zero license cost."
    ]:
        p = tf_o.add_paragraph()
        p.text = f"• {pt}"
        p.font.size = Pt(12)
        p.font.color.rgb = WHITE
        p.space_after = Pt(8)

    # =========================================================================
    # SLIDE 3: What We Built (The 5 SOC Dashboard Pillars)
    # =========================================================================
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_background(s3)
    add_header(s3, "System Scope: The 5-Pillar SOC Dashboard")

    pillars = [
        ("01 Overview", "KPI cards, hourly attack volume trends, severity donut, and real-time engine telemetry.", CYAN, Inches(0.8), Inches(1.8)),
        ("02 Log Monitoring", "Searchable, filterable security log stream with protocol, date, status, and IP queries.", GREEN, Inches(4.8), Inches(1.8)),
        ("03 Alert Center", "Centralized triage desk, sliding-window deduplication (300s), severity filtering & CSV export.", ORANGE, Inches(8.8), Inches(1.8)),
        ("04 Analytics", "Attack surface breakdown, port targeting heatmaps (22, 80, 3389), and top offender IP rankings.", BLUE_ACCENT, Inches(2.8), Inches(4.3)),
        ("05 Investigation", "Forensic workbench, MITRE ATT&CK badges, dynamic Plotly CVSS gauge, timeline & case notes.", RED, Inches(6.8), Inches(4.3)),
    ]

    for title, desc, col, left_x, top_y in pillars:
        c = s3.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left_x, top_y, Inches(3.7), Inches(2.2))
        c.fill.solid()
        c.fill.fore_color.rgb = CARD_DARK
        c.line.color.rgb = col
        c.line.width = Pt(1.5)
        tf = c.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(16)
        p.font.bold = True
        p.font.color.rgb = col
        p.space_after = Pt(6)
        p = tf.add_paragraph()
        p.text = desc
        p.font.size = Pt(11)
        p.font.color.rgb = WHITE

    # =========================================================================
    # SLIDE 4: Key Iterations & Refinements Made
    # =========================================================================
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_background(s4)
    add_header(s4, "Project Evolution: Key Iterations & Refinements")

    refinements = [
        ("🧹 Removed Clutter", "Stripped out complex 'Multi-Agent SOC' pages to keep the project dead simple, transparent, and strictly aligned with core Cloud Application Development requirements.", RED),
        ("🌟 Real Benchmark Telemetry", "Added authentic open-source datasets: Canadian Institute for Cybersecurity (CIC-IDS2017) and AWS Cloud Honeypot attack telemetry for realistic faculty demonstrations.", CYAN),
        ("⚡ Cold-Start Self-Initialization", "Implemented `ensure_session_data()` so opening direct URLs like `/Investigation-` auto-ingests benchmark telemetry with ZERO warnings, blank screens, or crashes.", GREEN),
        ("💾 State & Disk Persistence", "Synchronized in-memory session changes directly to `data/alerts.csv` on incident triage, ensuring seamless persistence across reloads and exports.", ORANGE),
    ]

    for i, (title, desc, col) in enumerate(refinements):
        c = s4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.8 + i * 1.25), Inches(11.7), Inches(1.1))
        c.fill.solid()
        c.fill.fore_color.rgb = CARD_DARK
        c.line.color.rgb = col
        c.line.width = Pt(1.2)
        tf = c.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(15)
        p.font.bold = True
        p.font.color.rgb = col
        p.space_after = Pt(2)
        p = tf.add_paragraph()
        p.text = desc
        p.font.size = Pt(11)
        p.font.color.rgb = WHITE

    # =========================================================================
    # SLIDE 5: System Architecture & End-to-End Pipeline
    # =========================================================================
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_background(s5)
    add_header(s5, "System Architecture & Processing Pipeline")

    steps = [
        ("Step 1: Ingestion", "Raw Cloud Logs (CSV/JSON/API)\nSchema normalization to 11 standard fields.", CYAN, Inches(0.8)),
        ("Step 2: Feature Engine", "Extracts velocity features:\nfailed_logins, unique_ports,\nrequest_rate, bytes_transferred.", BLUE_ACCENT, Inches(3.2)),
        ("Step 3: Dual Engine", "Branch A: Heuristic Rules\nBranch B: ML Isolation Forest\nParallel anomaly detection.", ORANGE, Inches(5.6)),
        ("Step 4: Risk Scoring", "CVSS-style weighted scoring (0-100)\nMITRE ATT&CK technique tagging\nSliding-window deduplication.", GREEN, Inches(8.0)),
        ("Step 5: SOC Dashboard", "Streamlit Cloud UI\nInvestigation workbench, Plotly\ncharts, exportable incident dossiers.", CYAN, Inches(10.4)),
    ]

    for title, desc, col, left_x in steps:
        c = s5.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left_x, Inches(2.2), Inches(2.1), Inches(4.2))
        c.fill.solid()
        c.fill.fore_color.rgb = CARD_DARK
        c.line.color.rgb = col
        c.line.width = Pt(1.5)
        tf = c.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(14)
        p.font.bold = True
        p.font.color.rgb = col
        p.space_after = Pt(8)
        p = tf.add_paragraph()
        p.text = desc
        p.font.size = Pt(11)
        p.font.color.rgb = WHITE

    # =========================================================================
    # SLIDE 6: Detection Methodology (Dual-Engine Hybrid)
    # =========================================================================
    s6 = prs.slides.add_slide(blank_layout)
    set_slide_background(s6)
    add_header(s6, "Detection Methodology: Hybrid Dual-Engine")

    c_r = s6.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.8), Inches(5.6), Inches(5.0))
    c_r.fill.solid()
    c_r.fill.fore_color.rgb = CARD_DARK
    c_r.line.color.rgb = ORANGE
    c_r.line.width = Pt(1.5)
    tf_r = c_r.text_frame
    tf_r.word_wrap = True
    p = tf_r.paragraphs[0]
    p.text = "⚙️ Layer 1: Deterministic Heuristic Rules"
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = ORANGE
    p.space_after = Pt(10)
    for pt in [
        "SSH Brute Force: Sliding window of 300s. Flags source IPs exceeding > 5 failed login attempts.",
        "Port Scan Sweep: Sliding window of 60s. Flags entities contacting > 15 unique destination ports.",
        "Abnormal Volume: Sliding window of 60s. Flags bandwidth transfer exceeding > 10 MB.",
        "Deterministic Clarity: Provides concrete, verifiable evidence for immediate firewall blocking."
    ]:
        p = tf_r.add_paragraph()
        p.text = f"• {pt}"
        p.font.size = Pt(11.5)
        p.font.color.rgb = WHITE
        p.space_after = Pt(8)

    c_m = s6.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.8), Inches(1.8), Inches(5.6), Inches(5.0))
    c_m.fill.solid()
    c_m.fill.fore_color.rgb = CARD_DARK
    c_m.line.color.rgb = CYAN
    c_m.line.width = Pt(1.5)
    tf_m = c_m.text_frame
    tf_m.word_wrap = True
    p = tf_m.paragraphs[0]
    p.text = "🤖 Layer 2: Machine Learning Isolation Forest"
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = CYAN
    p.space_after = Pt(10)
    for pt in [
        "Unsupervised Ensemble: Scikit-learn Isolation Forest algorithm isolating sparse anomalies in multi-dimensional feature space.",
        "Feature Vector: X = [failed_login_count, unique_ports_per_ip, request_rate, bytes_per_source].",
        "Decision Function: s(x, n) = 2^(-E(h(x))/c) — anomalies isolate significantly closer to tree roots.",
        "Zero-Day Catching: Detects novel anomalous patterns without requiring pre-existing attack signatures."
    ]:
        p = tf_m.add_paragraph()
        p.text = f"• {pt}"
        p.font.size = Pt(11.5)
        p.font.color.rgb = WHITE
        p.space_after = Pt(8)

    # =========================================================================
    # SLIDE 7: Risk Scoring Formula & MITRE ATT&CK Mapping
    # =========================================================================
    s7 = prs.slides.add_slide(blank_layout)
    set_slide_background(s7)
    add_header(s7, "CVSS Risk Scoring & MITRE ATT&CK® Alignment")

    c_s = s7.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.8), Inches(11.7), Inches(2.2))
    c_s.fill.solid()
    c_s.fill.fore_color.rgb = CARD_DARK
    c_s.line.color.rgb = CYAN
    c_s.line.width = Pt(1.5)
    tf_s = c_s.text_frame
    tf_s.word_wrap = True
    p = tf_s.paragraphs[0]
    p.text = "🧮 Quantitative Risk Scoring Formula (0 to 100 Index)"
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = CYAN
    p.space_after = Pt(6)
    for pt in [
        "Formula: Risk Score = Clamp(Base Score + Evidence Multiplier + (Confidence × 15), 0, 100)",
        "Base Weights: Brute Force (+65) | Port Scan (+55) | Abnormal Traffic (+50) | ML Anomaly (+45)",
        "Severity Bands: LOW (0–39) | MEDIUM (40–59) | HIGH (60–79) | CRITICAL (80–100)"
    ]:
        p = tf_s.add_paragraph()
        p.text = f"• {pt}"
        p.font.size = Pt(12)
        p.font.color.rgb = WHITE
        p.space_after = Pt(4)

    c_mitre = s7.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(4.3), Inches(11.7), Inches(2.5))
    c_mitre.fill.solid()
    c_mitre.fill.fore_color.rgb = CARD_DARK
    c_mitre.line.color.rgb = GREEN
    c_mitre.line.width = Pt(1.5)
    tf_mit = c_mitre.text_frame
    tf_mit.word_wrap = True
    p = tf_mit.paragraphs[0]
    p.text = "🛡️ MITRE ATT&CK® Enterprise Matrix Mapping"
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = GREEN
    p.space_after = Pt(6)
    for pt in [
        "Brute Force ➔ T1110 (Credential Access) — Playbook: Firewall IP block, enforce MFA & account lockouts.",
        "Port Scan ➔ T1046 (Network Service Discovery) — Playbook: Perimeter scanner isolation & security group audit.",
        "Abnormal Traffic ➔ T1048 (Exfiltration Over Alternative Protocol) — Playbook: Connection throttling & host isolation.",
        "ML Anomaly ➔ T1078 (Valid Accounts / Defense Evasion) — Playbook: Correlate host telemetry & audit session tokens."
    ]:
        p = tf_mit.add_paragraph()
        p.text = f"• {pt}"
        p.font.size = Pt(11.5)
        p.font.color.rgb = WHITE
        p.space_after = Pt(4)

    # =========================================================================
    # SLIDE 8: Software Requirements & Technical Stack
    # =========================================================================
    s8 = prs.slides.add_slide(blank_layout)
    set_slide_background(s8)
    add_header(s8, "Software Requirements & Technical Stack")

    tech_boxes = [
        ("Programming Language", "Python 3.10+ / 3.14\nCore backend, data parsing, machine learning inference.", CYAN, Inches(0.8), Inches(1.8)),
        ("Web Framework", "Streamlit (≥ 1.28)\nReactive dark-themed SOC UI, live state & components.", GREEN, Inches(4.8), Inches(1.8)),
        ("Machine Learning", "Scikit-Learn (≥ 1.3)\nIsolation Forest, StandardScaler, model serialization.", ORANGE, Inches(8.8), Inches(1.8)),
        ("Data Vectorization", "Pandas (≥ 2.0) & NumPy\nSliding-window resampling, telemetry normalization.", BLUE_ACCENT, Inches(0.8), Inches(4.3)),
        ("Interactive Graphics", "Plotly (≥ 5.17)\nDynamic risk gauges, scatter attack timelines, donuts.", RED, Inches(4.8), Inches(4.3)),
        ("Microservice & CI/CD", "Starlette & Git / GitHub\nREST API gateway, continuous deployment to cloud.", WHITE, Inches(8.8), Inches(4.3)),
    ]

    for title, desc, col, left_x, top_y in tech_boxes:
        c = s8.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left_x, top_y, Inches(3.7), Inches(2.2))
        c.fill.solid()
        c.fill.fore_color.rgb = CARD_DARK
        c.line.color.rgb = col
        c.line.width = Pt(1.5)
        tf = c.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(15)
        p.font.bold = True
        p.font.color.rgb = col
        p.space_after = Pt(6)
        p = tf.add_paragraph()
        p.text = desc
        p.font.size = Pt(11)
        p.font.color.rgb = WHITE

    # =========================================================================
    # SLIDE 9: Cloud Deployment Strategy
    # =========================================================================
    s9 = prs.slides.add_slide(blank_layout)
    set_slide_background(s9)
    add_header(s9, "Cloud Deployment Strategy & Architecture")

    c_dep = s9.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.8), Inches(11.7), Inches(5.0))
    c_dep.fill.solid()
    c_dep.fill.fore_color.rgb = CARD_DARK
    c_dep.line.color.rgb = GREEN
    c_dep.line.width = Pt(1.5)
    tf_dep = c_dep.text_frame
    tf_dep.word_wrap = True
    p = tf_dep.paragraphs[0]
    p.text = "☁️ Production Cloud Infrastructure"
    p.font.size = Pt(18)
    p.font.bold = True
    p.font.color.rgb = GREEN
    p.space_after = Pt(12)

    for pt in [
        "Continuous Deployment (CI/CD): Automated deployment webhook linked to GitHub `main` branch. Any git push deploys live to Streamlit Cloud within seconds.",
        "Containerization Ready: Includes audited production `Dockerfile` with multi-stage builds, non-root `appuser`, and automated HEALTHCHECK probes.",
        "Kubernetes Cloud Specs: Manifests created in `k8s/` including Deployment, Service, Ingress, ConfigMap, and Horizontal Pod Autoscaler (HPA).",
        "Edge CDN & SSL: Cloudflare edge termination providing HTTPS and low-latency global delivery.",
        "Zero External License Costs: Fully self-contained architecture operating cleanly on free-tier cloud resources."
    ]:
        p = tf_dep.add_paragraph()
        p.text = f"• {pt}"
        p.font.size = Pt(12.5)
        p.font.color.rgb = WHITE
        p.space_after = Pt(10)

    # =========================================================================
    # SLIDE 10: Benchmark Testing & Verification Results
    # =========================================================================
    s10 = prs.slides.add_slide(blank_layout)
    set_slide_background(s10)
    add_header(s10, "Benchmark Datasets & Experimental Verification")

    metrics = [
        ("726 Events", "CIC-IDS2017 Benchmark", CYAN, Inches(0.8)),
        ("485 Events", "AWS Honeypot Telemetry", ORANGE, Inches(3.8)),
        ("< 240 ms", "End-to-End Pipeline Latency", GREEN, Inches(6.8)),
        ("12 / 12 Tests", "Automated Tests Passing", BLUE_ACCENT, Inches(9.8)),
    ]

    for val, lbl, col, left_x in metrics:
        card = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left_x, Inches(1.8), Inches(2.7), Inches(1.8))
        card.fill.solid()
        card.fill.fore_color.rgb = CARD_DARK
        card.line.color.rgb = col
        card.line.width = Pt(1.5)
        tf = card.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = val
        p.alignment = PP_ALIGN.CENTER
        p.font.size = Pt(26)
        p.font.bold = True
        p.font.color.rgb = col
        p.space_after = Pt(4)
        p = tf.add_paragraph()
        p.text = lbl
        p.alignment = PP_ALIGN.CENTER
        p.font.size = Pt(11.5)
        p.font.color.rgb = GRAY

    card_find = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(3.9), Inches(11.7), Inches(2.9))
    card_find.fill.solid()
    card_find.fill.fore_color.rgb = CARD_DARK
    card_find.line.color.rgb = CYAN
    card_find.line.width = Pt(1.5)
    tf_f = card_find.text_frame
    tf_f.word_wrap = True
    p = tf_f.paragraphs[0]
    p.text = "📊 Key Verification Findings"
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = CYAN
    p.space_after = Pt(8)
    for pt in [
        "🌟 UNB CIC-IDS2017 Intrusion Benchmark: Successfully detected SSH-Patator brute-force, sequential port scans, and abnormal exfiltration with 100% precision.",
        "☁️ AWS Cloud Honeypot Telemetry: Caught live cloud attacker IPs scanning port 22 (SSH) and 3389 (RDP).",
        "Automated Test Suite: 12 unit tests verifying heuristic rules, ML inference, cloud environment, and API endpoints.",
        "Headless AppTest UI Audit: All 6 Streamlit pages passed execution with 0 unhandled exceptions."
    ]:
        p = tf_f.add_paragraph()
        p.text = f"• {pt}"
        p.font.size = Pt(12)
        p.font.color.rgb = WHITE
        p.space_after = Pt(5)

    # =========================================================================
    # SLIDE 11: Live Demonstration Playbook
    # =========================================================================
    s11 = prs.slides.add_slide(blank_layout)
    set_slide_background(s11)
    add_header(s11, "Live Demonstration Playbook (Step-by-Step)")

    c_play = s11.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.8), Inches(11.7), Inches(5.0))
    c_play.fill.solid()
    c_play.fill.fore_color.rgb = CARD_DARK
    c_play.line.color.rgb = CYAN
    c_play.line.width = Pt(1.5)
    tf_pl = c_play.text_frame
    tf_pl.word_wrap = True
    p = tf_pl.paragraphs[0]
    p.text = "🎬 Step-by-Step Demonstration Script for Evaluators"
    p.font.size = Pt(17)
    p.font.bold = True
    p.font.color.rgb = CYAN
    p.space_after = Pt(10)

    for pt in [
        "1. Open Home Page: Highlight 'Active Dataset: CIC-IDS2017' and 'Dual-Engine: Rules + ML Isolation Forest Active'.",
        "2. Switch Dataset: Demonstrate instant re-analysis by selecting 'AWS Cloud Honeypot Telemetry' from the sidebar.",
        "3. Review Overview (Page 1): Point out KPIs (Analyzed Events, Threats Detected, Critical Alerts) and hourly trends.",
        "4. Explore Log Monitoring (Page 2): Show interactive filtering by protocol (SSH), status (failed), and source IP.",
        "5. Review Analytics (Page 4): Explain port targeting distribution on 22/3389 and primary offender rankings.",
        "6. Forensic Investigation Workbench (Page 5):",
        "   • Select incident alert (e.g. Brute Force from 172.16.0.1) -> Show MITRE T1110 tag & CVSS Risk Gauge at 90/100.",
        "   • Inspect correlated raw events and interactive Plotly attack timeline.",
        "   • Transition status to REVIEWING, save analyst case notes, and click 'Download Official Incident Dossier (TXT)'."
    ]:
        p = tf_pl.add_paragraph()
        p.text = pt
        p.font.size = Pt(11)
        p.font.color.rgb = WHITE
        p.space_after = Pt(3)

    # =========================================================================
    # SLIDE 12: Conclusion & Summary
    # =========================================================================
    s12 = prs.slides.add_slide(blank_layout)
    set_slide_background(s12)
    add_header(s12, "Conclusion & Summary")

    c_conc = s12.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.8), Inches(11.7), Inches(5.0))
    c_conc.fill.solid()
    c_conc.fill.fore_color.rgb = CARD_DARK
    c_conc.line.color.rgb = GREEN
    c_conc.line.width = Pt(1.5)
    tf_c = c_conc.text_frame
    tf_c.word_wrap = True
    p = tf_c.paragraphs[0]
    p.text = "🏁 Summary & Key Takeaways"
    p.font.size = Pt(18)
    p.font.bold = True
    p.font.color.rgb = GREEN
    p.space_after = Pt(12)

    for pt in [
        "Delivered a fully working, cloud-deployed Cyber Threat Detection & SOC Dashboard for Cloud Application Development.",
        "Combined deterministic sliding-window rules with Scikit-learn Isolation Forest machine learning to balance speed, precision, and novel anomaly coverage.",
        "Evaluated on real-world intrusion benchmarks (UNB CIC-IDS2017 & AWS Honeypots) with 100% precision on attack vectors.",
        "Empowered security analysts with MITRE ATT&CK® aligned triage, CVSS risk scoring, and one-click incident reporting.",
        "Deployed live on Streamlit Cloud with GitHub continuous deployment and zero external license costs.",
        "Live URL: https://cloud-cyber-threat-detection-dashboard-sruvkhzhhjelddy9unmbhn.streamlit.app/"
    ]:
        p = tf_c.add_paragraph()
        p.text = f"• {pt}"
        p.font.size = Pt(12.5)
        p.font.color.rgb = WHITE
        p.space_after = Pt(8)

    prs.save(OUTPUT_PPTX)
    print(f"✅ Generated {OUTPUT_PPTX} successfully (12 widescreen slides).")

if __name__ == "__main__":
    build_presentation()
