# 🛡️ Cloud-Based Cyber Threat Detection Dashboard

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28%2B-FF4B4B?logo=streamlit&logoColor=white)
![Scikit-learn](https://img.shields.io/badge/scikit--learn-1.3%2B-F7931E?logo=scikitlearn&logoColor=white)
![Plotly](https://img.shields.io/badge/Plotly-5.17%2B-3F4F75?logo=plotly&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## Overview

The **Cloud-Based Cyber Threat Detection Dashboard** is a real-time security operations centre (SOC) tool built with Python and Streamlit. It ingests simulated network event streams, applies a layered detection pipeline (rule-based heuristics + machine-learning anomaly detection), computes risk scores, and presents the results through an interactive dark-themed dashboard designed for analyst workflows.

The system detects **brute-force login attacks**, **port scans**, **abnormal data exfiltration traffic**, and **statistical anomalies** flagged by an Isolation Forest model — all within configurable sliding-window time bounds. Each detected threat is assigned a risk score (0–100) and classified as LOW / MEDIUM / HIGH / CRITICAL, enabling triage prioritisation.

> **Demo Mode** — The application ships with a synthetic data generator so it runs out of the box without any external data source or cloud subscription.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  CYBER THREAT DETECTION PIPELINE                │
└─────────────────────────────────────────────────────────────────┘

  ┌──────────────┐     ┌───────────────────────────────────────┐
  │  Data Layer  │────▶│          Detection Engine             │
  │              │     │                                       │
  │ • Synthetic  │     │  ┌─────────────────────────────────┐  │
  │   Generator  │     │  │  Rule-Based Heuristics          │  │
  │ • CSV Import │     │  │  ┌─────────────┐ ┌───────────┐  │  │
  │ • Streaming  │     │  │  │ Brute Force │ │ Port Scan │  │  │
  │   Events     │     │  │  └─────────────┘ └───────────┘  │  │
  └──────────────┘     │  │  ┌───────────────────────────┐  │  │
                        │  │  │   Abnormal Traffic        │  │  │
                        │  │  └───────────────────────────┘  │  │
                        │  └─────────────────────────────────┘  │
                        │                                       │
                        │  ┌─────────────────────────────────┐  │
                        │  │  ML Anomaly Detection           │  │
                        │  │  (Isolation Forest – sklearn)   │  │
                        │  └─────────────────────────────────┘  │
                        │                                       │
                        │  ┌─────────────────────────────────┐  │
                        │  │  Risk Scoring & Alert Manager   │  │
                        │  │  Score 0-100 → LOW/MED/HIGH/CRIT│  │
                        │  └─────────────────────────────────┘  │
                        └───────────────────────────────────────┘
                                          │
                        ┌─────────────────▼─────────────────────┐
                        │        Streamlit Dashboard            │
                        │                                       │
                        │  ① Overview    ② Live Monitor        │
                        │  ③ Threat Intel ④ ML Insights        │
                        │  ⑤ Alerts & Reports                  │
                        └───────────────────────────────────────┘
```

---

## Features

### 📊 Six Dashboard Pages

| Page | Description |
|------|-------------|
| **① Overview** | KPI cards (total events, active alerts, critical count, detection rate), automated threat intelligence report, severity distribution, active multi-agent status |
| **② Log Monitoring** | Real-time event feed, protocol breakdown, sliding-window velocity indicators |
| **③ Alerts** | Full alert table with filter/sort, MITRE ATT&CK tags, CSV export, lifecycle state updates |
| **④ Analytics** | Isolation Forest anomaly scatter, feature importance, contamination tuning, attack vector correlation |
| **⑤ Investigation** | Offender forensic drilldown, source IP timeline, destination port matrix |
| **⑥ 🤖 Multi-Agent SOC** | Real-time 5-Agent fleet command center, step-by-step annotated trace audit trail, MITRE ATT&CK matrix, autonomous cloud remediation playbooks |

### 🤖 Multi-Agent Autonomous SOC Fleet

- **Agent-Alpha (Ingestion Sentinel)**: Validates canonical schema, sanitizes inputs, extracts 5 velocity features.
- **Agent-Beta (Heuristic Hunter)**: Evaluates brute force, port scans, abnormal egress, and critical port targets.
- **Agent-Gamma (Anomaly Oracle)**: Isolation Forest unsupervised ML outlier inference over high-dimensional feature spaces.
- **Agent-Delta (Correlation & MITRE Correlator)**: Maps threats to MITRE ATT&CK (T1110, T1046, T1048, T1190), fuses evidence, scores risk (0-100).
- **Agent-Epsilon (Autonomous Responder)**: Formulates perimeter containment playbooks with executable AWS WAF, iptables, and IAM commands.
- **Step-by-Step Annotated Trace**: Every decision is auditable with sequential step numbers, timestamps, confidence %, and evidence metrics.


---

## Tech Stack

| Component | Library | Version |
|-----------|---------|---------|
| Dashboard framework | [Streamlit](https://streamlit.io) | ≥ 1.28 |
| Data manipulation | [Pandas](https://pandas.pydata.org) | ≥ 2.0 |
| Numerical computing | [NumPy](https://numpy.org) | ≥ 1.24 |
| Machine learning | [scikit-learn](https://scikit-learn.org) | ≥ 1.3 |
| Interactive charts | [Plotly](https://plotly.com/python/) | ≥ 5.17 |
| Declarative charts | [Altair](https://altair-viz.github.io) | ≥ 5.0 |
| Model persistence | [Joblib](https://joblib.readthedocs.io) | ≥ 1.3 |
| Date utilities | [python-dateutil](https://dateutil.readthedocs.io) | ≥ 2.8 |

---

## Project Structure

```
cloud-cyber-threat-detection-dashboard/
├── .streamlit/
│   └── config.toml          # Dark SOC theme, server settings
├── detection/
│   ├── __init__.py
│   ├── config.py            # All detection thresholds & constants
│   ├── rules.py             # Rule-based heuristic detectors
│   ├── ml_detector.py       # Isolation Forest wrapper
│   ├── risk_scorer.py       # Score computation & severity mapping
│   └── alert_manager.py     # Alert lifecycle & deduplication
├── utils/
│   ├── __init__.py
│   ├── data_generator.py    # Synthetic network event generator
│   └── helpers.py           # Shared formatting/utility functions
├── pages/
│   ├── 1_📊_Overview.py
│   ├── 2_🔴_Live_Monitor.py
│   ├── 3_🌐_Threat_Intel.py
│   ├── 4_🤖_ML_Insights.py
│   └── 5_🚨_Alerts.py
├── models/
│   ├── .gitkeep
│   └── isolation_forest.pkl # Generated on first run
├── data/
│   ├── alerts.csv           # Persisted alert log
│   └── events.csv           # Persisted event log
├── screenshots/
│   └── .gitkeep
├── tests/
│   ├── test_rules.py
│   ├── test_ml_detector.py
│   └── test_risk_scorer.py
├── app.py                   # Streamlit entry point
├── requirements.txt
└── README.md
```

---

## Setup & Installation

### Prerequisites

- Python **3.10 or higher**
- `pip` package manager
- Git

### 1 — Clone the Repository

```bash
git clone https://github.com/<your-username>/cloud-cyber-threat-detection-dashboard.git
cd cloud-cyber-threat-detection-dashboard
```

### 2 — Create a Virtual Environment (Recommended)

```bash
python -m venv .venv
source .venv/bin/activate      # macOS / Linux
# .venv\Scripts\activate       # Windows PowerShell
```

### 3 — Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4 — Run the Dashboard

```bash
streamlit run app.py
```

Open your browser at **http://localhost:8501**.  
The synthetic data generator starts automatically; no external data source is required.

### 5 — (Optional) Train / Retrain the ML Model

```bash
python -m detection.ml_detector --train
```

This generates `models/isolation_forest.pkl` using the synthetic dataset. The dashboard loads this model automatically on the next run.

---

## Data Sources

### Reference Datasets

| Dataset | Description | URL |
|---------|-------------|-----|
| **CICIDS 2017** | Canadian Institute for Cybersecurity Intrusion Detection dataset — 15 attack categories over 5 days of pcap captures | [UNB CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) |
| **NSL-KDD** | Refined version of the KDD Cup 1999 dataset; widely used ML IDS benchmark | [NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html) |

> **Note** — The live dashboard operates on **synthetic data** generated by `utils/data_generator.py`. The generator's statistical distributions are modelled on CICIDS2017 feature ranges. To use real data, replace the generator with your own ETL pipeline and point `EVENT_STORAGE_PATH` in `detection/config.py` to your data file.

---

## Deployment

### Streamlit Community Cloud (Free Tier)

1. **Fork or push** this repository to your GitHub account.
2. Go to [share.streamlit.io](https://share.streamlit.io) and click **New app**.
3. Select your repository, branch (`main`), and entry point (`app.py`).
4. Click **Deploy** — Streamlit Cloud installs `requirements.txt` automatically.
5. Your dashboard will be live at `https://<your-app>.streamlit.app`.

### Docker (Self-Hosted)

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8501
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0"]
```

```bash
docker build -t cyber-threat-dashboard .
docker run -p 8501:8501 cyber-threat-dashboard
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `STREAMLIT_SERVER_PORT` | `8501` | Override the listening port |
| `DASHBOARD_REFRESH_INTERVAL` | `5` | Live monitor refresh rate (seconds) |
| `ANOMALY_CONTAMINATION` | `0.05` | ML contamination rate (overrides config.py) |

---

## Testing

Unit tests are located in the `tests/` directory and use **pytest**.

```bash
pip install pytest
pytest tests/ -v
```

| Test File | Coverage |
|-----------|----------|
| `test_rules.py` | Brute-force, port-scan, and traffic-spike rule logic |
| `test_ml_detector.py` | Model training, prediction, and feature-vector validation |
| `test_risk_scorer.py` | Score calculation, severity mapping, and critical-port boosting |

See [Test Plan](TESTPLAN.md) for detailed test case specifications.

---

## Security Notes

- **No real credentials are stored.** All data is synthetic; the dashboard is a demonstration tool.
- The Streamlit server is configured with `enableCORS = false` — do not expose port 8501 directly to the public internet without a reverse proxy and authentication layer (e.g., Nginx + OAuth2 Proxy).
- For production deployments, enable HTTPS via a TLS-terminating load balancer or Caddy/Nginx.
- Alert and event CSV files (`data/`) may contain sensitive IP addresses in real deployments — apply appropriate filesystem permissions and encryption at rest.

---

## Dataset Attribution

> Sharafaldin, I., Habibi Lashkari, A., & Ghorbani, A. A. (2018).
> **Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization.**
> *Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP)*, 108–116.
> Canadian Institute for Cybersecurity, University of New Brunswick.

> Tavallaee, M., Bagheri, E., Lu, W., & Ghorbani, A. A. (2009).
> **A Detailed Analysis of the KDD CUP 99 Data Set.**
> *Proceedings of the IEEE Symposium on Computational Intelligence in Security and Defense Applications (CISDA)*.

---

## License

This project is licensed under the **MIT License**.

```
MIT License

Copyright (c) 2024 Cp-01

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

---

*Built with ❤️ for the security community.*
