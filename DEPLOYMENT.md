# ☁️ CyberShield: Cloud Deployment & Multi-Agent Architecture Guide

> **Course**: Cloud Application Development (Microproject)  
> **Repository**: `cloud-cyber-threat-detection-dashboard`  
> **Platform Version**: v2.0 (Multi-Agent Cloud Native Architecture)

---

## 1. Cloud Architecture Overview

CyberShield has been transformed from a single-machine localhost application into a **cloud-native, microservices-ready distributed security operations platform**:

```
                       ┌─────────────────────────────────────────┐
                       │       Cloud Telemetry Sources           │
                       │  (AWS CloudTrail, VPC Flow, K8s, Logs)  │
                       └───────────────────┬─────────────────────┘
                                           │  HTTP POST (JSON)
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    Cloud Ingestion Microservice (Port 8000/Dynamic)             │
│                                                                                 │
│   • /healthz            - Kubernetes & Cloud Provider Health Probe              │
│   • /api/v1/status      - Agent Fleet Health & Latency Metrics                  │
│   • /api/v1/telemetry   - Live Cloud Telemetry Stream Ingestion                 │
│   • /api/v1/mitigate    - Automated Perimeter Firewall & IAM Containment        │
└──────────────────────────────────────────┬──────────────────────────────────────┘
                                           │
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    Multi-Agent SOC Orchestration Layer                          │
│                                                                                 │
│   ┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────┐   │
│   │ Agent-Alpha         │   │ Agent-Beta          │   │ Agent-Gamma         │   │
│   │ Ingestion Sentinel  ├──▶│ Heuristic Hunter    │   │ Anomaly Oracle (ML) │   │
│   │ (Schema & Features) │   │ (Rule Violations)   │   │ (Isolation Forest)  │   │
│   └─────────────────────┘   └──────────┬──────────┘   └──────────┬──────────┘   │
│                                        │                         │              │
│                                        └───────────┬─────────────┘              │
│                                                    ▼                            │
│                                     ┌─────────────────────────────┐             │
│                                     │ Agent-Delta                 │             │
│                                     │ MITRE ATT&CK Correlator     │             │
│                                     │ (Risk Scoring 0-100)        │             │
│                                     └──────────────┬──────────────┘             │
│                                                    ▼                            │
│                                     ┌─────────────────────────────┐             │
│                                     │ Agent-Epsilon               │             │
│                                     │ Autonomous Responder        │             │
│                                     │ (Cloud Playbooks & Drops)   │             │
│                                     └─────────────────────────────┘             │
└──────────────────────────────────────────┬──────────────────────────────────────┘
                                           │
                                           ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                     CyberShield SOC Dashboard (Port 8501/Dynamic)               │
│                                                                                 │
│   ① Overview & Threat KPIs            ④ ML Analytics & Contamination Tuning     │
│   ② Live Log Stream Monitoring        ⑤ Deep-Dive Incident Forensics            │
│   ③ Security Alerts & Triage          ⑥ 🤖 Multi-Agent Command & Trace Center   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Multi-Agent Division of Rules & Annotations

The threat detection pipeline is split across **5 autonomous agents**, with every step verified and annotated in real-time:

| Agent | Codename | Role & Assigned Rules | Output Annotation |
| :--- | :--- | :--- | :--- |
| **Agent-Alpha** | `IngestionSentinel` | Enforces 11-column canonical schema; sanitizes nulls; derives rolling-window velocity features. | `[SUCCESS]` Sanitized records, verified protocol spread. |
| **Agent-Beta** | `HeuristicHunter` | Evaluates sliding-window deterministic rules: (1) Brute-Force (`>5` fails in 5m), (2) Port-Scan (`>15` ports in 60s), (3) Abnormal Egress (`>10MB` in 60s), (4) Critical Port targeting (22, 3389, 445). | `[THREATS_DETECTED]` or `[CLEAN]` with violated threshold ratio and offending IP. |
| **Agent-Gamma** | `AnomalyOracle` | Runs unsupervised **Isolation Forest** inference over 4D feature vectors; isolates zero-day and stealthy anomalies. | `[THREATS_DETECTED]` with multidimensional outlier confidence. |
| **Agent-Delta** | `CorrelationRisk` | Aggregates multi-source detections, aligns with **MITRE ATT&CK** (T1110, T1046, T1048, T1190), scores risk (0-100), and assigns severity (LOW/MED/HIGH/CRITICAL). | `[TRIAGE_COMPLETE]` with multi-agent consensus IP and tactics identified. |
| **Agent-Epsilon**| `AutonomousResponder` | Formulates cloud-native containment playbooks (AWS WAF IP set blacklist, iptables drops, IAM credential isolation). | `[MITIGATIONS_DISPATCHED]` with executable CLI commands. |

---

## 3. Deployment Methods

### Option 1: Docker & Docker Compose (Recommended for Local Cloud Emulation)

Run the full multi-service stack (SOC Dashboard + Ingestion API) with one command:

```bash
docker compose up --build
```

- **SOC Dashboard**: [http://localhost:8501](http://localhost:8501)
- **Ingestion API**: [http://localhost:8000](http://localhost:8000)
- **Health Check**: `curl http://localhost:8000/healthz`

---

### Option 2: Render (Free Cloud PaaS Deployment)

1. Push your repository to GitHub.
2. Log into [Render](https://render.com) and click **New +** -> **Blueprint**.
3. Connect your repository. Render will detect `render.yaml` and configure:
   - Web Service 1: `cybershield-soc-dashboard` (Streamlit frontend)
   - Web Service 2: `cybershield-ingestion-api` (FastAPI/Starlette ingestion gateway)
4. Click **Apply**. Both services will be deployed with public HTTPS URLs!

---

### Option 3: Streamlit Community Cloud (1-Click Deployment)

1. Push this repository to GitHub.
2. Go to [share.streamlit.io](https://share.streamlit.io).
3. Click **New app** and select:
   - **Repository**: `<your-username>/cloud-cyber-threat-detection-dashboard`
   - **Branch**: `main`
   - **Main file path**: `app.py`
4. Click **Deploy**. The dashboard will be live at `https://<your-app>.streamlit.app`.

---

### Option 4: Fly.io (MicroVM Cloud Deployment)

Deploy using the included `fly.toml`:

```bash
# 1. Install Fly CLI & authenticate
fly auth login

# 2. Launch and deploy
fly launch --now
```

Fly.io will build the Docker container and expose it at `https://cybershield-soc-dashboard.fly.dev`.

---

### Option 5: Kubernetes (K8s Production Orchestration)

Deploy the multi-replica container with Horizontal Pod Autoscaler:

```bash
# 1. Apply namespace and configuration
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml

# 2. Deploy workloads and service
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml

# 3. Enable Horizontal Pod Autoscaling (elastic scaling under attack traffic)
kubectl apply -f k8s/hpa.yaml

# 4. Check deployment status
kubectl get pods -n cybershield-soc
kubectl get hpa -n cybershield-soc
```

---

## 4. Cloud Ingestion API Reference

### Health Probe
```bash
curl -X GET http://localhost:8000/healthz
```
**Response:**
```json
{
  "status": "healthy",
  "service": "cybershield-cloud-soc-api",
  "environment": "production",
  "bound_port": 8000
}
```

### Agent Fleet Status
```bash
curl -X GET http://localhost:8000/api/v1/status
```

### Stream Live Cloud Telemetry
```bash
curl -X POST http://localhost:8000/api/v1/telemetry \
  -H "Content-Type: application/json" \
  -d '[
    {
      "timestamp": "2024-10-12T12:00:00Z",
      "source_ip": "198.51.100.99",
      "destination_ip": "10.0.0.5",
      "source_port": 44222,
      "destination_port": 22,
      "protocol": "SSH",
      "user": "root",
      "event_type": "failed_login",
      "status": "FAILURE",
      "bytes": 512,
      "packets": 4
    }
  ]'
```

### Trigger Containment Playbook
```bash
curl -X POST http://localhost:8000/api/v1/mitigate \
  -H "Content-Type: application/json" \
  -d '{"ip": "198.51.100.99", "action": "FIREWALL_DROP"}'
```

---

## 5. Verification & Testing

Run the full automated test suite covering Multi-Agent logic, API endpoints, detection heuristics, and cloud environments:

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```
