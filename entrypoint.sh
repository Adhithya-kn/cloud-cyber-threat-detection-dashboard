#!/usr/bin/env bash
# ==============================================================================
# CyberShield Cloud Application Entrypoint Script
# Supports dynamic cloud port assignment ($PORT) for Render, Fly.io, Cloud Run,
# AWS App Runner, Heroku, Docker, and Kubernetes environments.
# ==============================================================================

set -e

# Default port to 8501 if not provided by the cloud container orchestrator
PORT="${PORT:-8501}"
API_PORT="${API_PORT:-8000}"
APP_MODE="${APP_MODE:-dashboard}" # "dashboard", "api", or "dual"

echo "=========================================================="
echo "🛡️  CyberShield Cloud Cyber Threat Detection Platform"
echo "=========================================================="
echo "⚡ Deployment Environment : ${ENV:-production}"
echo "🌐 Bound Port             : ${PORT}"
echo "🚀 Operating Mode         : ${APP_MODE}"
echo "=========================================================="

# Ensure runtime directories exist
mkdir -p data models

# Check if model exists, if not trigger initial training
if [ ! -f "models/isolation_forest.pkl" ]; then
    echo "⚙️  Initializing ML anomaly detection model..."
    python3 -c "
import pandas as pd
from detection.anomaly import train_model
from utils.log_parser import run_pipeline
import os

data_path = 'data/demo_security_logs.csv'
if os.path.exists(data_path):
    df = run_pipeline(data_path)
    train_model(df)
    print('✅ Baseline Isolation Forest model trained successfully.')
" || echo "⚠️ Model initialization skipped; will train on first web request."
fi

if [ "$APP_MODE" = "api" ]; then
    echo "📡 Starting CyberShield Cloud Ingestion API Gateway on 0.0.0.0:${PORT}..."
    exec python3 -m uvicorn api:app --host 0.0.0.0 --port "${PORT}"

elif [ "$APP_MODE" = "dual" ]; then
    echo "📡 Starting Cloud API Gateway in background on 0.0.0.0:${API_PORT}..."
    python3 -m uvicorn api:app --host 0.0.0.0 --port "${API_PORT}" &
    API_PID=$!
    
    echo "🛡️ Starting CyberShield SOC Dashboard on 0.0.0.0:${PORT}..."
    exec streamlit run app.py \
        --server.port="${PORT}" \
        --server.address="0.0.0.0" \
        --server.headless=true \
        --server.enableCORS=false \
        --server.enableXsrfProtection=false \
        --browser.gatherUsageStats=false

else
    # Default: dashboard
    echo "🛡️ Starting CyberShield SOC Dashboard on 0.0.0.0:${PORT}..."
    exec streamlit run app.py \
        --server.port="${PORT}" \
        --server.address="0.0.0.0" \
        --server.headless=true \
        --server.enableCORS=false \
        --server.enableXsrfProtection=false \
        --browser.gatherUsageStats=false
fi
