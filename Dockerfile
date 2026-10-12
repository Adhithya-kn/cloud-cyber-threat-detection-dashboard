# ==============================================================================
# CyberShield Cloud Cyber Threat Detection & Autonomous SOC Platform
# Multi-Stage Production Dockerfile for Cloud Application Deployment
# ==============================================================================

# ── Stage 1: Build & Dependency Resolution ──────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: Final Minimal Runtime Image ────────────────────────────────────
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PORT=8501 \
    API_PORT=8000 \
    APP_MODE=dashboard

WORKDIR /app

# Install runtime dependencies (curl for container healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder stage
COPY --from=builder /install /usr/local

# Create non-root system user for security compliance (Principle of Least Privilege)
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/bash -m appuser

# Copy application source code
COPY . /app

# Ensure proper ownership and permissions for runtime data directories
RUN mkdir -p /app/data /app/models && \
    chown -R appuser:appgroup /app && \
    chmod +x /app/entrypoint.sh

# Switch to non-root user
USER appuser

# Expose Streamlit dashboard and API ports
EXPOSE 8501 8000

# Cloud container healthcheck probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:${PORT}/_stcore/health || curl -f http://localhost:8000/healthz || exit 1

ENTRYPOINT ["./entrypoint.sh"]
