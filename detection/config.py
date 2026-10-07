"""
detection/config.py
===================
Centralised thresholds and configuration constants for every detection
module in the pipeline.  Change values here only — rules.py, anomaly.py,
and risk_score.py all import from this module.
"""

# ---------------------------------------------------------------------------
# Brute-Force Detection
# ---------------------------------------------------------------------------
# Flag a source IP when it generates more than BRUTE_FORCE_THRESHOLD
# failed login attempts within any BRUTE_FORCE_WINDOW_SECONDS rolling window.
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_SECONDS = 300          # 5-minute window

# ---------------------------------------------------------------------------
# Port-Scan Detection
# ---------------------------------------------------------------------------
# Flag a source IP that contacts more than PORT_SCAN_THRESHOLD unique
# destination ports within any PORT_SCAN_WINDOW_SECONDS rolling window.
PORT_SCAN_THRESHOLD = 15
PORT_SCAN_WINDOW_SECONDS = 60             # 1-minute window

# ---------------------------------------------------------------------------
# Abnormal Traffic Detection
# ---------------------------------------------------------------------------
# Flag a source IP that sends more than TRAFFIC_BYTES_THRESHOLD bytes
# (10 MB) within any TRAFFIC_WINDOW_SECONDS rolling window.
TRAFFIC_BYTES_THRESHOLD = 10_000_000      # 10 MB
TRAFFIC_WINDOW_SECONDS = 60              # 1-minute window
TRAFFIC_PACKETS_THRESHOLD = 5000         # optional packet-count threshold

# ---------------------------------------------------------------------------
# ML Anomaly Detection (Isolation Forest)
# ---------------------------------------------------------------------------
# Fraction of training samples expected to be anomalous.
ANOMALY_CONTAMINATION = 0.05

# Feature columns that the Isolation Forest model is trained on.
# These columns must exist in the log DataFrame supplied to the ML module.
ML_FEATURES = [
    "failed_login_count",   # number of failed auth attempts per row/window
    "unique_ports_per_ip",  # unique destination ports touched by the source IP
    "request_rate",         # requests-per-second for the source IP
    "bytes_per_source",     # bytes transferred by the source IP
]

# Path (relative to project root) where the trained model is persisted.
MODEL_SAVE_PATH = "models/isolation_forest.pkl"
# Legacy alias kept for backwards compatibility with older dashboard pages
MODEL_PATH = MODEL_SAVE_PATH

# ---------------------------------------------------------------------------
# Risk / Severity Scoring
# ---------------------------------------------------------------------------
# Ports whose involvement adds bonus risk points (SSH, RDP, SMB).
CRITICAL_PORTS = {22, 3389, 445}

# Base risk scores per threat type (0-100 scale).
BASE_SCORES = {
    "brute_force":        65,
    "port_scan":          55,
    "abnormal_traffic":   50,
    "ml_anomaly":         45,
}

# Bonus points applied conditionally.
CONFIDENCE_BONUS    = 15    # added when detection confidence > 0.8
EVIDENCE_BONUS      = 10    # added when evidence_count > 20
CRITICAL_PORT_BONUS = 10    # added when destination port is in CRITICAL_PORTS

# Severity bands (inclusive on both ends): list of (lo, hi, label).
SEVERITY_BANDS = [
    (0,  30,  "LOW"),
    (31, 60,  "MEDIUM"),
    (61, 80,  "HIGH"),
    (81, 100, "CRITICAL"),
]

# Legacy dict alias kept for backwards compatibility with older dashboard pages.
SEVERITY_THRESHOLDS = {
    "LOW":      (0,  30),
    "MEDIUM":   (31, 60),
    "HIGH":     (61, 80),
    "CRITICAL": (81, 100),
}

# ---------------------------------------------------------------------------
# Alert / Storage Settings
# ---------------------------------------------------------------------------
ALERT_DEDUP_WINDOW_SECONDS = 300     # suppress duplicate alerts in this window
ALERT_STORAGE_PATH         = "data/alerts.csv"
EVENT_STORAGE_PATH         = "data/events.csv"
