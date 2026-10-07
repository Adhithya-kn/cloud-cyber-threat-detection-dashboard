"""
detection/rules.py
==================
Rule-based detection engine for the Cloud-Based Cyber Threat Detection
Dashboard.

Detectors
---------
detect_brute_force(df)       → list[dict]
detect_port_scan(df)         → list[dict]
detect_abnormal_traffic(df)  → list[dict]
run_all_rules(df)            → list[dict]  (combined, de-duplicated)

Expected DataFrame columns
--------------------------
The functions are tolerant of missing optional columns but *require* at
least the columns called out in each docstring.  A minimal schema:

    timestamp        : datetime64[ns] or parseable string
    source_ip        : str
    destination_ip   : str  (optional – falls back to "unknown")
    destination_port : int  (optional – used by port-scan)
    event_type       : str  (contains "failed_login" / "auth_failure" etc.)
    bytes_sent       : int/float  (optional – used by traffic detector)
"""

from __future__ import annotations

import logging
from typing import Any

import pandas as pd

from detection.config import (
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_SECONDS,
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_WINDOW_SECONDS,
    TRAFFIC_BYTES_THRESHOLD,
    TRAFFIC_WINDOW_SECONDS,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ensure_datetime(df: pd.DataFrame) -> pd.DataFrame:
    """Return a copy of *df* with 'timestamp' coerced to datetime64."""
    df = df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df.dropna(subset=["timestamp"])


def _optional_col(df: pd.DataFrame, col: str, default: Any) -> pd.Series:
    """Return *df[col]* when it exists, else a Series filled with *default*."""
    return df[col] if col in df.columns else pd.Series(default, index=df.index)


def _make_detection(
    *,
    threat_type: str,
    source_ip: str,
    destination_ip: str,
    timestamp: pd.Timestamp,
    reason: str,
    severity_candidate: str,
    confidence: float,
    evidence_count: int,
) -> dict:
    """Construct a standardised detection dictionary."""
    return {
        "threat_type":        threat_type,
        "source_ip":          source_ip,
        "destination_ip":     destination_ip,
        "timestamp":          timestamp,
        "reason":             reason,
        "severity_candidate": severity_candidate,   # pre-scoring hint
        "confidence":         round(float(confidence), 4),
        "evidence_count":     int(evidence_count),
    }


# ---------------------------------------------------------------------------
# Brute-Force Detection
# ---------------------------------------------------------------------------

def detect_brute_force(df: pd.DataFrame) -> list[dict]:
    """
    Detect brute-force login attacks.

    Groups events by *source_ip* and tumbling windows of
    BRUTE_FORCE_WINDOW_SECONDS.  Any window where failed login events exceed
    BRUTE_FORCE_THRESHOLD is flagged.

    Required columns
    ----------------
    timestamp   : datetime-like
    source_ip   : str
    event_type  : str  (rows with value containing 'failed_login' or
                         'auth_failure' are counted)

    Optional columns
    ----------------
    destination_ip : str
    """
    logger.info("Running brute-force detection …")
    detections: list[dict] = []

    required = {"timestamp", "source_ip", "event_type"}
    if not required.issubset(df.columns):
        missing = required - set(df.columns)
        logger.warning("detect_brute_force: missing columns %s – skipping.", missing)
        return detections

    df = _ensure_datetime(df)
    if df.empty:
        return detections

    # Keep failed-login events: check event_type or status column
    failed_type = df["event_type"].str.lower().str.contains(
        r"failed_login|auth_failure|login_fail|failed", regex=True, na=False
    )
    failed_status = pd.Series(False, index=df.index)
    if "status" in df.columns:
        failed_status = df["status"].str.lower().isin(["failed", "failure", "rejected"])
    
    # Also check if SSH / login with failed status
    login_type = df["event_type"].str.upper().isin(["SSH", "RDP", "LOGIN", "AUTH"])
    failed_mask = failed_type | (failed_status & (login_type | True if "event_type" not in df.columns else (login_type | failed_type | failed_status)))
    
    failed_df = df[failed_mask].copy()
    if failed_df.empty:
        logger.info("No failed-login events found.")
        return detections

    # Build time-window buckets (tumbling windows keyed on source_ip)
    window = f"{BRUTE_FORCE_WINDOW_SECONDS}s"
    failed_df = failed_df.sort_values("timestamp").set_index("timestamp")

    dest_col = _optional_col(failed_df.reset_index(), "destination_ip", "unknown")

    for ip, group in failed_df.groupby("source_ip"):
        # Resample into fixed tumbling windows; count events per window
        counts = group.resample(window).size()
        flagged_windows = counts[counts > BRUTE_FORCE_THRESHOLD]

        for window_start, count in flagged_windows.items():
            # Most common destination IP in this window
            window_end = window_start + pd.Timedelta(seconds=BRUTE_FORCE_WINDOW_SECONDS)
            window_rows = group.loc[window_start:window_end]
            dest_ip = (
                window_rows["destination_ip"].mode().iloc[0]
                if "destination_ip" in window_rows.columns and not window_rows["destination_ip"].mode().empty
                else "unknown"
            )

            # Confidence scales with how far over threshold we are, capped at 1.0
            confidence = min(count / (BRUTE_FORCE_THRESHOLD * 3), 1.0)
            severity   = "CRITICAL" if count > BRUTE_FORCE_THRESHOLD * 3 else "HIGH"

            detections.append(
                _make_detection(
                    threat_type="brute_force",
                    source_ip=str(ip),
                    destination_ip=str(dest_ip),
                    timestamp=window_start,
                    reason=(
                        f"{count} failed login attempts from {ip} "
                        f"within a {BRUTE_FORCE_WINDOW_SECONDS // 60}-minute window "
                        f"(threshold: {BRUTE_FORCE_THRESHOLD})."
                    ),
                    severity_candidate=severity,
                    confidence=confidence,
                    evidence_count=int(count),
                )
            )

    logger.info("Brute-force detection complete: %d alert(s).", len(detections))
    return detections


# ---------------------------------------------------------------------------
# Port-Scan Detection
# ---------------------------------------------------------------------------

def detect_port_scan(df: pd.DataFrame) -> list[dict]:
    """
    Detect horizontal / vertical port-scanning behaviour.

    Groups events by *source_ip* and tumbling windows of
    PORT_SCAN_WINDOW_SECONDS.  Any window where the number of *unique*
    destination ports exceeds PORT_SCAN_THRESHOLD is flagged.

    Required columns
    ----------------
    timestamp        : datetime-like
    source_ip        : str
    destination_port : int

    Optional columns
    ----------------
    destination_ip   : str
    """
    logger.info("Running port-scan detection …")
    detections: list[dict] = []

    required = {"timestamp", "source_ip", "destination_port"}
    if not required.issubset(df.columns):
        missing = required - set(df.columns)
        logger.warning("detect_port_scan: missing columns %s – skipping.", missing)
        return detections

    df = _ensure_datetime(df)
    if df.empty:
        return detections

    window  = f"{PORT_SCAN_WINDOW_SECONDS}s"
    scan_df = df[["timestamp", "source_ip", "destination_port"]
                 + (["destination_ip"] if "destination_ip" in df.columns else [])
                ].sort_values("timestamp").copy()

    scan_df = scan_df.set_index("timestamp")

    for ip, group in scan_df.groupby("source_ip"):
        # Count unique ports per tumbling window
        port_counts = group["destination_port"].resample(window).nunique()
        flagged_windows = port_counts[port_counts > PORT_SCAN_THRESHOLD]

        for window_start, unique_ports in flagged_windows.items():
            window_end  = window_start + pd.Timedelta(seconds=PORT_SCAN_WINDOW_SECONDS)
            window_rows = group.loc[window_start:window_end]

            dest_ip = (
                window_rows["destination_ip"].mode().iloc[0]
                if "destination_ip" in window_rows.columns and not window_rows["destination_ip"].mode().empty
                else "unknown"
            )

            confidence = min(unique_ports / (PORT_SCAN_THRESHOLD * 4), 1.0)
            severity   = "CRITICAL" if unique_ports > PORT_SCAN_THRESHOLD * 4 else "HIGH"

            detections.append(
                _make_detection(
                    threat_type="port_scan",
                    source_ip=str(ip),
                    destination_ip=str(dest_ip),
                    timestamp=window_start,
                    reason=(
                        f"{ip} contacted {unique_ports} unique destination ports "
                        f"within {PORT_SCAN_WINDOW_SECONDS}s "
                        f"(threshold: {PORT_SCAN_THRESHOLD})."
                    ),
                    severity_candidate=severity,
                    confidence=confidence,
                    evidence_count=int(unique_ports),
                )
            )

    logger.info("Port-scan detection complete: %d alert(s).", len(detections))
    return detections


# ---------------------------------------------------------------------------
# Abnormal Traffic Detection
# ---------------------------------------------------------------------------

def detect_abnormal_traffic(df: pd.DataFrame) -> list[dict]:
    """
    Detect abnormally high data-transfer volumes from a single source.

    Groups events by *source_ip* and tumbling windows of
    TRAFFIC_WINDOW_SECONDS.  Any window where the total bytes sent exceeds
    TRAFFIC_BYTES_THRESHOLD is flagged.

    Required columns
    ----------------
    timestamp  : datetime-like
    source_ip  : str
    bytes_sent : numeric

    Optional columns
    ----------------
    destination_ip : str
    """
    logger.info("Running abnormal-traffic detection …")
    detections: list[dict] = []

    # Support 'bytes', 'bytes_sent', or 'bytes_transferred'
    byte_col = None
    for cand in ["bytes", "bytes_sent", "bytes_transferred"]:
        if cand in df.columns:
            byte_col = cand
            break

    if byte_col is None or not {"timestamp", "source_ip"}.issubset(df.columns):
        logger.warning("detect_abnormal_traffic: missing required columns (timestamp, source_ip, bytes/bytes_sent) – skipping.")
        return detections

    df = _ensure_datetime(df)
    if df.empty:
        return detections

    # Coerce byte column to numeric
    df = df.copy()
    df["bytes_sent"] = pd.to_numeric(df[byte_col], errors="coerce").fillna(0)

    window     = f"{TRAFFIC_WINDOW_SECONDS}s"
    traffic_df = df[["timestamp", "source_ip", "bytes_sent"]
                    + (["destination_ip"] if "destination_ip" in df.columns else [])
                   ].sort_values("timestamp").copy()
    traffic_df = traffic_df.set_index("timestamp")

    for ip, group in traffic_df.groupby("source_ip"):
        byte_sums = group["bytes_sent"].resample(window).sum()
        flagged   = byte_sums[byte_sums > TRAFFIC_BYTES_THRESHOLD]

        for window_start, total_bytes in flagged.items():
            window_end  = window_start + pd.Timedelta(seconds=TRAFFIC_WINDOW_SECONDS)
            window_rows = group.loc[window_start:window_end]

            dest_ip = (
                window_rows["destination_ip"].mode().iloc[0]
                if "destination_ip" in window_rows.columns and not window_rows["destination_ip"].mode().empty
                else "unknown"
            )
            event_count = int(window_rows.shape[0])

            # Confidence: how many multiples of threshold were exceeded
            ratio      = total_bytes / TRAFFIC_BYTES_THRESHOLD
            confidence = min(ratio / 5.0, 1.0)          # saturates at 5× threshold
            severity   = "CRITICAL" if ratio >= 3.0 else "HIGH"
            mb_sent    = total_bytes / 1_000_000

            detections.append(
                _make_detection(
                    threat_type="abnormal_traffic",
                    source_ip=str(ip),
                    destination_ip=str(dest_ip),
                    timestamp=window_start,
                    reason=(
                        f"{ip} transferred {mb_sent:.2f} MB "
                        f"within {TRAFFIC_WINDOW_SECONDS}s "
                        f"(threshold: {TRAFFIC_BYTES_THRESHOLD / 1_000_000:.0f} MB). "
                        f"{event_count} flow record(s) in window."
                    ),
                    severity_candidate=severity,
                    confidence=confidence,
                    evidence_count=event_count,
                )
            )

    logger.info("Abnormal-traffic detection complete: %d alert(s).", len(detections))
    return detections


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_all_rules(df: pd.DataFrame) -> list[dict]:
    """
    Execute every rule-based detector against *df* and return the combined,
    time-sorted list of detection dictionaries.

    The function is tolerant of a detector raising an exception — it logs the
    error and continues so that remaining detectors still run.

    Parameters
    ----------
    df : pd.DataFrame
        Raw network / authentication log data.  See individual detector
        docstrings for required column details.

    Returns
    -------
    list[dict]
        All detections sorted by timestamp ascending.
    """
    all_detections: list[dict] = []

    detectors = [
        ("brute_force",       detect_brute_force),
        ("port_scan",         detect_port_scan),
        ("abnormal_traffic",  detect_abnormal_traffic),
    ]

    for name, fn in detectors:
        try:
            results = fn(df)
            all_detections.extend(results)
            logger.info("Rule '%s' produced %d detection(s).", name, len(results))
        except Exception as exc:  # noqa: BLE001
            logger.error("Rule '%s' failed with error: %s", name, exc, exc_info=True)

    # Sort chronologically so downstream consumers see events in order
    all_detections.sort(key=lambda d: d.get("timestamp", pd.Timestamp.min))

    logger.info("run_all_rules complete: %d total detection(s).", len(all_detections))
    return all_detections
