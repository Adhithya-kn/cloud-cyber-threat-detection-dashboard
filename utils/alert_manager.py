"""
alert_manager.py
----------------
Alert management module for the Cloud-Based Cyber Threat Detection Dashboard.

Responsibilities:
  - Create structured alert records from enriched detection dictionaries.
  - Deduplicate alerts within a configurable time window.
  - Persist and load alerts from a CSV file.
  - Update alert status throughout the investigation lifecycle.
  - Provide summary statistics and suggested remediation actions.

Alert record schema
-------------------
{
    alert_id        : str   – unique ID, e.g. 'ALT-20241007-001'
    timestamp       : str   – ISO-8601 UTC timestamp
    threat_type     : str   – category of detected threat
    source_ip       : str   – origin IP address
    target_ip       : str   – destination IP address
    source_port     : int | None
    destination_port: int | None
    protocol        : str
    risk_score      : int   – 0-100
    severity        : str   – LOW | MEDIUM | HIGH | CRITICAL
    reason          : str   – human-readable detection rationale
    score_reason    : str   – explanation of the computed risk score
    evidence_count  : int   – number of supporting evidence items
    confidence      : float – detection confidence (0.0 – 1.0)
    status          : str   – NEW | REVIEWING | RESOLVED | FALSE_POSITIVE
    suggested_action: str   – recommended remediation step
}
"""

import os
import logging
from datetime import datetime, timezone
from typing import Optional

import pandas as pd

# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Valid values for the 'status' field
VALID_STATUSES = {"NEW", "REVIEWING", "RESOLVED", "FALSE_POSITIVE"}

# Severity thresholds derived from risk_score
SEVERITY_THRESHOLDS = {
    "CRITICAL": 80,
    "HIGH":     60,
    "MEDIUM":   40,
    # anything below MEDIUM threshold → LOW
}

# Expected DataFrame columns (preserves column order in the CSV)
ALERT_COLUMNS = [
    "alert_id",
    "timestamp",
    "threat_type",
    "source_ip",
    "target_ip",
    "source_port",
    "destination_port",
    "protocol",
    "risk_score",
    "severity",
    "reason",
    "score_reason",
    "evidence_count",
    "confidence",
    "status",
    "suggested_action",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _derive_severity(risk_score: int) -> str:
    """
    Convert a numeric risk_score (0-100) to a severity label.

    Parameters
    ----------
    risk_score : int
        Threat risk score in the range [0, 100].

    Returns
    -------
    str
        One of 'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL'.
    """
    if risk_score >= SEVERITY_THRESHOLDS["CRITICAL"]:
        return "CRITICAL"
    if risk_score >= SEVERITY_THRESHOLDS["HIGH"]:
        return "HIGH"
    if risk_score >= SEVERITY_THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    return "LOW"


def _next_alert_id(date_str: str, existing_alerts_df: pd.DataFrame) -> str:
    """
    Generate the next sequential alert ID for the given date.

    The ID format is ``ALT-YYYYMMDD-NNN`` where NNN is zero-padded to 3
    digits and increments from 001 per day, independent of existing alerts
    from other days.

    Parameters
    ----------
    date_str : str
        Date portion of the ID in 'YYYYMMDD' format.
    existing_alerts_df : pd.DataFrame
        Current alerts DataFrame used to determine the next sequence number.

    Returns
    -------
    str
        Unique alert ID string, e.g. 'ALT-20241007-003'.
    """
    prefix = f"ALT-{date_str}-"
    if existing_alerts_df.empty or "alert_id" not in existing_alerts_df.columns:
        return f"{prefix}001"

    # Filter IDs that belong to the same date
    today_ids = existing_alerts_df["alert_id"].astype(str).str.startswith(prefix)
    todays_alerts = existing_alerts_df[today_ids]

    if todays_alerts.empty:
        return f"{prefix}001"

    # Extract sequence numbers and find the maximum
    try:
        seq_numbers = (
            todays_alerts["alert_id"]
            .str.replace(prefix, "", regex=False)
            .astype(int)
        )
        next_seq = seq_numbers.max() + 1
    except (ValueError, AttributeError):
        next_seq = len(todays_alerts) + 1

    return f"{prefix}{next_seq:03d}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_suggested_action(threat_type: str) -> str:
    """
    Return a human-readable remediation suggestion for the given threat type.

    Parameters
    ----------
    threat_type : str
        Threat category identifier (case-insensitive).

    Returns
    -------
    str
        Recommended action string. Falls back to a generic message for
        unrecognised threat types.

    Examples
    --------
    >>> get_suggested_action("brute_force")
    'Block source IP and enforce MFA. Review account lockout policy.'
    >>> get_suggested_action("UNKNOWN_TYPE")
    'Escalate to security team for manual review.'
    """
    action_map = {
        "brute_force":       "Block source IP and enforce MFA. Review account lockout policy.",
        "port_scan":         "Isolate source IP. Check firewall rules for open ports.",
        "abnormal_traffic":  "Rate-limit source IP. Investigate data exfiltration possibility.",
        "ml_anomaly":        "Investigate manually. Review related log events for context.",
    }
    return action_map.get(
        threat_type.lower().strip(),
        "Escalate to security team for manual review.",
    )


def create_alert(detection_dict: dict) -> dict:
    """
    Create a structured alert record from an enriched detection dictionary.

    The function assigns a unique alert ID and a UTC timestamp. If the
    incoming dict already contains a ``severity`` key it is used directly;
    otherwise severity is derived from ``risk_score``. The ``status`` is
    always initialised to ``'NEW'``.

    Parameters
    ----------
    detection_dict : dict
        Enriched detection result.  Expected keys mirror the alert schema
        (see module docstring), though missing optional fields are filled
        with sensible defaults.

    Returns
    -------
    dict
        Complete alert record ready to be added to the alerts DataFrame.

    Notes
    -----
    The ID is provisionally generated without knowledge of the existing
    alerts DataFrame; the final, collision-free ID is assigned inside
    :func:`add_alert`.
    """
    now_utc = datetime.now(timezone.utc)
    date_str = now_utc.strftime("%Y%m%d")

    risk_score: int = int(detection_dict.get("risk_score", 0))

    # Derive severity from score if not explicitly provided
    severity: str = detection_dict.get("severity") or _derive_severity(risk_score)

    threat_type: str = str(detection_dict.get("threat_type", "unknown"))

    alert = {
        # ID is a placeholder; add_alert() will assign the final unique ID
        "alert_id":          f"ALT-{date_str}-TMP",
        "timestamp":         now_utc.isoformat(),
        "threat_type":       threat_type,
        "source_ip":         str(detection_dict.get("source_ip", "")),
        "target_ip":         str(detection_dict.get("target_ip") or detection_dict.get("destination_ip") or ""),
        "destination_ip":    str(detection_dict.get("destination_ip") or detection_dict.get("target_ip") or ""),
        "source_port":       detection_dict.get("source_port"),          # int or None
        "destination_port":  detection_dict.get("destination_port"),     # int or None
        "protocol":          str(detection_dict.get("protocol", "UNKNOWN")),
        "risk_score":        risk_score,
        "severity":          severity.upper(),
        "reason":            str(detection_dict.get("reason", "")),
        "score_reason":      str(detection_dict.get("score_reason", "")),
        "evidence_count":    int(detection_dict.get("evidence_count", 0)),
        "confidence":        float(detection_dict.get("confidence", 0.0)),
        "status":            "NEW",
        "suggested_action":  get_suggested_action(threat_type),
    }

    logger.debug("Created alert record for threat_type='%s' source_ip='%s'",
                 alert["threat_type"], alert["source_ip"])
    return alert


def is_duplicate(
    alert: dict,
    existing_alerts_df: pd.DataFrame,
    window_seconds: int = 300,
) -> bool:
    """
    Determine whether an alert is a duplicate of a recent one.

    An alert is considered a duplicate if the ``existing_alerts_df``
    already contains a row with the same ``source_ip`` **and**
    ``threat_type`` whose ``timestamp`` falls within the last
    ``window_seconds`` seconds.

    Parameters
    ----------
    alert : dict
        The candidate alert record (as returned by :func:`create_alert`).
    existing_alerts_df : pd.DataFrame
        Current in-memory alerts store.
    window_seconds : int, optional
        Deduplication window in seconds (default: 300 = 5 minutes).

    Returns
    -------
    bool
        ``True`` if a matching alert was found within the window,
        ``False`` otherwise.
    """
    if existing_alerts_df.empty:
        return False

    required_cols = {"source_ip", "threat_type", "timestamp"}
    if not required_cols.issubset(existing_alerts_df.columns):
        return False

    # Parse the candidate timestamp
    try:
        alert_ts = pd.Timestamp(alert["timestamp"]).tz_convert("UTC")
    except Exception:
        alert_ts = pd.Timestamp.utcnow()

    cutoff = alert_ts - pd.Timedelta(seconds=window_seconds)

    # Vectorised comparison for speed on large DataFrames
    df = existing_alerts_df.copy()
    df["_ts"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")

    mask = (
        (df["source_ip"] == alert["source_ip"])
        & (df["threat_type"] == alert["threat_type"])
        & (df["_ts"] >= cutoff)
        & (df["_ts"] <= alert_ts)
    )

    duplicate_found = mask.any()
    if duplicate_found:
        logger.info(
            "Duplicate alert suppressed: source_ip=%s threat_type=%s within %ds window",
            alert["source_ip"], alert["threat_type"], window_seconds,
        )
    return bool(duplicate_found)


def add_alert(alert: dict, alerts_df: pd.DataFrame) -> pd.DataFrame:
    """
    Add an alert to the alerts DataFrame after deduplication.

    Assigns the final unique alert ID before inserting.  If the alert is
    detected as a duplicate (same source_ip + threat_type within 5 minutes)
    the DataFrame is returned unchanged.

    Parameters
    ----------
    alert : dict
        Alert record produced by :func:`create_alert`.
    alerts_df : pd.DataFrame
        Existing alerts store (may be empty).

    Returns
    -------
    pd.DataFrame
        Updated DataFrame with the new alert appended, or the original
        DataFrame if the alert was suppressed as a duplicate.
    """
    if is_duplicate(alert, alerts_df):
        logger.warning(
            "Alert for source_ip=%s / threat_type=%s suppressed (duplicate).",
            alert.get("source_ip"), alert.get("threat_type"),
        )
        return alerts_df

    # Assign final, collision-free ID
    now_utc = datetime.now(timezone.utc)
    date_str = now_utc.strftime("%Y%m%d")
    alert["alert_id"] = _next_alert_id(date_str, alerts_df)

    # Build a single-row DataFrame to concatenate
    new_row = pd.DataFrame([alert], columns=ALERT_COLUMNS)
    updated_df = pd.concat([alerts_df, new_row], ignore_index=True)

    logger.info("Alert added: id=%s severity=%s threat_type=%s",
                alert["alert_id"], alert.get("severity"), alert.get("threat_type"))
    return updated_df


def save_alerts(
    alerts_df: pd.DataFrame,
    filepath: str = "data/alerts.csv",
) -> None:
    """
    Persist the alerts DataFrame to a CSV file.

    Creates parent directories automatically if they do not exist.

    Parameters
    ----------
    alerts_df : pd.DataFrame
        Alerts data to persist.
    filepath : str, optional
        Destination file path (default: 'data/alerts.csv').

    Raises
    ------
    OSError
        If the file cannot be written due to permission or I/O errors.
    """
    os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)
    alerts_df.to_csv(filepath, index=False)
    logger.info("Alerts saved to '%s' (%d records).", filepath, len(alerts_df))


def load_alerts(filepath: str = "data/alerts.csv") -> pd.DataFrame:
    """
    Load alerts from a CSV file into a DataFrame.

    Returns an empty DataFrame (with the correct schema columns) if the
    file does not exist or is empty.

    Parameters
    ----------
    filepath : str, optional
        Source file path (default: 'data/alerts.csv').

    Returns
    -------
    pd.DataFrame
        Alerts data, or an empty DataFrame with schema columns if the file
        is absent.
    """
    if not os.path.exists(filepath):
        logger.info("Alerts file '%s' not found – returning empty DataFrame.", filepath)
        return pd.DataFrame(columns=ALERT_COLUMNS)

    try:
        df = pd.read_csv(filepath)
        # Ensure all expected columns are present (forward-compatible)
        for col in ALERT_COLUMNS:
            if col not in df.columns:
                df[col] = None
        logger.info("Loaded %d alerts from '%s'.", len(df), filepath)
        return df[ALERT_COLUMNS]
    except pd.errors.EmptyDataError:
        logger.warning("Alerts file '%s' is empty – returning empty DataFrame.", filepath)
        return pd.DataFrame(columns=ALERT_COLUMNS)


def update_alert_status(
    alert_id: str,
    new_status: str,
    alerts_df: pd.DataFrame,
) -> pd.DataFrame:
    """
    Update the ``status`` field of a specific alert in the DataFrame.

    Parameters
    ----------
    alert_id : str
        The unique identifier of the alert to update (e.g. 'ALT-20241007-001').
    new_status : str
        New status value.  Must be one of: NEW, REVIEWING, RESOLVED,
        FALSE_POSITIVE.
    alerts_df : pd.DataFrame
        Alerts store to update (mutated in-place on the matching row).

    Returns
    -------
    pd.DataFrame
        Updated DataFrame.  Unchanged if the alert_id was not found.

    Raises
    ------
    ValueError
        If ``new_status`` is not one of the allowed status values.
    """
    new_status = new_status.upper().strip()
    if new_status not in VALID_STATUSES:
        raise ValueError(
            f"Invalid status '{new_status}'. Must be one of {sorted(VALID_STATUSES)}."
        )

    mask = alerts_df["alert_id"] == alert_id
    if not mask.any():
        logger.warning("update_alert_status: alert_id '%s' not found.", alert_id)
        return alerts_df

    alerts_df.loc[mask, "status"] = new_status
    logger.info("Alert '%s' status updated to '%s'.", alert_id, new_status)
    return alerts_df


def get_alerts_summary(alerts_df: pd.DataFrame) -> dict:
    """
    Compute aggregate statistics over the alerts DataFrame.

    Parameters
    ----------
    alerts_df : pd.DataFrame
        Current alerts store.

    Returns
    -------
    dict
        Dictionary with the following keys:

        ``total``         – total number of alerts  
        ``critical_count``– alerts with severity CRITICAL  
        ``high_count``    – alerts with severity HIGH  
        ``medium_count``  – alerts with severity MEDIUM  
        ``low_count``     – alerts with severity LOW  
        ``new_count``     – alerts with status NEW  
        ``resolved_count``– alerts with status RESOLVED  
    """
    if alerts_df.empty:
        return {
            "total":          0,
            "critical_count": 0,
            "high_count":     0,
            "medium_count":   0,
            "low_count":      0,
            "new_count":      0,
            "resolved_count": 0,
        }

    severity_col = alerts_df["severity"].str.upper()
    status_col   = alerts_df["status"].str.upper()

    return {
        "total":          len(alerts_df),
        "critical_count": int((severity_col == "CRITICAL").sum()),
        "high_count":     int((severity_col == "HIGH").sum()),
        "medium_count":   int((severity_col == "MEDIUM").sum()),
        "low_count":      int((severity_col == "LOW").sum()),
        "new_count":      int((status_col == "NEW").sum()),
        "resolved_count": int((status_col == "RESOLVED").sum()),
    }
