"""
utils/log_parser.py
-------------------
Log normalization, parsing, validation, and feature extraction module for the
Cloud-Based Cyber Threat Detection Dashboard.

Responsibilities:
  - load_data        : Load CSV or JSON log files into a DataFrame.
  - normalize_events : Map raw columns to a canonical security-event schema.
  - validate_schema  : Enforce required columns, types, and completeness.
  - extract_features : Derive behavioural features used by the threat-detection
                       models (brute-force signals, port-scan signals, etc.).

Dependencies: pandas, numpy
"""

import json
import logging
from pathlib import Path
from typing import Union

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Canonical schema that every downstream component expects
# ---------------------------------------------------------------------------
CANONICAL_COLUMNS = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "user",
    "event_type",
    "status",
    "bytes",
    "packets",
]

# Required columns whose absence is a hard error
REQUIRED_COLUMNS = CANONICAL_COLUMNS  # all fields are required in this pipeline

# Expected dtype categories (used for soft validation / coercion)
DTYPE_EXPECTATIONS = {
    "timestamp":        "datetime64[ns]",
    "source_port":      "int64",
    "destination_port": "int64",
    "bytes":            "int64",
    "packets":          "int64",
    "source_ip":        "object",
    "destination_ip":   "object",
    "protocol":         "object",
    "user":             "object",
    "event_type":       "object",
    "status":           "object",
}

# ---------------------------------------------------------------------------
# Column alias maps for common raw log formats
# ---------------------------------------------------------------------------
COLUMN_ALIASES = {
    # timestamp aliases
    "time":          "timestamp",
    "datetime":      "timestamp",
    "ts":            "timestamp",
    "log_time":      "timestamp",
    # source_ip aliases
    "src_ip":        "source_ip",
    "src":           "source_ip",
    "srcip":         "source_ip",
    "client_ip":     "source_ip",
    # destination_ip aliases
    "dst_ip":        "destination_ip",
    "dst":           "destination_ip",
    "dstip":         "destination_ip",
    "server_ip":     "destination_ip",
    "dest_ip":       "destination_ip",
    # port aliases
    "src_port":      "source_port",
    "sport":         "source_port",
    "dst_port":      "destination_port",
    "dport":         "destination_port",
    "dest_port":     "destination_port",
    # other aliases
    "proto":         "protocol",
    "username":      "user",
    "uid":           "user",
    "type":          "event_type",
    "action":        "event_type",
    "result":        "status",
    "outcome":       "status",
    "byte_count":    "bytes",
    "pkt_count":     "packets",
}

# Business-hours window (08:00-18:00 local time)
BUSINESS_HOUR_START = 8
BUSINESS_HOUR_END   = 18


# ===========================================================================
# Public API
# ===========================================================================

def load_data(filepath: Union[str, Path]) -> pd.DataFrame:
    """
    Load a security log file (CSV or JSON) from *filepath* and return a raw
    DataFrame.

    Parameters
    ----------
    filepath : str | Path
        Absolute or relative path to the log file.  Supported extensions:
        ``.csv`` and ``.json``.

    Returns
    -------
    pd.DataFrame
        Raw DataFrame exactly as stored on disk - no schema mapping applied.

    Raises
    ------
    FileNotFoundError
        If the file does not exist.
    ValueError
        If the file extension is not supported.
    """
    filepath = Path(filepath)

    if not filepath.exists():
        raise FileNotFoundError(f"Log file not found: {filepath}")

    ext = filepath.suffix.lower()
    logger.info("Loading log file: %s  (format: %s)", filepath, ext)

    if ext == ".csv":
        df = pd.read_csv(filepath, low_memory=False)
    elif ext == ".json":
        with open(filepath, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        # Accept both a list of records and a dict-of-lists format
        if isinstance(raw, list):
            df = pd.DataFrame(raw)
        elif isinstance(raw, dict):
            df = pd.DataFrame(raw)
        else:
            raise ValueError("JSON file must contain a list of records or a dict-of-lists.")
    else:
        raise ValueError(f"Unsupported file extension '{ext}'. Use .csv or .json.")

    logger.info("Loaded %d rows, %d columns from %s", len(df), len(df.columns), filepath.name)
    return df


def normalize_events(df: pd.DataFrame) -> pd.DataFrame:
    """
    Map raw column names to the canonical security-event schema and coerce
    data types.

    Mapping strategy
    ----------------
    1. Lower-case all column names.
    2. Apply the COLUMN_ALIASES dictionary to rename known variants.
    3. Cast each canonical column to its expected dtype, filling gaps with
       sensible defaults where safe to do so.

    Parameters
    ----------
    df : pd.DataFrame
        Raw DataFrame returned by :func:`load_data`.

    Returns
    -------
    pd.DataFrame
        DataFrame containing only the canonical columns in a consistent dtype
        layout.  Rows with un-parseable timestamps are dropped.
    """
    df = df.copy()

    # --- Step 1: normalise column names -----------------------------------
    df.columns = [c.strip().lower() for c in df.columns]
    df.rename(columns=COLUMN_ALIASES, inplace=True)

    # --- Step 2: ensure all canonical columns exist (fill if absent) ------
    for col in CANONICAL_COLUMNS:
        if col not in df.columns:
            logger.warning("Column '%s' not found - filling with NaN.", col)
            df[col] = np.nan

    # Keep only canonical columns (discard unknown extras for now)
    df = df[CANONICAL_COLUMNS].copy()

    # --- Step 3: type coercions -------------------------------------------

    # Timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=False)
    pre_drop = len(df)
    df.dropna(subset=["timestamp"], inplace=True)
    if len(df) < pre_drop:
        logger.warning("Dropped %d rows with un-parseable timestamps.", pre_drop - len(df))

    # Numeric columns
    for col in ("source_port", "destination_port", "bytes", "packets"):
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype("int64")

    # String columns - strip whitespace, title-case protocol
    for col in ("source_ip", "destination_ip", "user", "event_type", "status"):
        df[col] = df[col].astype(str).str.strip()

    df["protocol"] = df["protocol"].astype(str).str.upper().str.strip()

    # Sort chronologically
    df.sort_values("timestamp", inplace=True, ignore_index=True)

    logger.info("Normalization complete - %d events retained.", len(df))
    return df


def validate_schema(df: pd.DataFrame) -> bool:
    """
    Validate the canonical DataFrame for required columns, acceptable dtypes,
    and missing-value thresholds.

    Validation rules
    ----------------
    * All REQUIRED_COLUMNS must be present.
    * The ``timestamp`` column must be ``datetime64[ns]``.
    * Numeric columns (``bytes``, ``packets``, ``source_port``,
      ``destination_port``) must be non-negative.
    * No column may exceed 5 % missing values (NaN / empty string).

    Parameters
    ----------
    df : pd.DataFrame
        Normalised DataFrame (output of :func:`normalize_events`).

    Returns
    -------
    bool
        ``True`` if all checks pass; ``False`` otherwise.  Warnings are
        emitted via the module logger for each failed rule.

    Raises
    ------
    ValueError
        If a required column is completely absent from the DataFrame.
    """
    passed = True

    # --- Check 1: required columns present --------------------------------
    missing_cols = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing_cols:
        raise ValueError(f"Required columns missing from DataFrame: {missing_cols}")

    # --- Check 2: timestamp dtype -----------------------------------------
    if not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
        logger.warning("VALIDATION FAIL - 'timestamp' is not datetime64.")
        passed = False

    # --- Check 3: numeric columns are non-negative ------------------------
    for col in ("bytes", "packets", "source_port", "destination_port"):
        if (df[col] < 0).any():
            logger.warning("VALIDATION FAIL - '%s' contains negative values.", col)
            passed = False

    # --- Check 4: missing-value rate per column ---------------------------
    total = len(df)
    if total == 0:
        logger.warning("VALIDATION FAIL - DataFrame is empty.")
        return False

    for col in REQUIRED_COLUMNS:
        if col in ("source_port", "destination_port", "bytes", "packets"):
            # Already coerced numerics; 0 is a valid fill, skip NaN check
            continue
        null_rate = df[col].replace("nan", np.nan).isna().mean()
        if null_rate > 0.05:
            logger.warning(
                "VALIDATION FAIL - '%s' has %.1f%% missing values (threshold 5%%).",
                col,
                null_rate * 100,
            )
            passed = False

    if passed:
        logger.info("Schema validation PASSED for %d events.", total)
    else:
        logger.warning("Schema validation FAILED - review warnings above.")

    return passed


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Derive threat-detection features from the normalised event log and append
    them as new columns.

    Features computed
    -----------------
    failed_login_count : int
        Rolling count of failed login events per ``source_ip`` within every
        5-minute tumbling window.  Brute-force signal (threshold >= 5).

    unique_ports_per_ip : int
        Number of distinct ``destination_port`` values contacted by each
        ``source_ip`` within every 1-minute tumbling window.  Port-scan
        signal (threshold >= 20).

    request_rate : float
        Number of events generated by each ``source_ip`` per minute, computed
        within the same 1-minute tumbling window.

    bytes_per_source : int
        Total ``bytes`` transferred by each ``source_ip`` within a 5-minute
        tumbling window.  Exfiltration / abnormal-traffic signal.

    is_after_hours : bool
        ``True`` when the event ``timestamp`` falls outside 08:00-18:00
        (business hours).

    Parameters
    ----------
    df : pd.DataFrame
        Normalised DataFrame (output of :func:`normalize_events`).

    Returns
    -------
    pd.DataFrame
        Original DataFrame with five new feature columns appended.

    Notes
    -----
    * The function does **not** mutate the input DataFrame.
    * Windows are tumbling (non-overlapping) using ``pd.Grouper``.
    * All aggregations are computed on a single DatetimeIndex-backed helper
      (ts_df) BEFORE any merge operations, so the DatetimeIndex is never
      silently reset to a RangeIndex mid-function.
    * All new columns default to 0 / False for rows that fall in windows with
      insufficient data.
    """
    df = df.copy()

    # Build a DatetimeIndex helper view used for ALL window groupbys.
    # We never merge into ts_df, so its DatetimeIndex stays intact throughout.
    ts_df = df.set_index("timestamp")
    ts_df.index = pd.DatetimeIndex(ts_df.index)

    # Pre-compute tumbling-window floor keys on the main df before any merges.
    df["_w5"] = pd.DatetimeIndex(df["timestamp"]).floor("5min")
    df["_w1"] = pd.DatetimeIndex(df["timestamp"]).floor("1min")

    # -----------------------------------------------------------------------
    # 1. failed_login_count -- per source_ip, per 5-min window
    # -----------------------------------------------------------------------
    failed_mask   = ts_df["status"].str.lower().isin(["failed", "failure", "denied", "rejected"])
    failed_events = ts_df[failed_mask]

    if not failed_events.empty:
        failed_counts = (
            failed_events.groupby([pd.Grouper(freq="5min"), "source_ip"])
            .size()
            .rename("failed_login_count")
            .reset_index()
            .rename(columns={"timestamp": "_w5"})
        )
        df = df.merge(failed_counts, on=["_w5", "source_ip"], how="left")
    else:
        df["failed_login_count"] = 0

    df["failed_login_count"] = df["failed_login_count"].fillna(0).astype("int64")

    # -----------------------------------------------------------------------
    # 2. unique_ports_per_ip -- per source_ip, per 1-min window
    # -----------------------------------------------------------------------
    unique_ports = (
        ts_df.groupby([pd.Grouper(freq="1min"), "source_ip"])["destination_port"]
        .nunique()
        .rename("unique_ports_per_ip")
        .reset_index()
        .rename(columns={"timestamp": "_w1"})
    )
    df = df.merge(unique_ports, on=["_w1", "source_ip"], how="left")
    df["unique_ports_per_ip"] = df["unique_ports_per_ip"].fillna(0).astype("int64")

    # -----------------------------------------------------------------------
    # 3. request_rate -- events per source_ip per minute (1-min window)
    # -----------------------------------------------------------------------
    req_rate = (
        ts_df.groupby([pd.Grouper(freq="1min"), "source_ip"])
        .size()
        .rename("request_rate")
        .reset_index()
        .rename(columns={"timestamp": "_w1"})
    )
    df = df.merge(req_rate, on=["_w1", "source_ip"], how="left")
    df["request_rate"] = df["request_rate"].fillna(0).astype("float64")

    # -----------------------------------------------------------------------
    # 4. bytes_per_source -- per source_ip, per 5-min window
    # -----------------------------------------------------------------------
    bytes_sum = (
        ts_df.groupby([pd.Grouper(freq="5min"), "source_ip"])["bytes"]
        .sum()
        .rename("bytes_per_source")
        .reset_index()
        .rename(columns={"timestamp": "_w5"})
    )
    df = df.merge(bytes_sum, on=["_w5", "source_ip"], how="left")
    df["bytes_per_source"] = df["bytes_per_source"].fillna(0).astype("int64")

    # -----------------------------------------------------------------------
    # 5. is_after_hours -- outside 08:00-18:00 local time
    # -----------------------------------------------------------------------
    hour = pd.DatetimeIndex(df["timestamp"]).hour
    df["is_after_hours"] = ~((hour >= BUSINESS_HOUR_START) & (hour < BUSINESS_HOUR_END))

    # Drop internal window-key helper columns
    df.drop(columns=["_w5", "_w1"], inplace=True)

    logger.info(
        "Feature extraction complete -- columns added: "
        "failed_login_count, unique_ports_per_ip, request_rate, "
        "bytes_per_source, is_after_hours."
    )
    return df


# ===========================================================================
# Convenience pipeline
# ===========================================================================

def run_pipeline(filepath: Union[str, Path]) -> pd.DataFrame:
    """
    Full end-to-end pipeline: load -> normalize -> validate -> extract features.

    Parameters
    ----------
    filepath : str | Path
        Path to the raw security log file (.csv or .json).

    Returns
    -------
    pd.DataFrame
        Clean, feature-enriched DataFrame ready for dashboard consumption.
    """
    raw_df      = load_data(filepath)
    norm_df     = normalize_events(raw_df)
    validate_schema(norm_df)          # logs warnings; does not raise on soft fails
    enriched_df = extract_features(norm_df)
    return enriched_df
