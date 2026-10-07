"""
detection/anomaly.py
====================
Isolation Forest–based ML anomaly detection for the Cloud-Based Cyber
Threat Detection Dashboard.

Public API
----------
train_model(df, features, contamination)  → IsolationForest
load_model()                              → IsolationForest | None
detect_anomalies(df, model)               → pd.DataFrame
get_anomaly_detections(df)               → list[dict]
evaluate_model(df, model, label_col)      → dict
"""

from __future__ import annotations

import logging
import os
import pickle
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, f1_score
from sklearn.preprocessing import StandardScaler

from detection.config import (
    ANOMALY_CONTAMINATION,
    ML_FEATURES,
    MODEL_SAVE_PATH,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _resolve_model_path() -> str:
    """Return an absolute path for the model pickle file."""
    # If MODEL_SAVE_PATH is relative, anchor it to the project root which is
    # two directories above this file (project_root/detection/anomaly.py).
    if os.path.isabs(MODEL_SAVE_PATH):
        return MODEL_SAVE_PATH
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(project_root, MODEL_SAVE_PATH)


def _prepare_features(
    df: pd.DataFrame,
    features: list[str],
) -> Optional[tuple[pd.DataFrame, np.ndarray]]:
    """
    Validate and extract the feature matrix from *df*.

    Returns (sub_df, X_array) or None if the necessary columns are missing.
    Any rows with NaN in feature columns are dropped with a warning.
    """
    missing = [f for f in features if f not in df.columns]
    if missing:
        logger.warning("Missing feature columns: %s.  Cannot proceed.", missing)
        return None

    sub = df[features].copy()
    n_before = len(sub)
    sub = sub.dropna()
    if len(sub) < n_before:
        logger.warning(
            "Dropped %d row(s) with NaN values in feature columns.",
            n_before - len(sub),
        )
    if sub.empty:
        logger.error("Feature matrix is empty after dropping NaNs.")
        return None

    # Coerce all features to float
    for col in features:
        sub[col] = pd.to_numeric(sub[col], errors="coerce")
    sub = sub.dropna()

    return sub, sub.values.astype(float)


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train_model(
    df: pd.DataFrame,
    features: list[str] | None = None,
    contamination: float | str = ANOMALY_CONTAMINATION,
) -> Optional[IsolationForest]:
    """
    Train an Isolation Forest on the given DataFrame and persist it to disk.

    Parameters
    ----------
    df            : pd.DataFrame  – training data (ideally clean / normal traffic)
    features      : list[str]     – feature column names (defaults to ML_FEATURES)
    contamination : float | 'auto' – expected fraction of anomalies in data

    Returns
    -------
    Trained IsolationForest instance, or None on failure.
    """
    features = features or ML_FEATURES
    logger.info("Training Isolation Forest on %d row(s), features=%s …", len(df), features)

    result = _prepare_features(df, features)
    if result is None:
        return None

    _, X = result

    # Standardise before fitting (improves convergence for some feature scales)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_scaled)

    # Bundle the scaler inside a wrapper dict so we can preprocess at inference
    bundle = {"model": model, "scaler": scaler, "features": features}

    # Persist to disk
    save_path = _resolve_model_path()
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    try:
        with open(save_path, "wb") as fh:
            pickle.dump(bundle, fh)
        logger.info("Model bundle saved to %s.", save_path)
    except OSError as exc:
        logger.error("Could not save model: %s", exc)

    # Return bundle dictionary containing model, scaler, and features
    return bundle


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_model() -> Optional[dict]:
    """
    Load a previously trained model bundle from disk.

    Returns
    -------
    dict with keys 'model', 'scaler', 'features', or None if not found.
    """
    save_path = _resolve_model_path()
    if not os.path.exists(save_path):
        logger.warning("Model file not found at %s.  Run train_model() first.", save_path)
        return None

    try:
        with open(save_path, "rb") as fh:
            bundle = pickle.load(fh)
        logger.info("Model bundle loaded from %s.", save_path)
        return bundle
    except (OSError, pickle.UnpicklingError) as exc:
        logger.error("Failed to load model: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Inference
# ---------------------------------------------------------------------------

def detect_anomalies(
    df: pd.DataFrame,
    model: Optional[dict | IsolationForest] = None,
) -> pd.DataFrame:
    """
    Run anomaly detection on *df* and append result columns.

    Appends two columns to a *copy* of *df*:
      • anomaly_flag  (bool)   – True when the row is predicted anomalous
      • anomaly_score (float)  – decision function score; more negative → more anomalous

    If *model* is None the function attempts to load a saved bundle
    automatically.  If no bundle exists, both columns are set to None and a
    warning is logged.

    Parameters
    ----------
    df    : pd.DataFrame         – log data with feature columns
    model : dict | IsolationForest | None

    Returns
    -------
    pd.DataFrame  (copy of *df* with new columns added)
    """
    result_df = df.copy()
    result_df["anomaly_flag"]  = None
    result_df["anomaly_score"] = None

    # Resolve bundle vs raw model
    bundle: Optional[dict] = None
    if model is None:
        bundle = load_model()
    elif isinstance(model, dict):
        bundle = model
    elif isinstance(model, IsolationForest):
        # Bare model without scaler – treat features from config
        bundle = {"model": model, "scaler": None, "features": ML_FEATURES}

    if bundle is None:
        logger.warning(
            "No model available.  Train a model with train_model() first. "
            "Returning DataFrame with null anomaly columns."
        )
        return result_df

    iso: IsolationForest = bundle["model"]
    scaler: Optional[StandardScaler] = bundle.get("scaler")
    features: list[str] = bundle.get("features", ML_FEATURES)

    prepared = _prepare_features(result_df, features)
    if prepared is None:
        return result_df

    sub_df, X = prepared

    if scaler is not None:
        X = scaler.transform(X)

    # IsolationForest.predict: -1 → anomaly, 1 → normal
    predictions = iso.predict(X)
    scores      = iso.decision_function(X)   # negative = more anomalous

    # Map back to original index positions
    result_df.loc[sub_df.index, "anomaly_flag"]  = predictions == -1
    result_df.loc[sub_df.index, "anomaly_score"] = scores

    n_anomalies = int((predictions == -1).sum())
    logger.info(
        "detect_anomalies: %d anomal%s detected out of %d scored row(s).",
        n_anomalies,
        "y" if n_anomalies == 1 else "ies",
        len(sub_df),
    )
    return result_df


# ---------------------------------------------------------------------------
# Convert anomalous rows → detection dicts
# ---------------------------------------------------------------------------

def get_anomaly_detections(df: pd.DataFrame) -> list[dict]:
    """
    Convert anomalous rows in *df* into standardised detection dictionaries.

    Expects *df* to have been processed by :func:`detect_anomalies` so that
    'anomaly_flag' and 'anomaly_score' columns are present.

    Parameters
    ----------
    df : pd.DataFrame

    Returns
    -------
    list[dict]  – one detection dict per anomalous row, sorted by
                  anomaly_score ascending (most anomalous first).
    """
    if "anomaly_flag" not in df.columns:
        logger.warning("'anomaly_flag' column not found.  Run detect_anomalies() first.")
        return []

    # Filter to confirmed anomalies with a valid flag
    anomalies = df[df["anomaly_flag"] == True].copy()  # noqa: E712
    if anomalies.empty:
        logger.info("No ML anomalies detected.")
        return []

    # Sort most-anomalous first (lowest score = most deviant)
    if "anomaly_score" in anomalies.columns:
        anomalies = anomalies.sort_values("anomaly_score", ascending=True)

    detections: list[dict] = []
    for _, row in anomalies.iterrows():
        score = row.get("anomaly_score", 0.0)
        # Normalise score to [0, 1] confidence:
        # decision_function range is typically [-0.5, 0.5] for IF.
        # We clamp and invert so that more-anomalous → higher confidence.
        raw_conf   = float(score) if score is not None else 0.0
        confidence = float(np.clip((-raw_conf + 0.5) / 1.0, 0.0, 1.0))

        # Extract common fields gracefully
        source_ip   = str(row.get("source_ip",      "unknown"))
        dest_ip     = str(row.get("destination_ip", "unknown"))
        timestamp   = row.get("timestamp", pd.Timestamp.now())

        # Build a human-readable reason from available feature values
        feature_vals = {
            f: row[f] for f in ML_FEATURES if f in row.index and pd.notna(row[f])
        }
        feature_str = ", ".join(f"{k}={v:.2f}" for k, v in feature_vals.items())
        reason = (
            f"ML Isolation Forest flagged row as anomalous "
            f"(score={raw_conf:.4f}). "
            + (f"Features: [{feature_str}]." if feature_str else "")
        )

        detections.append(
            {
                "threat_type":        "ml_anomaly",
                "source_ip":          source_ip,
                "destination_ip":     dest_ip,
                "timestamp":          timestamp,
                "reason":             reason,
                "severity_candidate": "HIGH",
                "confidence":         round(confidence, 4),
                "evidence_count":     1,   # single row flagged
                "anomaly_score":      round(raw_conf, 6),
            }
        )

    logger.info("get_anomaly_detections: %d ML detection(s) prepared.", len(detections))
    return detections


# ---------------------------------------------------------------------------
# Model Evaluation (when ground-truth labels are available)
# ---------------------------------------------------------------------------

def evaluate_model(
    df: pd.DataFrame,
    model: Optional[dict | IsolationForest] = None,
    label_col: str = "is_anomaly",
) -> dict:
    """
    Evaluate the Isolation Forest against known ground-truth labels.

    Parameters
    ----------
    df        : pd.DataFrame  – data that includes *label_col* (1=anomaly, 0=normal)
    model     : dict | IsolationForest | None
    label_col : str           – column name containing binary ground truth

    Returns
    -------
    dict with keys: precision, recall, f1, n_samples, n_positives
         Returns an empty dict if labels are missing or model unavailable.
    """
    if label_col not in df.columns:
        logger.warning("Label column '%s' not found – evaluation skipped.", label_col)
        return {}

    scored_df = detect_anomalies(df, model=model)
    if scored_df["anomaly_flag"].isna().all():
        logger.warning("No predictions generated – evaluation skipped.")
        return {}

    # Drop rows where either flag or label is missing
    eval_df = scored_df[[label_col, "anomaly_flag"]].dropna()

    y_true = eval_df[label_col].astype(int).values
    y_pred = eval_df["anomaly_flag"].astype(int).values

    metrics = {
        "precision":   float(precision_score(y_true, y_pred, zero_division=0)),
        "recall":      float(recall_score(y_true, y_pred, zero_division=0)),
        "f1":          float(f1_score(y_true, y_pred, zero_division=0)),
        "n_samples":   int(len(y_true)),
        "n_positives": int(y_true.sum()),
    }
    logger.info(
        "Model evaluation – precision=%.3f  recall=%.3f  f1=%.3f  "
        "(samples=%d, positives=%d).",
        metrics["precision"], metrics["recall"], metrics["f1"],
        metrics["n_samples"], metrics["n_positives"],
    )
    return metrics
