"""
detection/risk_score.py
=======================
Risk and severity scoring engine for the Cloud-Based Cyber Threat Detection
Dashboard.

Every raw detection dictionary produced by rules.py or anomaly.py is passed
through this module before being stored or displayed.  The module:

  1. Calculates a numeric risk score (0–100).
  2. Maps the score to a qualitative severity label.
  3. Enriches the detection dict with these values plus a human-readable
     explanation of how the score was derived.

Public API
----------
calculate_risk_score(detection_dict)   → int          (0-100)
assign_severity(score)                 → str          ('LOW'|'MEDIUM'|'HIGH'|'CRITICAL')
enrich_detection(detection_dict)       → dict         (mutated copy)
process_all_detections(detections)     → list[dict]   (sorted high-risk first)
"""

from __future__ import annotations

import logging
from typing import Any

from detection.config import (
    BASE_SCORES,
    CONFIDENCE_BONUS,
    CRITICAL_PORT_BONUS,
    CRITICAL_PORTS,
    EVIDENCE_BONUS,
    SEVERITY_BANDS,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Risk Score Calculation
# ---------------------------------------------------------------------------

def calculate_risk_score(detection: dict[str, Any]) -> tuple[int, list[str]]:
    """
    Calculate a risk score (0–100) for a single detection dictionary.

    Scoring rules
    -------------
    1. Base score from threat_type  (brute_force=65, port_scan=55,
                                     abnormal_traffic=50, ml_anomaly=45)
    2. +CONFIDENCE_BONUS (15)  if confidence > 0.8
    3. +EVIDENCE_BONUS   (10)  if evidence_count > 20
    4. +CRITICAL_PORT_BONUS (10) if destination_port is in {22, 3389, 445}
    5. Clamp result to [0, 100]

    Parameters
    ----------
    detection : dict
        A detection dict produced by rules.py or anomaly.py.

    Returns
    -------
    (score, reasons)
        score   : int           – clamped 0-100 risk score
        reasons : list[str]     – human-readable explanation of each component
    """
    reasons: list[str] = []
    score = 0

    # --- 1. Base score by threat type ---
    threat_type = str(detection.get("threat_type", "")).lower()
    base = BASE_SCORES.get(threat_type, 0)
    score += base
    if base > 0:
        reasons.append(
            f"Base score for '{threat_type}': +{base}"
        )
    else:
        reasons.append(f"Unknown threat_type '{threat_type}': +0 (no base score)")

    # --- 2. High-confidence bonus ---
    confidence = float(detection.get("confidence", 0.0))
    if confidence > 0.8:
        score += CONFIDENCE_BONUS
        reasons.append(
            f"High confidence ({confidence:.0%} > 80 %): +{CONFIDENCE_BONUS}"
        )

    # --- 3. Large evidence-count bonus ---
    evidence_count = int(detection.get("evidence_count", 0))
    if evidence_count > 20:
        score += EVIDENCE_BONUS
        reasons.append(
            f"High evidence count ({evidence_count} > 20): +{EVIDENCE_BONUS}"
        )

    # --- 4. Critical destination port ---
    # The detection dict may carry destination_port as a top-level key, or
    # it might be encoded in the 'reason' string.  We check both.
    dest_port = _extract_destination_port(detection)
    if dest_port in CRITICAL_PORTS:
        score += CRITICAL_PORT_BONUS
        reasons.append(
            f"Destination port {dest_port} is critical (SSH/RDP/SMB): +{CRITICAL_PORT_BONUS}"
        )

    # --- 5. Clamp ---
    score = max(0, min(100, score))
    reasons.append(f"Final (clamped) score: {score}")

    return score, reasons


def _extract_destination_port(detection: dict[str, Any]) -> int:
    """
    Best-effort extraction of a destination port from a detection dict.

    Checks:
      • 'destination_port' key (int or str)
      • 'destination_ip' key for patterns like "10.0.0.1:22"
    """
    port = detection.get("destination_port")
    if port is not None:
        try:
            return int(port)
        except (ValueError, TypeError):
            pass

    # Try to parse "host:port" from destination_ip
    dest_ip = str(detection.get("destination_ip", ""))
    if ":" in dest_ip:
        try:
            return int(dest_ip.split(":")[-1])
        except (ValueError, TypeError):
            pass

    return -1   # sentinel – not in CRITICAL_PORTS


# ---------------------------------------------------------------------------
# Severity Assignment
# ---------------------------------------------------------------------------

def assign_severity(score: int) -> str:
    """
    Map a numeric risk score to a severity label.

    Bands (inclusive)
    -----------------
    0  – 30  → LOW
    31 – 60  → MEDIUM
    61 – 80  → HIGH
    81 – 100 → CRITICAL

    Parameters
    ----------
    score : int  – a value in [0, 100]

    Returns
    -------
    str  – one of 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    """
    clamped = max(0, min(100, int(score)))
    for lo, hi, label in SEVERITY_BANDS:
        if lo <= clamped <= hi:
            return label
    # Fallback (should never reach here given the clamp above)
    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------

def enrich_detection(detection: dict[str, Any]) -> dict[str, Any]:
    """
    Add 'risk_score', 'severity', and 'score_reason' to a detection dict.

    Returns a *new* dict; the original is not mutated.

    Parameters
    ----------
    detection : dict  – raw detection from rules.py or anomaly.py

    Returns
    -------
    dict  – enriched copy with three new keys:
              risk_score   (int)
              severity     (str)
              score_reason (str)  – newline-separated scoring rationale
    """
    enriched = dict(detection)   # shallow copy; detection values are scalars

    score, reasons = calculate_risk_score(enriched)
    severity       = assign_severity(score)

    enriched["risk_score"]   = score
    enriched["severity"]     = severity
    enriched["score_reason"] = "\n".join(reasons)

    logger.debug(
        "Enriched %s from %s → score=%d, severity=%s",
        enriched.get("threat_type", "?"),
        enriched.get("source_ip", "?"),
        score,
        severity,
    )
    return enriched


# ---------------------------------------------------------------------------
# Batch Processing
# ---------------------------------------------------------------------------

def process_all_detections(detections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Enrich every detection in *detections* and return them sorted by
    risk_score descending (highest-risk first).

    Empty or None entries in the input list are silently skipped.

    Parameters
    ----------
    detections : list[dict]  – raw detections from run_all_rules() and/or
                                get_anomaly_detections()

    Returns
    -------
    list[dict]  – enriched and sorted detections
    """
    if not detections:
        logger.info("process_all_detections: no detections to process.")
        return []

    enriched: list[dict] = []
    for idx, det in enumerate(detections):
        if not det:
            logger.debug("Skipping empty detection at index %d.", idx)
            continue
        try:
            enriched.append(enrich_detection(det))
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "Failed to enrich detection at index %d: %s", idx, exc, exc_info=True
            )

    # Highest risk first → most actionable detections appear at the top
    enriched.sort(key=lambda d: d.get("risk_score", 0), reverse=True)

    logger.info(
        "process_all_detections: %d detection(s) enriched. "
        "Top score: %d (%s).",
        len(enriched),
        enriched[0].get("risk_score", 0) if enriched else 0,
        enriched[0].get("threat_type", "N/A") if enriched else "N/A",
    )
    return enriched
