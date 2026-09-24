"""soc.priority_engine - who should be worked first. Severity is one input, not the answer."""

from datetime import datetime
from typing import Dict, List, Optional

from . import config
from .models import parse_iso, utcnow


def score_incident(incident: dict, now: Optional[datetime] = None) -> dict:
    now = now or utcnow()
    w = config.PRIORITY_WEIGHTS
    events = incident.get("related_events", [])
    sources = {e["source"] for e in events}
    label = incident["severity"]

    severity = incident["severity_score"]
    confidence = incident["confidence"] * 100
    impact = config.HOST_CRITICALITY.get(incident["host"], config.DEFAULT_HOST_CRITICALITY)
    volume = min(100, len(events) * config.VOLUME_POINTS_PER_EVENT)
    try:
        age = max(0.0, (now - parse_iso(incident["created_at"])).total_seconds())
    except (KeyError, ValueError):
        age = 0.0
    sla = min(100.0, age / config.SLA_SECONDS.get(label, 3600) * 100)

    score = round(w["severity"] * severity + w["confidence"] * confidence + w["impact"] * impact
                  + w["volume"] * volume + w["sla"] * sla)
    score = max(0, min(100, score))

    reasons = [f"{label.capitalize()} severity"]
    if incident["confidence"] >= 0.8:
        reasons.append("high confidence")
    elif incident["confidence"] >= 0.6:
        reasons.append("moderate confidence")
    if len(sources) >= 3:
        reasons.append("multiple sources")
    if impact >= 80:
        reasons.append("critical asset")
    if sla >= 75:
        reasons.append("SLA at risk")
    if len(events) >= 5:
        reasons.append(f"{len(events)} correlated events")
    return {"priority_score": score, "priority_reason": " + ".join(reasons),
            "priority_factors": {"severity": round(severity), "confidence": round(confidence),
                                 "impact": impact, "volume": volume, "sla": round(sla)}}


def rank(incidents: List[dict]) -> Dict[str, int]:
    """incident_id -> rank (1 = work first). Ties: older incident first."""
    ordered = sorted(incidents, key=lambda i: (-i["priority_score"], i["created_at"], i["incident_id"]))
    return {inc["incident_id"]: n for n, inc in enumerate(ordered, start=1)}
