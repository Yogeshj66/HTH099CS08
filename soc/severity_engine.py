"""soc.severity_engine - transparent 0-100 severity with a line-by-line explanation.

Works on event dicts (SecurityEvent.to_dict()). All numbers come from soc.config.
Trust score is CONTEXT here (a small bonus when trust is low), never added as a score.
"""

from collections import Counter
from typing import List, Optional

from . import config


def label_for(score: int) -> str:
    for upper, label in config.SEVERITY_THRESHOLDS:
        if score <= upper:
            return label
    return config.SEVERITY_THRESHOLDS[-1][1]


def _label(event_type: str) -> str:
    return config.EVENT_LABELS.get(event_type, event_type.replace("_", " ").capitalize())


def score_incident(events: List[dict], matched_rules: List[dict],
                   trust_score: Optional[float] = None) -> dict:
    signals = [e for e in events if e.get("base_severity") != "info"]
    counts = Counter(e["event_type"] for e in signals)
    breakdown = []

    # 1) each distinct signal type counts once
    for etype, n in counts.items():
        if n == 1 and etype in config.SINGLE_OCCURRENCE_POINTS:
            pts = config.SINGLE_OCCURRENCE_POINTS[etype]
            label = "Failed login" if etype == "failed_login" else _label(etype)
        elif etype in config.EVENT_POINTS:
            pts, label = config.EVENT_POINTS[etype], _label(etype)
        else:
            worst = max((e["base_severity"] for e in signals if e["event_type"] == etype),
                        key=lambda s: config.BASE_SEVERITY_POINTS.get(s, 0))
            pts, label = config.BASE_SEVERITY_POINTS.get(worst, 0), _label(etype)
        breakdown.append({"label": label, "points": pts,
                          "detail": f"{n} event(s)" if n > 1 else "1 event"})

    # 2) repeated activity
    extra = sum(n - 1 for n in counts.values() if n > 1)
    if extra:
        pts = min(config.REPEAT_POINTS_MAX, extra * config.REPEAT_POINTS_PER_EXTRA)
        breakdown.append({"label": "Repeated activity", "points": pts,
                          "detail": f"{extra} repeat occurrence(s)"})

    # 3) cross-source correlation
    sources = sorted({e["source"] for e in signals})
    if len(sources) >= 2:
        table = config.CROSS_SOURCE_POINTS
        pts = table.get(len(sources), table[max(table)])
        breakdown.append({"label": "Multi-source correlation", "points": pts,
                          "detail": f"{len(sources)} sources: {', '.join(sources)}"})

    # 4) attack-pattern confidence
    if matched_rules:
        best = max(matched_rules, key=lambda r: r["rank"])
        if best["severity_bonus"]:
            breakdown.append({"label": f"Pattern: {best['name']}", "points": best["severity_bonus"],
                              "detail": best["id"]})

    # 5) trust context
    if trust_score is not None:
        for limit, pts in config.TRUST_CONTEXT_POINTS:
            if trust_score < limit:
                breakdown.append({"label": "Low environment trust", "points": pts,
                                  "detail": f"Trust Score {trust_score:g}/100"})
                break

    raw = sum(b["points"] for b in breakdown)
    score = max(0, min(100, raw))
    severity = label_for(score)

    lines = [f"SEVERITY SCORE: {score} ({severity})", "WHY:"]
    lines += [f"+{b['points']:02d} {b['label']}" for b in breakdown]
    if raw > 100:
        lines.append(f"Total {raw}, capped at 100")
    return {"score": score, "severity": severity, "breakdown": breakdown,
            "raw_total": raw, "explanation": "\n".join(lines)}
