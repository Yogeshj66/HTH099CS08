"""soc.correlation_engine - relate weak signals into composite incident candidates.

Rules live in soc.config.RULES (data). Events are related when they share a
host or a source IP and fall inside the rule's time window. Informational
events are never signals. One weak signal alone never creates an incident.
"""

import threading
from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Dict, List, Optional

from . import config
from .models import SecurityEvent


@dataclass
class Correlation:
    host: str
    source_ip: Optional[str]
    events: List[SecurityEvent]
    matched_rules: List[dict]          # sorted, strongest rule first
    confidence: float
    sources: List[str] = field(default_factory=list)

    @property
    def primary_rule(self) -> dict:
        return self.matched_rules[0]


def rule_summary(rule: dict) -> dict:
    """The small, JSON-safe rule description stored on incidents."""
    return {k: rule[k] for k in ("id", "name", "incident_type", "rank", "severity_bonus",
                                 "base_confidence", "description")}


def compute_confidence(rules: List[dict], source_count: int) -> float:
    if not rules:
        return 0.0
    base = max(r["base_confidence"] for r in rules)
    base += config.CONFIDENCE_PER_EXTRA_RULE * (len(rules) - 1)
    base += config.CONFIDENCE_PER_EXTRA_SOURCE * max(0, source_count - 1)
    return round(min(config.MAX_CONFIDENCE, base), 2)


class CorrelationEngine:
    def __init__(self, rules: Optional[List[dict]] = None, window_sec: Optional[int] = None):
        self.rules = sorted(rules if rules is not None else config.RULES, key=lambda r: -r["rank"])
        self.window_sec = window_sec or config.Settings().correlation_window_sec
        self._signals: List[SecurityEvent] = []
        self._seen_ids = set()
        self._seen_fps = set()
        self._max_ts = None
        self._lock = threading.RLock()
        self.duplicates = 0

    # -- intake -----------------------------------------------------------
    def register(self, event: SecurityEvent) -> bool:
        """Remember the event. False if it is a duplicate (same id or identical content)."""
        with self._lock:
            fp = event.fingerprint()
            if event.event_id in self._seen_ids or fp in self._seen_fps:
                self.duplicates += 1
                return False
            self._seen_ids.add(event.event_id)
            self._seen_fps.add(fp)
            if event.is_signal:
                self._signals.append(event)
            if self._max_ts is None or event.timestamp > self._max_ts:
                self._max_ts = event.timestamp
            self._prune()
            return True

    def ingest(self, event: SecurityEvent) -> Optional[Correlation]:
        """register + evaluate in one call."""
        if not self.register(event):
            return None
        return self.evaluate(event)

    def reset(self):
        with self._lock:
            self._signals.clear()
            self._seen_ids.clear()
            self._seen_fps.clear()
            self._max_ts = None
            self.duplicates = 0

    def _prune(self):
        horizon = self._max_ts - timedelta(seconds=self.window_sec * 4)
        if len(self._signals) > 2000 or (self._signals and self._signals[0].timestamp < horizon):
            self._signals = [e for e in self._signals if e.timestamp >= horizon]

    # -- evaluation -------------------------------------------------------
    def evaluate(self, event: SecurityEvent) -> Optional[Correlation]:
        if not event.is_signal:
            return None
        with self._lock:
            matched: List[dict] = []
            evidence: Dict[str, SecurityEvent] = {}
            for rule in self.rules:
                window = timedelta(seconds=rule.get("window_sec", self.window_sec))
                related = self._related(event, window)
                hit = self._match(rule, related)
                if hit is not None:
                    matched.append(rule)
                    for e in hit:
                        evidence[e.event_id] = e
            if not matched:
                return None
            events = sorted(evidence.values(), key=lambda e: (e.timestamp, e.event_id))
            sources = sorted({e.source for e in events})
            ips = Counter(e.src_ip for e in events if e.src_ip)
            return Correlation(
                host=event.host,
                source_ip=ips.most_common(1)[0][0] if ips else None,
                events=events,
                matched_rules=[rule_summary(r) for r in matched],
                confidence=compute_confidence(matched, len(sources)),
                sources=sources,
            )

    def _related(self, event: SecurityEvent, window: timedelta) -> List[SecurityEvent]:
        lo = event.timestamp - window
        return [e for e in self._signals
                if lo <= e.timestamp <= event.timestamp
                and (e.host == event.host or (event.src_ip and e.src_ip == event.src_ip))]

    @staticmethod
    def _match(rule: dict, related: List[SecurityEvent]) -> Optional[List[SecurityEvent]]:
        """Return the evidence events if the rule matches, else None."""
        if "all_of" in rule:
            evidence: Dict[str, SecurityEvent] = {}
            for req in rule["all_of"]:
                hits = [e for e in related if e.event_type in req["types"]
                        and ("sources" not in req or e.source in req["sources"])]
                if len(hits) < req.get("min_count", 1):
                    return None
                evidence.update({e.event_id: e for e in hits})
            return list(evidence.values())
        if "sources" in rule:
            related = [e for e in related if e.source in rule["sources"]]
        if len({e.source for e in related}) >= rule.get("min_sources", 2) \
                and len(related) >= rule.get("min_events", 2):
            return list(related)
        return None
