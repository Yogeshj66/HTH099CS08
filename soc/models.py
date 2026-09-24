"""soc.models - the common security event model and shared constants."""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

SOURCES = ("authentication", "network", "firewall", "endpoint", "system", "wifi", "usb", "bluetooth")
SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

INCIDENT_STATUSES = ("NEW", "PENDING", "ASSIGNED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE")
ACTIVE_STATUSES = ("NEW", "PENDING", "ASSIGNED", "INVESTIGATING")
TERMINAL_STATUSES = ("RESOLVED", "FALSE_POSITIVE")
SEVERITY_LABELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(dt: datetime) -> str:
    """UTC ISO-8601 with seconds precision, e.g. 2026-09-24T12:30:10Z."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@dataclass
class SecurityEvent:
    """One normalized security event, whatever its origin."""

    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    host: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    base_severity: str = "low"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_signal(self) -> bool:
        """Informational events are context, not weak signals."""
        return self.base_severity != "info"

    def fingerprint(self) -> tuple:
        meta = json.dumps(self.metadata, sort_keys=True, default=str)
        return (self.timestamp.isoformat(), self.source, self.event_type, self.host,
                self.src_ip, self.dst_ip, self.base_severity, meta)

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": to_iso(self.timestamp),
            "source": self.source,
            "event_type": self.event_type,
            "host": self.host,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "base_severity": self.base_severity,
            "metadata": dict(self.metadata),
        }
