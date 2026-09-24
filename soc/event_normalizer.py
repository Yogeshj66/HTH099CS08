"""soc.event_normalizer - turn any raw event dict into a SecurityEvent.

Malformed input never raises: normalize() returns None and counts the reject.
"""

import ipaddress
import itertools
import json
import logging
import re
import threading
from datetime import datetime, timezone
from typing import Any, Callable, List, Optional

from . import config
from .models import SEVERITIES, SOURCES, SecurityEvent, utcnow

log = logging.getLogger("soc.normalizer")

_TYPE_RE = re.compile(r"[^a-z0-9_]")
_HOST_RE = re.compile(r"[^A-Za-z0-9._\-]")
MAX_META_KEYS = 30
MAX_STR = 300


class NormalizationError(ValueError):
    pass


def _pick(raw: dict, field_name: str) -> Any:
    for key in config.FIELD_ALIASES[field_name]:
        value = raw.get(key)
        if value is not None and value != "":
            return value
    return None


def parse_timestamp(value: Any) -> datetime:
    """datetime | epoch seconds/ms | ISO string -> aware UTC datetime. Raises ValueError."""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, bool):
        raise ValueError("bool is not a timestamp")
    elif isinstance(value, (int, float)):
        seconds = value / 1000.0 if value > 1e11 else float(value)
        dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    elif isinstance(value, str):
        text = value.strip()
        try:
            return parse_timestamp(float(text))
        except ValueError:
            pass
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    else:
        raise ValueError(f"unsupported timestamp type {type(value).__name__}")
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def normalize_severity(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        v = float(value)
        if v <= 0:
            return "info"
        if v <= 3:
            return "low"
        if v <= 6:
            return "medium"
        if v <= 8:
            return "high"
        return "critical"
    text = str(value).strip().lower()
    text = config.SEVERITY_ALIASES.get(text, text)
    return text if text in SEVERITIES else None


def _clean_meta(value: Any) -> dict:
    if not isinstance(value, dict):
        return {} if value is None else {"raw": str(value)[:MAX_STR]}
    out = {}
    for key, val in list(value.items())[:MAX_META_KEYS]:
        k = str(key)[:40]
        if isinstance(val, (int, float, bool)) or val is None:
            out[k] = val
        elif isinstance(val, str):
            out[k] = val[:MAX_STR]
        else:
            try:
                out[k] = json.dumps(val, default=str)[:MAX_STR]
            except (TypeError, ValueError):
                out[k] = str(val)[:MAX_STR]
    return out


class EventNormalizer:
    def __init__(self, clock: Callable[[], datetime] = utcnow, id_prefix: str = "EVT"):
        self._clock = clock
        self._prefix = id_prefix
        self._counter = itertools.count(1)
        self._lock = threading.Lock()
        self.accepted = 0
        self.rejected = 0
        self.last_error: Optional[str] = None

    # -- public -----------------------------------------------------------
    def normalize(self, raw: Any) -> Optional[SecurityEvent]:
        try:
            event = self._normalize(raw)
        except NormalizationError as exc:
            return self._reject(str(exc))
        except Exception:                      # never let bad data crash the dashboard
            log.exception("unexpected normalization failure")
            return self._reject("unexpected error while normalizing event")
        with self._lock:
            self.accepted += 1
        return event

    def normalize_batch(self, raws) -> List[SecurityEvent]:
        return [e for e in (self.normalize(r) for r in raws) if e is not None]

    def reset(self):
        with self._lock:
            self._counter = itertools.count(1)
            self.accepted = self.rejected = 0
            self.last_error = None

    # -- internals --------------------------------------------------------
    def _reject(self, reason: str) -> None:
        with self._lock:
            self.rejected += 1
            self.last_error = reason
        log.warning("rejected event: %s", reason)
        return None

    def _next_id(self) -> str:
        with self._lock:
            return f"{self._prefix}-{next(self._counter):03d}"

    def _normalize(self, raw: Any) -> SecurityEvent:
        if not isinstance(raw, dict):
            raise NormalizationError("event is not an object")
        warnings: List[str] = []

        # event type
        etype = _pick(raw, "event_type")
        if etype is None:
            raise NormalizationError("missing event type")
        etype = _TYPE_RE.sub("", str(etype).strip().lower().replace(" ", "_").replace("-", "_"))[:64]
        if not etype:
            raise NormalizationError("empty event type")

        # source
        src_raw = _pick(raw, "source")
        source = None
        if src_raw is not None:
            s = str(src_raw).strip().lower()
            s = config.SOURCE_ALIASES.get(s, s)
            source = s if s in SOURCES else None
            if source is None:
                warnings.append(f"unknown source '{str(src_raw)[:30]}'")
        if source is None:
            candidates = [s for s, types in config.EVENT_CATALOG.items() if etype in types]
            if len(candidates) == 1:
                source = candidates[0]
            else:
                raise NormalizationError(f"cannot determine source for event '{etype}'")

        # severity
        sev_raw = _pick(raw, "base_severity")
        severity = normalize_severity(sev_raw)
        if severity is None:
            if sev_raw is not None:
                warnings.append("invalid severity, using catalog default")
            severity = config.EVENT_CATALOG.get(source, {}).get(etype, "low")

        # timestamp
        ts_raw = _pick(raw, "timestamp")
        if ts_raw is None:
            ts = self._clock()
        else:
            try:
                ts = parse_timestamp(ts_raw)
            except (ValueError, OverflowError, OSError):
                ts = self._clock()
                warnings.append("invalid timestamp, using receive time")

        # host / addresses
        host_raw = _pick(raw, "host")
        host = _HOST_RE.sub("_", str(host_raw).strip())[:64].upper() if host_raw is not None else ""
        if not host:
            host = config.DEFAULT_HOST
            warnings.append("missing host")
        src_ip = self._ip(_pick(raw, "src_ip"), "src_ip", warnings)
        dst_ip = self._ip(_pick(raw, "dst_ip"), "dst_ip", warnings)

        meta = _clean_meta(_pick(raw, "metadata"))
        if warnings:
            meta["normalization_warnings"] = warnings

        event_id = _pick(raw, "event_id")
        event_id = _HOST_RE.sub("_", str(event_id))[:64] if event_id is not None else self._next_id()

        return SecurityEvent(event_id=event_id, timestamp=ts, source=source, event_type=etype,
                             host=host, src_ip=src_ip, dst_ip=dst_ip, base_severity=severity,
                             metadata=meta)

    @staticmethod
    def _ip(value: Any, name: str, warnings: List[str]) -> Optional[str]:
        if value is None:
            return None
        try:
            return str(ipaddress.ip_address(str(value).strip()))
        except ValueError:
            warnings.append(f"invalid {name}")
            return None
