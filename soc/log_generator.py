"""soc.log_generator - safe, simulated security log generator.

Emits RAW event dicts (deliberately not the canonical schema) so the
normalizer has real work to do. Nothing here touches the network or system.
"""

import random
from datetime import datetime
from typing import Iterator, List, Optional

from . import config

HOSTS = ["HOST-01", "HOST-02", "HOST-03", "HOST-04"]
INTERNAL_IPS = [f"192.168.1.{n}" for n in (10, 11, 12, 20, 30, 44, 50)]
# TEST-NET-3 (RFC 5737): documentation addresses, never routable
EXTERNAL_IPS = ["203.0.113.5", "203.0.113.77", "203.0.113.200"]
USERS = ["admin", "root", "svc-backup", "analyst1", "guest"]
PROCESSES = ["unknown_tool.exe", "rundll32_sim.exe", "encoded_script_sim"]


def make_raw_event(source: str, event_type: str, host: str = "HOST-01",
                   src_ip: Optional[str] = None, dst_ip: Optional[str] = None,
                   severity: Optional[str] = None, timestamp: Optional[datetime] = None,
                   details: Optional[dict] = None) -> dict:
    """Build a raw log record (vendor-style keys). None values are omitted."""
    raw = {
        "ts": timestamp.isoformat() if timestamp else None,
        "category": source,
        "event": event_type,
        "hostname": host,
        "src": src_ip,
        "dst": dst_ip,
        "severity": severity,
        "details": details,
    }
    return {k: v for k, v in raw.items() if v is not None}


class LogGenerator:
    def __init__(self, seed: Optional[int] = None, rate: float = 0.5, hosts: Optional[List[str]] = None):
        self._rng = random.Random(seed)
        self.rate = rate                       # events per second (configurable)
        self.hosts = hosts or HOSTS
        self._suspicious = [(s, t, sev) for s, types in config.EVENT_CATALOG.items()
                            for t, sev in types.items() if sev != "info"]

    def interval(self) -> float:
        return 1.0 / max(self.rate, 0.01)

    def _details(self, event_type: str) -> dict:
        r = self._rng
        if event_type in ("failed_login", "brute_force_attempt", "successful_login"):
            return {"user": r.choice(USERS), "protocol": r.choice(["ssh", "rdp", "smb"])}
        if event_type == "port_scan":
            return {"ports_probed": r.randint(20, 1024)}
        if event_type in ("suspicious_process", "process_started"):
            return {"process": r.choice(PROCESSES)}
        if event_type in ("traffic_spike", "routine_traffic"):
            return {"mbps": r.randint(5, 900)}
        return {"simulated": True}

    def normal_event(self, timestamp: Optional[datetime] = None) -> dict:
        source, etype = self._rng.choice(config.NORMAL_EVENTS)
        return make_raw_event(source, etype, self._rng.choice(self.hosts),
                              self._rng.choice(INTERNAL_IPS), self._rng.choice(INTERNAL_IPS),
                              None, timestamp, self._details(etype))

    def suspicious_event(self, timestamp: Optional[datetime] = None) -> dict:
        source, etype, sev = self._rng.choice(self._suspicious)
        return make_raw_event(source, etype, self._rng.choice(self.hosts),
                              self._rng.choice(EXTERNAL_IPS + INTERNAL_IPS), self._rng.choice(INTERNAL_IPS),
                              sev, timestamp, self._details(etype))

    def random_event(self, suspicious_ratio: float = 0.25, timestamp: Optional[datetime] = None) -> dict:
        if self._rng.random() < suspicious_ratio:
            return self.suspicious_event(timestamp)
        return self.normal_event(timestamp)

    def stream(self, count: Optional[int] = None, suspicious_ratio: float = 0.25) -> Iterator[dict]:
        n = 0
        while count is None or n < count:
            yield self.random_event(suspicious_ratio)
            n += 1
