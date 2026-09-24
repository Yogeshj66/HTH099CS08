import os
import sys
import time
from datetime import datetime, timedelta, timezone

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for p in (ROOT, os.path.join(ROOT, "dashboard")):
    if p not in sys.path:
        sys.path.insert(0, p)
os.environ["SOC_DB_PATH"] = ":memory:"      # importing dashboard.app must not create a db file

from soc import config                      # noqa: E402
from soc.incident_manager import IncidentManager   # noqa: E402
from soc.models import to_iso               # noqa: E402
from soc.runtime import SocRuntime          # noqa: E402

T0 = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)


class FakeClock:
    def __init__(self, start=T0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)


def wait_until(cond, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def settings():
    return config.Settings(db_path=":memory:", scenario_step_delay=0.0, analyst_capacity=3)


@pytest.fixture
def runtime(settings, clock):
    rt = SocRuntime(settings, live_trust_fn=lambda: (_ for _ in ()).throw(RuntimeError("no hardware")), clock=clock)
    yield rt
    rt.stop_scenario()
    rt._live_stop.set()


def make_incident(mgr, severity_score=60, confidence=0.7, host="HOST-01", n_events=3, created_at=None,
                  severity="HIGH"):
    """Insert a ready-made incident straight into the store (for queue/priority tests)."""
    events = [{"event_id": f"E{i}", "timestamp": "2026-09-24T12:00:00Z", "source": s, "event_type": "x",
               "host": host, "src_ip": None, "dst_ip": None, "base_severity": "medium", "metadata": {}}
              for i, s in zip(range(n_events), ["network", "authentication", "endpoint", "usb"] * 3)]
    return mgr.create({
        "title": "Test incident", "type": "composite_incident", "host": host, "source_ip": "192.168.1.20",
        "created_at": created_at or to_iso(T0), "last_event_at": to_iso(T0), "related_events": events,
        "matched_rules": [], "trust_score": 50.0, "severity_score": severity_score, "severity": severity,
        "confidence": confidence, "recommended_actions": [],
    })


@pytest.fixture
def mgr():
    return IncidentManager(":memory:")
