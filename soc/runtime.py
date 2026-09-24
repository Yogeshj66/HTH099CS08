"""soc.runtime - wires the pipeline together and owns the background threads.

raw event -> normalizer -> correlation -> incident (severity + priority + response)
          -> analyst queue

Route handlers and tests talk to this class only.
"""

import logging
import threading
import time
from collections import deque
from datetime import datetime
from typing import Callable, Dict, List, Optional

from . import attack_scenarios, config, priority_engine, response_engine, severity_engine
from .analyst_queue import AnalystQueue
from .correlation_engine import CorrelationEngine, compute_confidence, rule_summary
from .event_normalizer import EventNormalizer
from .incident_manager import IncidentManager
from .log_generator import LogGenerator
from .models import SecurityEvent, parse_iso, to_iso, utcnow
from .trust_adapter import TrustAdapter

log = logging.getLogger("soc.runtime")

DASHBOARD_SOURCES = ("wifi", "usb", "bluetooth", "authentication", "network", "firewall", "endpoint", "system")


class ScenarioError(ValueError):
    pass


class SocRuntime:
    def __init__(self, settings: Optional[config.Settings] = None,
                 live_trust_fn: Optional[Callable[[], dict]] = None,
                 clock: Callable[[], datetime] = utcnow):
        self.settings = settings or config.load_settings()
        self._clock = clock
        self.lock = threading.RLock()
        self.started_at = clock()

        self.normalizer = EventNormalizer(clock)
        self.correlation = CorrelationEngine(window_sec=self.settings.correlation_window_sec)
        self.incidents = IncidentManager(self.settings.db_path)
        self.queue = AnalystQueue(self.incidents, self.settings.analyst_capacity, clock)
        self.trust = TrustAdapter(self.settings, live_trust_fn)
        self.generator = LogGenerator(self.settings.sim_seed, self.settings.sim_event_rate)

        self.events: deque = deque(maxlen=self.settings.max_events)
        self.cleared_event_ids = set()
        self.mode = self.settings.mode

        self._scenario_thread: Optional[threading.Thread] = None
        self._scenario_stop = threading.Event()
        self.scenario = {"running": False, "name": None, "title": None, "step": 0, "total": 0}
        self._live_thread: Optional[threading.Thread] = None
        self._live_stop = threading.Event()

        self.queue.rebalance()                       # pick up incidents persisted by a previous run
        if self.mode == "live":
            self._start_live()

    # ------------------------------------------------------------------
    # Ingestion pipeline
    # ------------------------------------------------------------------
    def ingest_raw(self, raw) -> Optional[dict]:
        event = self.normalizer.normalize(raw)
        return self.ingest_event(event) if event else None

    def ingest_event(self, event: SecurityEvent) -> Optional[dict]:
        """Returns the affected incident (dict) or None. Duplicates are dropped."""
        with self.lock:
            if not self.correlation.register(event):
                return None
            self.events.append(event)
            corr = self.correlation.evaluate(event)
            if corr is None:
                return None
            incident = self._upsert_incident(corr, event)
            self.queue.rebalance()
            return self.incidents.get(incident["incident_id"])

    def _upsert_incident(self, corr, trigger: SecurityEvent) -> dict:
        trust = self.trust_score()["final_score"]
        existing = self.incidents.find_open_match(corr.host, corr.source_ip, trigger.timestamp,
                                                  self.settings.correlation_window_sec)
        events: Dict[str, dict] = {}
        rules: Dict[str, dict] = {}
        if existing:
            events.update({e["event_id"]: e for e in existing["related_events"]})
            rules.update({r["id"]: r for r in existing["matched_rules"]})
        events.update({e.event_id: e.to_dict() for e in corr.events})
        rules.update({r["id"]: r for r in corr.matched_rules})

        ordered = sorted(events.values(), key=lambda e: (e["timestamp"], e["event_id"]))
        matched = sorted(rules.values(), key=lambda r: -r["rank"])
        sources = sorted({e["source"] for e in ordered})
        sev = severity_engine.score_incident(ordered, matched, trust)
        primary = matched[0]

        fields = {
            "title": primary["name"], "type": primary["incident_type"],
            "host": corr.host, "source_ip": corr.source_ip or (existing or {}).get("source_ip"),
            "related_events": ordered, "event_count": len(ordered), "sources": sources,
            "last_event_at": ordered[-1]["timestamp"],
            "matched_rules": matched,
            "trust_score": trust, "severity_score": sev["score"], "severity": sev["severity"],
            "severity_breakdown": sev["breakdown"], "explanation": sev["explanation"],
            "confidence": compute_confidence(matched, len(sources)),
            "updated_at": to_iso(self._clock()),
        }
        if existing:
            merged = dict(existing, **fields)
            fields["recommended_actions"] = response_engine.recommend(merged)
            return self.incidents.update(existing["incident_id"], **fields)
        fields.update({"created_at": to_iso(self._clock()), "status": "NEW", "assigned_analyst": None})
        fields["recommended_actions"] = response_engine.recommend(fields)
        return self.incidents.create(fields)

    # ------------------------------------------------------------------
    # Trust score (existing engine preserved; simulated in SIMULATION mode)
    # ------------------------------------------------------------------
    def trust_score(self) -> dict:
        if self.mode == "live":
            result = dict(self.trust.cached_live() or self.trust.refresh_live())
        else:
            with self.lock:
                usable = [e for e in self.events if e.event_id not in self.cleared_event_ids]
            result = self.trust.simulated(usable, self._clock())
        result["mode"] = self.mode
        return result

    # ------------------------------------------------------------------
    # Analyst actions
    # ------------------------------------------------------------------
    def acknowledge(self, incident_id: str) -> dict:
        with self.lock:
            return self.queue.acknowledge(incident_id)

    def resolve(self, incident_id: str) -> dict:
        return self._close(incident_id, self.queue.resolve)

    def false_positive(self, incident_id: str) -> dict:
        return self._close(incident_id, self.queue.false_positive)

    def _close(self, incident_id: str, action) -> dict:
        with self.lock:
            incident = action(incident_id)
            # a closed incident no longer drags the simulated trust score down
            self.cleared_event_ids.update(e["event_id"] for e in incident["related_events"])
            return incident

    # ------------------------------------------------------------------
    # Scenarios (SIMULATION mode only)
    # ------------------------------------------------------------------
    def start_scenario(self, name: str) -> dict:
        if name not in attack_scenarios.SCENARIO_NAMES:
            raise ScenarioError(f"unknown scenario '{name}'")
        if self.mode != "simulation":
            raise ScenarioError("scenarios run only in simulation mode")
        self.stop_scenario()
        total = None if name == attack_scenarios.RANDOM_SCENARIO else len(attack_scenarios.scenario_steps(name))
        title = "Random Simulation" if total is None else attack_scenarios.SCENARIOS[name]["title"]
        self._scenario_stop = threading.Event()
        self.scenario = {"running": True, "name": name, "title": title, "step": 0, "total": total}
        self._scenario_thread = threading.Thread(target=self._run_scenario, args=(name, self._scenario_stop),
                                                 daemon=True, name=f"scenario-{name}")
        self._scenario_thread.start()
        return dict(self.scenario)

    def stop_scenario(self) -> dict:
        self._scenario_stop.set()
        thread = self._scenario_thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=3)
        self.scenario["running"] = False
        return dict(self.scenario)

    def _run_scenario(self, name: str, stop: threading.Event):
        try:
            if name == attack_scenarios.RANDOM_SCENARIO:
                self.generator.rate = self.settings.sim_event_rate
                while not stop.wait(self.generator.interval()):
                    self.ingest_raw(self.generator.random_event(self.settings.sim_suspicious_ratio))
                    self.scenario["step"] += 1
            else:
                for raw in attack_scenarios.build_scenario_events(name):
                    if stop.wait(self.settings.scenario_step_delay):
                        break
                    self.ingest_raw(raw)
                    self.scenario["step"] += 1
        except Exception:
            log.exception("scenario %s crashed", name)
        finally:
            if self._scenario_stop is stop:
                self.scenario["running"] = False

    def replay_scenario(self, name: str, base_time: Optional[datetime] = None) -> List[Optional[dict]]:
        """Synchronous, deterministic replay (tests / CLI): timestamps = base_time + offset."""
        base = base_time or self._clock()
        return [self.ingest_raw(raw) for raw in attack_scenarios.build_scenario_events(name, base)]

    # ------------------------------------------------------------------
    # Mode handling
    # ------------------------------------------------------------------
    def set_mode(self, mode: str) -> str:
        if mode not in config.MODES:
            raise ScenarioError(f"unknown mode '{mode}'")
        if mode == self.mode:
            return self.mode
        if mode == "live":
            self.stop_scenario()
            self.mode = "live"
            self._start_live()
        else:
            self._live_stop.set()
            self.mode = "simulation"
        return self.mode

    def _start_live(self):
        self._live_stop = threading.Event()
        self._live_thread = threading.Thread(target=self._live_loop, args=(self._live_stop,),
                                             daemon=True, name="live-collector")
        self._live_thread.start()

    def _live_loop(self, stop: threading.Event):
        while not stop.is_set():
            try:
                trust = self.trust.refresh_live()            # slow, deliberately outside the lock
                for raw in self.trust.snapshot_events(trust) + self.trust.signals_from_trust(trust):
                    self.ingest_raw(raw)
            except Exception:
                log.exception("live collection cycle failed")
            stop.wait(self.settings.live_poll_sec)

    # ------------------------------------------------------------------
    # Reset
    # ------------------------------------------------------------------
    def reset(self):
        self.stop_scenario()
        with self.lock:
            self.events.clear()
            self.cleared_event_ids.clear()
            self.correlation.reset()
            self.normalizer.reset()
            self.incidents.clear()
            self.trust.reset()
            self.scenario = {"running": False, "name": None, "title": None, "step": 0, "total": 0}

    # ------------------------------------------------------------------
    # Read models for the API
    # ------------------------------------------------------------------
    def list_events(self, limit: int = 100, source: Optional[str] = None) -> List[dict]:
        with self.lock:
            items = [e for e in self.events if source is None or e.source == source]
        return [e.to_dict() for e in items[-limit:]][::-1]           # newest first

    def list_incidents(self, status: Optional[str] = None) -> List[dict]:
        self.queue.rebalance()
        items = self.incidents.list([status] if status else None)
        return sorted(items, key=lambda i: (i["priority_rank"] is None, i["priority_rank"] or 0,
                                            i["incident_id"]))

    def analyst_queue(self) -> dict:
        return self.queue.view()

    def statistics(self) -> dict:
        self.queue.rebalance()
        stats = self.incidents.statistics()
        view = self.queue.view()
        with self.lock:
            events = list(self.events)
        horizon = self._clock().timestamp() - 900
        alerts_by_source: Dict[str, int] = {}
        for e in events:
            if e.is_signal:
                alerts_by_source[e.source] = alerts_by_source.get(e.source, 0) + 1
        signals: Dict[str, dict] = {s: {"events": 0, "signals": 0, "last_event": None} for s in DASHBOARD_SOURCES}
        for e in events:
            row = signals.setdefault(e.source, {"events": 0, "signals": 0, "last_event": None})
            row["events"] += 1
            if e.is_signal and e.timestamp.timestamp() >= horizon:
                row["signals"] += 1
            row["last_event"] = e.to_dict()
        return {"incidents": stats,
                "analysts": {"capacity": view["capacity"], "active": view["active_count"],
                             "available": view["available"], "waiting": len(view["waiting"])},
                "events": {"total": len(events), "rejected": self.normalizer.rejected,
                           "duplicates": self.correlation.duplicates},
                "alerts_by_source": alerts_by_source, "signals": signals}

    def system_status(self) -> dict:
        return {"mode": self.mode, "scenario": dict(self.scenario),
                "uptime_sec": int((self._clock() - self.started_at).total_seconds()),
                "analyst_capacity": self.queue.capacity,
                "live_collectors": {"available": self.trust.live_available, "error": self.trust.last_live_error},
                "database": "memory" if self.settings.db_path == ":memory:" else "sqlite",
                "settings": {"correlation_window_sec": self.settings.correlation_window_sec,
                             "scenario_step_delay": self.settings.scenario_step_delay},
                "time": to_iso(self._clock())}


if __name__ == "__main__":       # python -m soc.runtime coordinated_intrusion
    import sys
    logging.basicConfig(level=logging.WARNING)
    scenario = sys.argv[1] if len(sys.argv) > 1 else "coordinated_intrusion"
    rt = SocRuntime(config.Settings(db_path=":memory:"))
    for step, inc in enumerate(rt.replay_scenario(scenario), start=1):
        print(f"T+{step}: ", inc and f"{inc['incident_id']} {inc['title']} sev={inc['severity_score']} {inc['severity']}")
    for inc in rt.list_incidents():
        print("\n" + inc["explanation"])
        print("trust:", inc["trust_score"], "| priority:", inc["priority_score"], "-", inc["priority_reason"])
        print("actions:", *inc["recommended_actions"], sep="\n  - ")
