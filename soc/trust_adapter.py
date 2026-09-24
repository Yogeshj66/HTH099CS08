"""soc.trust_adapter - bridge between the existing Trust Score Engine and the SOC layer.

* LIVE: calls fusion.engine.compute_trust_score() (unchanged), cached, with a
  clean fallback if the real collectors are unavailable (e.g. not on Windows).
* SIMULATION: builds a score of the SAME SHAPE using the SAME fusion weights
  (imported from fusion.engine) from simulated SOC events - no hardware needed.
* Turns weak Wi-Fi/USB/Bluetooth sub-scores into SecurityEvents (context for incidents).
Trust Score is never merged into, or replaced by, the Severity Score.
"""

import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional

from . import config
from .log_generator import make_raw_event
from .models import SecurityEvent, utcnow

log = logging.getLogger("soc.trust")


def _weights() -> Dict[str, float]:
    try:
        from fusion.engine import WEIGHTS          # single source of truth for weights
        return dict(WEIGHTS)
    except Exception:                               # pragma: no cover - only if fusion import breaks
        return {"wifi": 0.40, "usb": 0.35, "bluetooth": 0.25}


def _status(score: float) -> str:
    for limit, label in config.TRUST_STATUS_THRESHOLDS:
        if score >= limit:
            return label
    return "Untrusted"


def _default_live_fn():
    from fusion.engine import compute_trust_score
    return compute_trust_score


class TrustAdapter:
    def __init__(self, settings: config.Settings, live_fn: Optional[Callable[[], dict]] = None):
        self.settings = settings
        self._live_fn = live_fn
        self._cache: Optional[dict] = None
        self._cache_at = 0.0
        self._lock = threading.Lock()
        self._fingerprints: Dict[str, tuple] = {}
        self.live_available = True
        self.last_live_error: Optional[str] = None

    # -- simulation -------------------------------------------------------
    def simulated(self, events: List[SecurityEvent], now: Optional[datetime] = None) -> dict:
        now = now or utcnow()
        horizon = now - timedelta(seconds=self.settings.trust_sim_window_sec)
        penalty = {m: 0.0 for m in config.SIM_TRUST_BASELINE}
        seen: Dict[str, List[str]] = {m: [] for m in penalty}
        for e in events:
            if not e.is_signal or e.timestamp < horizon:
                continue
            module = config.SIM_TRUST_MODULE_MAP.get(e.source)
            if module is None:
                continue
            p = config.SIM_TRUST_PENALTY.get(e.base_severity, 0)
            for m in penalty:
                penalty[m] += p if m == module else p * config.SIM_TRUST_SPILLOVER
            seen[module].append(f"{e.event_type} ({e.source})")

        weights = _weights()
        subs = {}
        for m, base in config.SIM_TRUST_BASELINE.items():
            score = max(0, min(100, round(base - penalty[m])))
            flags = [f"Simulated signal: {s}" for s in seen[m][:5]] or ["Simulated: no issues detected"]
            subs[m] = {"module": m, "score": score, "flags": flags, "raw_features": {"simulated": True}}
        return self._assemble(subs, weights, "simulated")

    # -- live -------------------------------------------------------------
    def refresh_live(self) -> dict:
        """Run the real collectors (slow: BLE scan). Falls back cleanly on failure."""
        try:
            fn = self._live_fn or _default_live_fn()
            result = dict(fn())
            self.live_available, self.last_live_error = True, None
            result["data_source"] = "live"
        except Exception as exc:                    # netsh/powershell missing, permissions, etc.
            log.warning("live trust collectors unavailable: %s", exc)
            self.live_available, self.last_live_error = False, f"{type(exc).__name__}: {exc}"
            result = self.simulated([])
            result["data_source"] = "simulated_fallback"
        with self._lock:
            self._cache, self._cache_at = result, time.monotonic()
        return result

    def live(self, max_age: Optional[float] = None) -> dict:
        max_age = self.settings.live_cache_ttl_sec if max_age is None else max_age
        with self._lock:
            fresh = self._cache is not None and (time.monotonic() - self._cache_at) <= max_age
            cached = self._cache
        return cached if fresh else self.refresh_live()

    def cached_live(self) -> Optional[dict]:
        with self._lock:
            return self._cache

    # -- trust -> SOC signals ---------------------------------------------
    def signals_from_trust(self, trust: dict) -> List[dict]:
        """Raw SOC events for Wi-Fi/USB/Bluetooth sub-scores below the threshold.
        Emits only when a module's state changes, so polling never floods the log."""
        raws = []
        for module, sub in trust.get("sub_scores", {}).items():
            score, flags = sub.get("score", 100), list(sub.get("flags", []))
            fp = (score, tuple(flags))
            if score >= self.settings.trust_event_threshold:
                self._fingerprints.pop(module, None)
                continue
            if self._fingerprints.get(module) == fp:
                continue
            self._fingerprints[module] = fp
            severity = "high" if score < 40 else "medium" if score < 60 else "low"
            raws.append(make_raw_event(module, self._event_type(module, score, flags),
                                       self.settings.local_host, None, None, severity, None,
                                       {"trust_subscore": score, "flags": "; ".join(flags)[:280]}))
        return raws

    def snapshot_events(self, trust: dict) -> List[dict]:
        """One informational 'trust_check' event per module per scan. They are context, not
        signals: they keep the live event feed alive without creating incidents."""
        raws = []
        for module, sub in trust.get("sub_scores", {}).items():
            flags = "; ".join(sub.get("flags", []))[:280] or "no flags"
            raws.append(make_raw_event(module, "trust_check", self.settings.local_host, None, None,
                                       "info", None, {"trust_subscore": sub.get("score"), "flags": flags,
                                                      "data_source": trust.get("data_source", "live")}))
        return raws

    @staticmethod
    def _event_type(module: str, score: float, flags: List[str]) -> str:
        text = " ".join(flags).lower()
        if module == "wifi":
            if "evil twin" in text or "multiple access points" in text:
                return "suspicious_access_point"
            if any(k in text for k in ("encryption", "open network", "wep", "wpa")):
                return "weak_security"
            return "network_anomaly"
        if module == "usb":
            return "suspicious_usb" if score < 50 else "unknown_usb"
        return "suspicious_device" if score < 50 else "unknown_device"

    def reset(self):
        self._fingerprints.clear()

    # -- shared -----------------------------------------------------------
    @staticmethod
    def _assemble(subs: dict, weights: dict, source: str) -> dict:
        final = round(sum(subs[m]["score"] * weights[m] for m in subs), 1)
        ranked = sorted(({"module": m, "score": s["score"], "weight": weights[m], "flags": s["flags"]}
                         for m, s in subs.items()), key=lambda x: x["score"])
        return {"final_score": final, "status": _status(final), "sub_scores": subs,
                "contributions_ranked": ranked, "data_source": source}
