"""soc.analyst_queue - capacity-limited assignment of incidents to analysts.

Policy (deterministic):
  * INVESTIGATING incidents keep their analyst (never pre-empted).
  * Remaining free slots go to the highest-priority NEW/PENDING/ASSIGNED incidents.
  * Everything else waits as PENDING. Active assignments never exceed capacity.
The queue is re-balanced on: new/updated incident, acknowledge, resolve,
false positive, capacity change.
"""

import threading
from datetime import datetime
from typing import Callable, List

from . import priority_engine
from .incident_manager import IncidentManager, InvalidTransition
from .models import ACTIVE_STATUSES, to_iso, utcnow


class AnalystQueue:
    def __init__(self, manager: IncidentManager, capacity: int = 3,
                 clock: Callable[[], datetime] = utcnow):
        self.manager = manager
        self.capacity = max(1, int(capacity))
        self._clock = clock
        self._lock = threading.RLock()

    @property
    def analyst_names(self) -> List[str]:
        return [f"Analyst {n}" for n in range(1, self.capacity + 1)]

    def set_capacity(self, capacity: int):
        with self._lock:
            self.capacity = max(1, int(capacity))
            self.rebalance()

    # -- core -------------------------------------------------------------
    def rebalance(self) -> None:
        with self._lock:
            now = self._clock()
            incidents = self.manager.active()
            for inc in incidents:
                inc.update(priority_engine.score_incident(inc, now))
            ranks = priority_engine.rank(incidents)
            for inc in incidents:
                inc["priority_rank"] = ranks[inc["incident_id"]]
            incidents.sort(key=lambda i: i["priority_rank"])

            names = set(self.analyst_names)
            pinned = [i for i in incidents if i["status"] == "INVESTIGATING"][: self.capacity]
            pinned_ids = {i["incident_id"] for i in pinned}
            used = {i["assigned_analyst"] for i in pinned if i["assigned_analyst"] in names}
            waiting_pool = [i for i in incidents if i["incident_id"] not in pinned_ids]
            free_slots = self.capacity - len(pinned)
            chosen = waiting_pool[:free_slots]
            chosen_ids = {i["incident_id"] for i in chosen}

            desired = {}
            for inc in pinned:
                desired[inc["incident_id"]] = ("INVESTIGATING", inc["assigned_analyst"] if inc["assigned_analyst"] in names
                                               else self._free_name(used))
                used.add(desired[inc["incident_id"]][1])
            for inc in chosen:                                   # keep an existing valid analyst
                if inc["status"] == "ASSIGNED" and inc["assigned_analyst"] in names \
                        and inc["assigned_analyst"] not in used:
                    used.add(inc["assigned_analyst"])
                    desired[inc["incident_id"]] = ("ASSIGNED", inc["assigned_analyst"])
            for inc in chosen:
                if inc["incident_id"] not in desired:
                    name = self._free_name(used)
                    used.add(name)
                    desired[inc["incident_id"]] = ("ASSIGNED", name)
            for inc in waiting_pool:
                if inc["incident_id"] not in chosen_ids:
                    desired[inc["incident_id"]] = ("PENDING", None)
            for inc in incidents:                                # demoted pinned overflow
                desired.setdefault(inc["incident_id"], ("PENDING", None))

            for inc in incidents:
                status, analyst = desired[inc["incident_id"]]
                fields = {k: inc[k] for k in ("priority_score", "priority_reason", "priority_factors",
                                              "priority_rank")}
                fields["assigned_analyst"] = analyst
                if status != inc["status"]:
                    self.manager.set_status(inc["incident_id"], status, **fields)
                else:
                    self.manager.update(inc["incident_id"], **fields)

    def _free_name(self, used) -> str:
        for name in self.analyst_names:
            if name not in used:
                return name
        raise RuntimeError("no free analyst slot")            # unreachable: capacity is enforced above

    # -- analyst actions --------------------------------------------------
    def acknowledge(self, incident_id: str) -> dict:
        with self._lock:
            inc = self.manager.get(incident_id)
            if inc["status"] != "ASSIGNED":
                raise InvalidTransition(
                    f"cannot acknowledge an incident in status {inc['status']}; it must be ASSIGNED to an analyst")
            self.manager.set_status(incident_id, "INVESTIGATING", acknowledged_at=to_iso(self._clock()))
            self.rebalance()
            return self.manager.get(incident_id)

    def resolve(self, incident_id: str) -> dict:
        return self._close(incident_id, "RESOLVED")

    def false_positive(self, incident_id: str) -> dict:
        return self._close(incident_id, "FALSE_POSITIVE")

    def _close(self, incident_id: str, status: str) -> dict:
        with self._lock:
            inc = self.manager.get(incident_id)
            if inc["status"] not in ACTIVE_STATUSES:
                raise InvalidTransition(f"incident is already {inc['status']}")
            self.manager.set_status(incident_id, status, closed_at=to_iso(self._clock()),
                                    closed_by=inc.get("assigned_analyst"), assigned_analyst=None,
                                    priority_rank=None)
            self.rebalance()
            return self.manager.get(incident_id)

    # -- views ------------------------------------------------------------
    def view(self) -> dict:
        with self._lock:
            self.rebalance()
            incidents = sorted(self.manager.active(), key=lambda i: i["priority_rank"])

            def brief(i):
                return {"rank": i["priority_rank"], "incident_id": i["incident_id"], "title": i["title"],
                        "severity": i["severity"], "severity_score": i["severity_score"],
                        "priority_score": i["priority_score"], "priority_reason": i["priority_reason"],
                        "assigned_analyst": i["assigned_analyst"], "status": i["status"], "host": i["host"]}

            by_analyst = {i["assigned_analyst"]: brief(i) for i in incidents if i["assigned_analyst"]}
            analysts = [{"analyst": n, "incident": by_analyst.get(n)} for n in self.analyst_names]
            active = [a for a in analysts if a["incident"]]
            return {"capacity": self.capacity, "active_count": len(active),
                    "available": self.capacity - len(active), "analysts": analysts,
                    "queue": [brief(i) for i in incidents],
                    "waiting": [brief(i) for i in incidents if i["status"] in ("PENDING", "NEW")]}
