"""soc.incident_manager - incident storage (SQLite) and status rules. No scoring logic here."""

import json
import logging
import os
import sqlite3
import threading
from datetime import datetime
from typing import Dict, List, Optional

from .models import ACTIVE_STATUSES, INCIDENT_STATUSES, TERMINAL_STATUSES, parse_iso

log = logging.getLogger("soc.incidents")

ALLOWED_TRANSITIONS = {
    "NEW": {"PENDING", "ASSIGNED", "RESOLVED", "FALSE_POSITIVE"},
    "PENDING": {"NEW", "ASSIGNED", "RESOLVED", "FALSE_POSITIVE"},
    "ASSIGNED": {"PENDING", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"},
    "INVESTIGATING": {"PENDING", "RESOLVED", "FALSE_POSITIVE"},
    "RESOLVED": set(),
    "FALSE_POSITIVE": set(),
}


class IncidentNotFound(KeyError):
    pass


class InvalidTransition(ValueError):
    pass


class IncidentManager:
    def __init__(self, db_path: str = ":memory:"):
        if db_path != ":memory:":
            folder = os.path.dirname(os.path.abspath(db_path))
            os.makedirs(folder, exist_ok=True)
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.RLock()
        with self._lock:
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS incidents ("
                "incident_id TEXT PRIMARY KEY, seq INTEGER, status TEXT, host TEXT, "
                "created_at TEXT, data TEXT)")
            self._db.commit()

    # -- CRUD -------------------------------------------------------------
    def create(self, fields: dict) -> dict:
        with self._lock:
            row = self._db.execute("SELECT COALESCE(MAX(seq), 0) FROM incidents").fetchone()
            seq = row[0] + 1
            incident = dict(fields)
            incident["incident_id"] = f"INC-{seq:03d}"
            incident.setdefault("status", "NEW")
            incident.setdefault("assigned_analyst", None)
            self._db.execute(
                "INSERT INTO incidents (incident_id, seq, status, host, created_at, data) VALUES (?,?,?,?,?,?)",
                (incident["incident_id"], seq, incident["status"], incident.get("host"),
                 incident.get("created_at"), json.dumps(incident)))
            self._db.commit()
            return incident

    def get(self, incident_id: str) -> dict:
        with self._lock:
            row = self._db.execute("SELECT data FROM incidents WHERE incident_id = ?",
                                   (incident_id,)).fetchone()
        if row is None:
            raise IncidentNotFound(incident_id)
        return json.loads(row[0])

    def list(self, statuses=None) -> List[dict]:
        with self._lock:
            rows = self._db.execute("SELECT data FROM incidents ORDER BY seq").fetchall()
        items = [json.loads(r[0]) for r in rows]
        if statuses:
            wanted = set(statuses)
            items = [i for i in items if i["status"] in wanted]
        return items

    def active(self) -> List[dict]:
        return self.list(ACTIVE_STATUSES)

    def update(self, incident_id: str, **fields) -> dict:
        with self._lock:
            incident = self.get(incident_id)
            incident.update(fields)
            self._db.execute("UPDATE incidents SET status = ?, host = ?, data = ? WHERE incident_id = ?",
                             (incident["status"], incident.get("host"), json.dumps(incident), incident_id))
            self._db.commit()
            return incident

    def set_status(self, incident_id: str, new_status: str, **fields) -> dict:
        if new_status not in INCIDENT_STATUSES:
            raise InvalidTransition(f"unknown status '{new_status}'")
        with self._lock:
            current = self.get(incident_id)["status"]
            if new_status != current and new_status not in ALLOWED_TRANSITIONS[current]:
                raise InvalidTransition(f"cannot move incident from {current} to {new_status}")
            return self.update(incident_id, status=new_status, **fields)

    def clear(self):
        with self._lock:
            self._db.execute("DELETE FROM incidents")
            self._db.commit()

    # -- lookup used by the pipeline -------------------------------------
    def find_open_match(self, host: str, source_ip: Optional[str], event_time: datetime,
                        window_sec: int) -> Optional[dict]:
        """Open incident on the same host / source IP whose latest event is within the window."""
        best = None
        for inc in self.active():
            same = inc["host"] == host or (source_ip and inc.get("source_ip") == source_ip)
            if not same:
                continue
            try:
                gap = abs((event_time - parse_iso(inc["last_event_at"])).total_seconds())
            except (KeyError, ValueError):
                continue
            if gap <= window_sec and (best is None or inc["incident_id"] < best["incident_id"]):
                best = inc
        return best

    def statistics(self) -> dict:
        items = self.list()
        active = [i for i in items if i["status"] in ACTIVE_STATUSES]
        by_status: Dict[str, int] = {s: 0 for s in INCIDENT_STATUSES}
        for i in items:
            by_status[i["status"]] += 1
        by_sev = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
        for i in active:
            by_sev[i["severity"]] = by_sev.get(i["severity"], 0) + 1
        return {"total": len(items), "active": len(active), "by_severity": by_sev,
                "by_status": by_status, "terminal": sum(by_status[s] for s in TERMINAL_STATUSES)}
