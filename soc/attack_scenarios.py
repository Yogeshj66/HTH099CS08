"""soc.attack_scenarios - deterministic demo scenarios (same input => same incidents).

A scenario is a list of steps with a T+offset. Severity is never stored here:
the severity engine calculates it from the events.
"""

from datetime import datetime, timedelta
from typing import List, Optional

from .log_generator import make_raw_event

TARGET_HOST, TARGET_IP = "HOST-01", "192.168.1.10"
ATTACKER_IP = "192.168.1.20"
OTHER_HOST, OTHER_IP = "HOST-02", "192.168.1.50"


def _s(offset, source, etype, host=TARGET_HOST, src=None, dst=None, **details):
    return {"offset": offset, "source": source, "event_type": etype, "host": host,
            "src_ip": src, "dst_ip": dst, "details": details or None}


SCENARIOS = {
    "benign": {
        "title": "Normal Activity",
        "description": "Routine traffic plus one stray failed login. No incident should be raised.",
        "expected_incident_type": None,
        "steps": [
            _s(0, "authentication", "successful_login", OTHER_HOST, OTHER_IP, TARGET_IP, user="analyst1"),
            _s(10, "network", "routine_traffic", OTHER_HOST, OTHER_IP, TARGET_IP, mbps=40),
            _s(20, "authentication", "failed_login", OTHER_HOST, OTHER_IP, TARGET_IP, user="analyst1"),
            _s(30, "firewall", "allowed_connection", OTHER_HOST, OTHER_IP, "203.0.113.5"),
            _s(40, "system", "system_heartbeat", OTHER_HOST),
            _s(50, "endpoint", "process_started", OTHER_HOST, process="editor.exe"),
        ],
    },
    "credential_attack": {
        "title": "Credential Attack",
        "description": "Repeated failed logins and a brute-force burst against one host.",
        "expected_incident_type": "credential_attack",
        "steps": [
            _s(0, "authentication", "failed_login", TARGET_HOST, ATTACKER_IP, TARGET_IP, user="admin"),
            _s(10, "authentication", "failed_login", TARGET_HOST, ATTACKER_IP, TARGET_IP, user="admin"),
            _s(20, "authentication", "failed_login", TARGET_HOST, ATTACKER_IP, TARGET_IP, user="root"),
            _s(30, "authentication", "failed_login", TARGET_HOST, ATTACKER_IP, TARGET_IP, user="root"),
            _s(40, "authentication", "brute_force_attempt", TARGET_HOST, ATTACKER_IP, TARGET_IP, attempts=120),
            _s(50, "authentication", "successful_login", TARGET_HOST, ATTACKER_IP, TARGET_IP, user="guest"),
        ],
    },
    "network_recon": {
        "title": "Network Reconnaissance",
        "description": "Port scanning followed by probing of the same host.",
        "expected_incident_type": "network_reconnaissance",
        "steps": [
            _s(0, "network", "port_scan", TARGET_HOST, ATTACKER_IP, TARGET_IP, ports_probed=512),
            _s(10, "network", "port_scan", TARGET_HOST, ATTACKER_IP, TARGET_IP, ports_probed=1024),
            _s(20, "network", "unusual_connection", TARGET_HOST, ATTACKER_IP, TARGET_IP),
            _s(30, "network", "suspicious_dns", TARGET_HOST, ATTACKER_IP, TARGET_IP),
            _s(40, "firewall", "repeated_block", TARGET_HOST, ATTACKER_IP, TARGET_IP, blocks=25),
        ],
    },
    "endpoint_compromise": {
        "title": "Endpoint Compromise",
        "description": "Unknown USB, suspicious process, privilege change, then odd DNS from the host.",
        "expected_incident_type": "endpoint_compromise_high_confidence",
        "steps": [
            _s(0, "usb", "unknown_usb", TARGET_HOST, None, None, vendor_id="FFFF"),
            _s(10, "endpoint", "suspicious_process", TARGET_HOST, None, None, process="unknown_tool.exe"),
            _s(20, "endpoint", "privilege_change", TARGET_HOST, None, None, user="guest"),
            _s(30, "network", "suspicious_dns", TARGET_HOST, TARGET_IP, "203.0.113.77"),
        ],
    },
    "coordinated_intrusion": {
        "title": "Coordinated Intrusion",
        "description": "Recon, credential guessing, traffic spike, then endpoint compromise: one composite incident.",
        "expected_incident_type": "coordinated_intrusion",
        "steps": [
            _s(0, "network", "port_scan", TARGET_HOST, ATTACKER_IP, TARGET_IP, ports_probed=800),
            _s(10, "authentication", "failed_login", TARGET_HOST, ATTACKER_IP, TARGET_IP, user="admin"),
            _s(20, "authentication", "failed_login", TARGET_HOST, ATTACKER_IP, TARGET_IP, user="root"),
            _s(30, "network", "traffic_spike", TARGET_HOST, ATTACKER_IP, TARGET_IP, mbps=850),
            _s(40, "usb", "unknown_usb", TARGET_HOST, None, None, vendor_id="FFFF"),
            _s(50, "endpoint", "suspicious_process", TARGET_HOST, None, None, process="unknown_tool.exe"),
        ],
    },
}

# "random" is not deterministic: the runtime drives it with the LogGenerator.
RANDOM_SCENARIO = "random"
SCENARIO_NAMES = tuple(SCENARIOS) + (RANDOM_SCENARIO,)


def list_scenarios() -> List[dict]:
    out = [{"name": n, "title": s["title"], "description": s["description"], "steps": len(s["steps"])}
           for n, s in SCENARIOS.items()]
    out.append({"name": RANDOM_SCENARIO, "title": "Random Simulation",
                "description": "Endless random normal and suspicious events.", "steps": None})
    return out


def scenario_steps(name: str) -> List[dict]:
    if name not in SCENARIOS:
        raise KeyError(name)
    return SCENARIOS[name]["steps"]


def build_scenario_events(name: str, base_time: Optional[datetime] = None) -> List[dict]:
    """Raw events for a scenario. With base_time each event gets base_time + offset
    (deterministic replay); without it timestamps are left for the normalizer to stamp."""
    raws = []
    for step in scenario_steps(name):
        ts = base_time + timedelta(seconds=step["offset"]) if base_time else None
        raws.append(make_raw_event(step["source"], step["event_type"], step["host"], step["src_ip"],
                                   step["dst_ip"], None, ts, step["details"]))
    return raws
