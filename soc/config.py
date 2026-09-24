"""
soc.config - the ONE place for SOC tuning: settings, rules, scoring tables,
thresholds, playbooks. Nothing in the other soc modules hard-codes these.

Runtime settings can be overridden with environment variables (see load_settings).
"""

import os
from dataclasses import dataclass, asdict
from typing import Optional

MODES = ("simulation", "live")


# --------------------------------------------------------------------------
# Runtime settings
# --------------------------------------------------------------------------
@dataclass
class Settings:
    mode: str = "simulation"               # SOC_MODE: simulation | live
    analyst_capacity: int = 3              # SOC_ANALYST_CAPACITY
    correlation_window_sec: int = 300      # default rule window (5 min)
    db_path: str = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "soc_incidents.db")   # SOC_DB_PATH (":memory:" = no persistence)
    scenario_step_delay: float = 2.0       # seconds between scenario events (live demo pacing)
    sim_event_rate: float = 0.5            # random simulation: events per second
    sim_suspicious_ratio: float = 0.25     # random simulation: share of suspicious events
    sim_seed: Optional[int] = None         # SOC_SIM_SEED for reproducible random mode
    max_events: int = 1000                 # events kept in the live event log
    live_poll_sec: float = 15.0            # LIVE mode: how often to re-scan Wi-Fi/USB/BT
    live_cache_ttl_sec: float = 30.0       # LIVE mode: cache lifetime of the fused score
    local_host: str = "HOST-01"            # host name used for Wi-Fi/USB/BT trust signals
    trust_event_threshold: int = 70        # module sub-score below this becomes a signal
    trust_sim_window_sec: int = 900        # simulated trust looks back this far
    debug: bool = False                    # FLASK_DEBUG (default OFF: debugger = remote code exec)
    host: str = "127.0.0.1"                # SOC_HOST
    port: int = 5000                       # SOC_PORT

    def to_dict(self):
        return asdict(self)


def _int(env, key, default, lo, hi):
    try:
        return max(lo, min(hi, int(env.get(key, default))))
    except (TypeError, ValueError):
        return default


def _float(env, key, default, lo, hi):
    try:
        return max(lo, min(hi, float(env.get(key, default))))
    except (TypeError, ValueError):
        return default


def load_settings(env=None) -> Settings:
    env = os.environ if env is None else env
    s = Settings()
    mode = str(env.get("SOC_MODE", s.mode)).strip().lower()
    s.mode = mode if mode in MODES else "simulation"
    s.analyst_capacity = _int(env, "SOC_ANALYST_CAPACITY", s.analyst_capacity, 1, 20)
    s.db_path = env.get("SOC_DB_PATH", s.db_path)
    s.scenario_step_delay = _float(env, "SOC_SCENARIO_STEP_DELAY", s.scenario_step_delay, 0.0, 30.0)
    s.sim_event_rate = _float(env, "SOC_SIM_EVENT_RATE", s.sim_event_rate, 0.05, 20.0)
    seed = env.get("SOC_SIM_SEED")
    s.sim_seed = int(seed) if seed not in (None, "") and str(seed).lstrip("-").isdigit() else None
    s.debug = str(env.get("FLASK_DEBUG", "0")).lower() in ("1", "true", "yes")
    s.host = env.get("SOC_HOST", s.host)
    s.port = _int(env, "SOC_PORT", s.port, 1, 65535)
    return s


# --------------------------------------------------------------------------
# Event catalog: source -> event_type -> default base severity
# --------------------------------------------------------------------------
EVENT_CATALOG = {
    "authentication": {"failed_login": "low", "successful_login": "info", "brute_force_attempt": "high"},
    "network": {"port_scan": "medium", "unusual_connection": "medium",
                "traffic_spike": "medium", "suspicious_dns": "medium", "routine_traffic": "info"},
    "firewall": {"blocked_connection": "low", "repeated_block": "medium",
                 "suspicious_destination": "medium", "allowed_connection": "info"},
    "endpoint": {"suspicious_process": "high", "privilege_change": "high",
                 "unknown_device": "medium", "process_started": "info"},
    "system": {"service_stopped": "medium", "system_heartbeat": "info"},
    "usb": {"unknown_usb": "medium", "suspicious_usb": "high", "trust_check": "info"},
    "wifi": {"weak_security": "low", "suspicious_access_point": "high",
             "network_anomaly": "medium", "wifi_connected": "info", "trust_check": "info"},
    "bluetooth": {"unknown_device": "low", "suspicious_device": "medium", "unusual_connection": "medium",
                  "trust_check": "info"},
}

# Event types the generator emits as "normal" background noise: (source, event_type)
NORMAL_EVENTS = [
    ("authentication", "successful_login"),
    ("network", "routine_traffic"),
    ("firewall", "allowed_connection"),
    ("endpoint", "process_started"),
    ("system", "system_heartbeat"),
    ("wifi", "wifi_connected"),
]

SEVERITY_ALIASES = {
    "informational": "info", "information": "info", "notice": "info", "debug": "info", "none": "info",
    "minor": "low", "warn": "medium", "warning": "medium", "med": "medium", "moderate": "medium",
    "major": "high", "error": "high", "err": "high",
    "crit": "critical", "fatal": "critical", "emergency": "critical", "alert": "critical",
}

SOURCE_ALIASES = {
    "auth": "authentication", "authn": "authentication", "login": "authentication",
    "net": "network", "netflow": "network", "ids": "network",
    "fw": "firewall", "edr": "endpoint", "host": "endpoint",
    "os": "system", "syslog": "system", "sys": "system",
    "wi-fi": "wifi", "wi_fi": "wifi", "wlan": "wifi",
    "bt": "bluetooth", "ble": "bluetooth",
}

# Field-name aliases accepted by the normalizer (first present wins)
FIELD_ALIASES = {
    "event_id": ("event_id", "id", "uuid"),
    "timestamp": ("timestamp", "ts", "time", "@timestamp", "datetime"),
    "source": ("source", "category", "log_source", "channel"),
    "event_type": ("event_type", "event", "type", "action"),
    "host": ("host", "hostname", "device", "computer", "asset"),
    "src_ip": ("src_ip", "src", "source_ip", "client_ip"),
    "dst_ip": ("dst_ip", "dst", "dest_ip", "destination_ip"),
    "base_severity": ("base_severity", "severity", "level", "sev", "priority"),
    "metadata": ("metadata", "details", "extra", "data"),
}

DEFAULT_HOST = "UNKNOWN-HOST"


# --------------------------------------------------------------------------
# Correlation rules (data, not code). Edit here to change detection.
#   all_of      : every requirement needs >= min_count matching events
#                 (types, optional sources)
#   min_sources / min_events : generic "many weak signals" rule
#   rank        : which rule wins when several match (higher wins)
#   severity_bonus : points the severity engine adds for this pattern
# --------------------------------------------------------------------------
NETWORK_ANOMALY_TYPES = ["traffic_spike", "network_anomaly", "unusual_connection", "suspicious_dns"]
NETWORK_ANOMALY_SOURCES = ["network", "wifi"]

RULES = [
    {
        "id": "R1", "name": "Credential Attack Candidate", "incident_type": "credential_attack",
        "description": "3 or more failed logins within 5 minutes",
        "window_sec": 300, "rank": 20, "base_confidence": 0.65, "severity_bonus": 5,
        "all_of": [{"types": ["failed_login", "brute_force_attempt"], "min_count": 3}],
    },
    {
        "id": "R2", "name": "Possible Credential Attack", "incident_type": "possible_credential_attack",
        "description": "Port scan + failed login within 5 minutes",
        "window_sec": 300, "rank": 30, "base_confidence": 0.70, "severity_bonus": 5,
        "all_of": [{"types": ["port_scan"]}, {"types": ["failed_login", "brute_force_attempt"]}],
    },
    {
        "id": "R3", "name": "Possible Coordinated Intrusion", "incident_type": "coordinated_intrusion",
        "description": "Port scan + failed login + traffic spike within 5 minutes",
        "window_sec": 300, "rank": 60, "base_confidence": 0.85, "severity_bonus": 10,
        "all_of": [{"types": ["port_scan"]},
                   {"types": ["failed_login", "brute_force_attempt"]},
                   {"types": ["traffic_spike"]}],
    },
    {
        "id": "R4", "name": "Possible Endpoint Compromise", "incident_type": "endpoint_compromise",
        "description": "Unknown USB + suspicious process",
        "window_sec": 300, "rank": 40, "base_confidence": 0.75, "severity_bonus": 5,
        "all_of": [{"types": ["unknown_usb", "suspicious_usb"]}, {"types": ["suspicious_process"]}],
    },
    {
        "id": "R5", "name": "High-Confidence Endpoint Compromise",
        "incident_type": "endpoint_compromise_high_confidence",
        "description": "Unknown USB + suspicious process + network anomaly",
        "window_sec": 300, "rank": 55, "base_confidence": 0.90, "severity_bonus": 10,
        "all_of": [{"types": ["unknown_usb", "suspicious_usb"]},
                   {"types": ["suspicious_process"]},
                   {"types": NETWORK_ANOMALY_TYPES, "sources": NETWORK_ANOMALY_SOURCES}],
    },
    {
        "id": "R6", "name": "Composite Incident Candidate", "incident_type": "composite_incident",
        "description": "Multiple weak signals from different sources",
        "window_sec": 300, "rank": 10, "base_confidence": 0.55, "severity_bonus": 0,
        "min_sources": 3, "min_events": 3,
    },
    {
        "id": "R7", "name": "Network Reconnaissance", "incident_type": "network_reconnaissance",
        "description": "Port scan + another probing signal (odd connection, DNS, repeated block)",
        "window_sec": 300, "rank": 15, "base_confidence": 0.60, "severity_bonus": 0,
        "all_of": [{"types": ["port_scan"]},
                   {"types": ["unusual_connection", "suspicious_dns", "repeated_block",
                              "suspicious_destination"]}],
    },
    {
        "id": "R8", "name": "Device Trust Degradation", "incident_type": "device_trust_degradation",
        "description": "Wi-Fi, USB and/or Bluetooth trust signals degraded together (LIVE mode signals)",
        "window_sec": 600, "rank": 12, "base_confidence": 0.60, "severity_bonus": 0,
        "min_sources": 2, "min_events": 2, "sources": ["wifi", "usb", "bluetooth"],
    },
]

MAX_CONFIDENCE = 0.99
CONFIDENCE_PER_EXTRA_RULE = 0.03
CONFIDENCE_PER_EXTRA_SOURCE = 0.02


# --------------------------------------------------------------------------
# Severity scoring (0-100), fully table driven
# --------------------------------------------------------------------------
EVENT_LABELS = {
    "port_scan": "Port scanning", "failed_login": "Multiple failed logins",
    "brute_force_attempt": "Brute-force attempt", "traffic_spike": "Traffic anomaly",
    "unusual_connection": "Unusual connection", "suspicious_dns": "Suspicious DNS",
    "network_anomaly": "Network anomaly", "blocked_connection": "Blocked connection",
    "repeated_block": "Repeated firewall blocks", "suspicious_destination": "Suspicious destination",
    "unknown_usb": "Unknown USB", "suspicious_usb": "Suspicious USB",
    "suspicious_process": "Suspicious process", "privilege_change": "Privilege change",
    "unknown_device": "Unknown device", "weak_security": "Weak Wi-Fi security",
    "suspicious_access_point": "Suspicious access point", "suspicious_device": "Suspicious Bluetooth device",
    "service_stopped": "Service stopped",
}

EVENT_POINTS = {
    "port_scan": 20, "failed_login": 10, "brute_force_attempt": 25, "traffic_spike": 20,
    "unusual_connection": 10, "suspicious_dns": 10, "network_anomaly": 15,
    "blocked_connection": 3, "repeated_block": 8, "suspicious_destination": 12,
    "unknown_usb": 20, "suspicious_usb": 25, "suspicious_process": 20, "privilege_change": 20,
    "unknown_device": 8, "weak_security": 8, "suspicious_access_point": 20,
    "suspicious_device": 12, "service_stopped": 8,
}
# A lone occurrence counts for less than a repeated one
SINGLE_OCCURRENCE_POINTS = {"failed_login": 5}
# Fallback for event types missing from EVENT_POINTS: points by base severity
BASE_SEVERITY_POINTS = {"info": 0, "low": 3, "medium": 8, "high": 15, "critical": 25}

REPEAT_POINTS_PER_EXTRA = 2       # each extra occurrence of an already-counted type
REPEAT_POINTS_MAX = 10
CROSS_SOURCE_POINTS = {2: 5, 3: 8, 4: 10}   # distinct sources -> points (4+ uses the 4 value)

# Trust score is CONTEXT for severity (never summed with it): (trust < limit) -> points
TRUST_CONTEXT_POINTS = [(40, 10), (60, 5)]

# (upper bound inclusive, label)
SEVERITY_THRESHOLDS = [(25, "LOW"), (50, "MEDIUM"), (75, "HIGH"), (100, "CRITICAL")]


# --------------------------------------------------------------------------
# Priority scoring
# --------------------------------------------------------------------------
PRIORITY_WEIGHTS = {"severity": 0.45, "confidence": 0.20, "impact": 0.15, "volume": 0.10, "sla": 0.10}
HOST_CRITICALITY = {"HOST-01": 70, "HOST-02": 50, "HOST-03": 40, "HOST-04": 30, "DC-01": 100}
DEFAULT_HOST_CRITICALITY = 50
VOLUME_POINTS_PER_EVENT = 12      # 8+ correlated events saturates the volume factor
SLA_SECONDS = {"CRITICAL": 900, "HIGH": 3600, "MEDIUM": 14400, "LOW": 86400}


# --------------------------------------------------------------------------
# Simulated trust score (SIMULATION mode only; LIVE uses the real modules)
# --------------------------------------------------------------------------
SIM_TRUST_BASELINE = {"wifi": 88, "usb": 92, "bluetooth": 90}
# Which sub-score a simulated SOC event mainly degrades (illustrative)
SIM_TRUST_MODULE_MAP = {
    "wifi": "wifi", "network": "wifi", "firewall": "wifi",
    "usb": "usb", "endpoint": "usb", "system": "usb", "authentication": "usb",
    "bluetooth": "bluetooth",
}
SIM_TRUST_PENALTY = {"info": 0, "low": 6, "medium": 12, "high": 22, "critical": 32}
SIM_TRUST_SPILLOVER = 0.5        # share of an event's penalty applied to the other modules
TRUST_STATUS_THRESHOLDS = [(80, "Trusted"), (50, "Caution")]   # else "Untrusted" (same as fusion.engine)


# --------------------------------------------------------------------------
# Response playbooks - RECOMMENDATIONS ONLY, nothing is ever executed
# --------------------------------------------------------------------------
RESPONSE_PLAYBOOKS = {
    "credential_attack": [
        "Review authentication logs for {host}",
        "Investigate source IP {source_ip}",
        "Check which accounts were targeted",
        "Consider temporary account lockout for targeted accounts",
    ],
    "network_intrusion": [
        "Review network traffic to and from {host}",
        "Investigate source IP {source_ip}",
        "Review firewall events for {host}",
        "Consider network containment for {host}",
    ],
    "endpoint_compromise": [
        "Investigate the suspicious process on {host}",
        "Review recent device activity on {host} (USB, logins, privilege changes)",
        "Collect endpoint evidence from {host} before any cleanup",
        "Consider isolating {host} from the network",
    ],
    "reconnaissance": [
        "Review scan sources and targeted ports in firewall logs",
        "Investigate source IP {source_ip}",
        "Confirm exposed services on {host} are expected",
    ],
    "device_trust": [
        "Review the flagged Wi-Fi network, USB device or Bluetooth device on {host}",
        "Verify with the device owner before disconnecting or removing anything (manual step)",
        "Re-run the trust scan after changes and confirm the Trust Score recovers",
    ],
    "composite": [
        "Review all correlated events in the timeline for {host}",
        "Investigate source IP {source_ip}",
        "Decide which signal source (auth, network, endpoint) to triage first",
    ],
}
INCIDENT_TYPE_PLAYBOOKS = {
    "credential_attack": ["credential_attack"],
    "possible_credential_attack": ["credential_attack", "network_intrusion"],
    "coordinated_intrusion": ["network_intrusion", "credential_attack", "endpoint_compromise"],
    "endpoint_compromise": ["endpoint_compromise"],
    "endpoint_compromise_high_confidence": ["endpoint_compromise", "network_intrusion"],
    "network_reconnaissance": ["reconnaissance"],
    "composite_incident": ["composite"],
    "device_trust_degradation": ["device_trust"],
}
CRITICAL_EXTRA_ACTIONS = ["Escalate to a senior analyst / incident lead"]
RESPONSE_DISCLAIMER = ("Recommendations only. Nothing is executed automatically: no shutdowns, "
                       "file deletion, account changes or IP blocking.")
