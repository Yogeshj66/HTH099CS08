from datetime import datetime, timezone

from soc import config
from soc.event_normalizer import EventNormalizer, normalize_severity, parse_timestamp
from soc.log_generator import LogGenerator, make_raw_event

SPEC_TYPES = {
    "authentication": {"failed_login", "successful_login", "brute_force_attempt"},
    "network": {"port_scan", "unusual_connection", "traffic_spike", "suspicious_dns"},
    "firewall": {"blocked_connection", "repeated_block", "suspicious_destination"},
    "endpoint": {"suspicious_process", "privilege_change", "unknown_device"},
    "usb": {"unknown_usb", "suspicious_usb"},
    "wifi": {"weak_security", "suspicious_access_point", "network_anomaly"},
    "bluetooth": {"unknown_device", "suspicious_device", "unusual_connection"},
}


def test_catalog_covers_every_required_event_type():
    for source, types in SPEC_TYPES.items():
        assert types <= set(config.EVENT_CATALOG[source])


def test_generator_is_deterministic_with_seed():
    a = list(LogGenerator(seed=7).stream(20))
    b = list(LogGenerator(seed=7).stream(20))
    assert a == b


def test_normal_events_are_not_signals_and_suspicious_are():
    g, n = LogGenerator(seed=1), EventNormalizer()
    assert all(not n.normalize(g.normal_event()).is_signal for _ in range(30))
    assert all(n.normalize(g.suspicious_event()).is_signal for _ in range(30))


def test_event_rate_is_configurable():
    assert LogGenerator(rate=4).interval() == 0.25
    assert LogGenerator(rate=0.5).interval() == 2.0


def test_random_mode_mixes_ratio():
    g, n = LogGenerator(seed=3), EventNormalizer()
    events = [n.normalize(e) for e in g.stream(400, suspicious_ratio=0.5)]
    share = sum(e.is_signal for e in events) / len(events)
    assert 0.35 < share < 0.65


def test_all_generated_events_normalize():
    g, n = LogGenerator(seed=5), EventNormalizer()
    for raw in g.stream(200, 0.5):
        assert n.normalize(raw) is not None
    assert n.rejected == 0


# ---- normalizer -----------------------------------------------------------
def test_normalizes_vendor_keys_to_common_schema():
    n = EventNormalizer()
    e = n.normalize(make_raw_event("network", "port_scan", "host-01", "192.168.1.20", "192.168.1.10",
                                   None, datetime(2026, 9, 24, 12, 30, 10, tzinfo=timezone.utc)))
    d = e.to_dict()
    assert d["event_id"] == "EVT-001" and d["timestamp"] == "2026-09-24T12:30:10Z"
    assert d["host"] == "HOST-01" and d["base_severity"] == "medium"
    assert set(d) == {"event_id", "timestamp", "source", "event_type", "host", "src_ip", "dst_ip",
                      "base_severity", "metadata"}


def test_missing_values_get_safe_defaults():
    n = EventNormalizer(clock=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc))
    e = n.normalize({"type": "failed login", "source": "AUTH"})
    assert e.source == "authentication" and e.event_type == "failed_login"
    assert e.host == config.DEFAULT_HOST and e.timestamp.year == 2026
    assert e.base_severity == "low"
    assert "missing host" in e.metadata["normalization_warnings"]


def test_source_inferred_from_unique_event_type():
    assert EventNormalizer().normalize({"event": "port_scan"}).source == "network"


def test_ambiguous_source_is_rejected():
    n = EventNormalizer()
    assert n.normalize({"event": "unusual_connection"}) is None     # network or bluetooth
    assert n.rejected == 1


def test_malformed_events_never_raise():
    n = EventNormalizer()
    for bad in [None, 42, "text", [], {}, {"event": ""}, {"event": "???"}, {"event": "x", "source": "nope"}]:
        assert n.normalize(bad) is None
    assert n.rejected == 8 and n.last_error


def test_invalid_timestamp_ip_and_severity_are_repaired():
    n = EventNormalizer()
    e = n.normalize({"event": "port_scan", "ts": "not-a-date", "src": "999.1.1.1", "severity": "banana"})
    w = e.metadata["normalization_warnings"]
    assert e.src_ip is None and e.base_severity == "medium"
    assert any("timestamp" in x for x in w) and any("src_ip" in x for x in w) and any("severity" in x for x in w)


def test_timestamp_formats():
    assert parse_timestamp(1_700_000_000).year == 2023
    assert parse_timestamp(1_700_000_000_000).year == 2023           # milliseconds
    assert parse_timestamp("2026-09-24T12:30:10Z").hour == 12
    assert parse_timestamp("2026-09-24T12:30:10").tzinfo is not None
    assert parse_timestamp("2026-09-24T18:00:00+05:30").hour == 12


def test_severity_normalization():
    assert normalize_severity("WARN") == "medium" and normalize_severity("Crit") == "critical"
    assert normalize_severity(9) == "critical" and normalize_severity(0) == "info"
    assert normalize_severity("weird") is None and normalize_severity(None) is None


def test_metadata_is_sanitized():
    n = EventNormalizer()
    e = n.normalize({"event": "port_scan", "details": {"a": "x" * 5000, "b": {"n": 1}, "c": 3}})
    assert len(e.metadata["a"]) == 300 and isinstance(e.metadata["b"], str) and e.metadata["c"] == 3
