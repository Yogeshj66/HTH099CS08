from datetime import datetime, timedelta, timezone

from soc.correlation_engine import CorrelationEngine
from soc.models import SecurityEvent

T0 = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)
_n = [0]


def ev(source, etype, t=0, host="HOST-01", src="192.168.1.20", sev="medium", **meta):
    _n[0] += 1
    return SecurityEvent(f"E{_n[0]}", T0 + timedelta(seconds=t), source, etype, host, src, None, sev, meta)


def run(events, engine=None):
    engine = engine or CorrelationEngine()
    result = None
    for e in events:
        result = engine.ingest(e)
    return result


def ids(corr):
    return {r["id"] for r in corr.matched_rules}


def test_single_weak_signal_creates_nothing():
    assert run([ev("authentication", "failed_login", sev="low")]) is None


def test_rule1_three_failed_logins():
    c = run([ev("authentication", "failed_login", t, sev="low") for t in (0, 60, 120)])
    assert c.primary_rule["id"] == "R1" and len(c.events) == 3


def test_two_failed_logins_not_enough():
    assert run([ev("authentication", "failed_login", t, sev="low") for t in (0, 60)]) is None


def test_rule2_port_scan_plus_failed_login():
    c = run([ev("network", "port_scan"), ev("authentication", "failed_login", 10, sev="low")])
    assert c.primary_rule["id"] == "R2"


def test_rule3_coordinated_intrusion():
    c = run([ev("network", "port_scan"), ev("authentication", "failed_login", 10, sev="low"),
             ev("network", "traffic_spike", 20)])
    assert c.primary_rule["id"] == "R3" and {"R2", "R3"} <= ids(c)


def test_rule4_and_rule5_endpoint():
    c4 = run([ev("usb", "unknown_usb", src=None), ev("endpoint", "suspicious_process", 5, src=None, sev="high")])
    assert c4.primary_rule["id"] == "R4"
    c5 = run([ev("usb", "unknown_usb", src=None), ev("endpoint", "suspicious_process", 5, src=None, sev="high"),
              ev("network", "traffic_spike", 9, src=None)])
    assert c5.primary_rule["id"] == "R5"


def test_rule6_composite_needs_three_sources():
    two = run([ev("firewall", "blocked_connection", sev="low", src=None),
               ev("wifi", "weak_security", 5, sev="low", src=None),
               ev("wifi", "network_anomaly", 6, src=None)])
    assert two is None or "R6" not in ids(two)
    three = run([ev("firewall", "blocked_connection", sev="low", src=None),
                 ev("wifi", "weak_security", 5, sev="low", src=None),
                 ev("bluetooth", "suspicious_device", 6, src=None)])
    assert "R6" in ids(three)                               # (R8 also fires: wifi + bluetooth)


def test_unrelated_events_do_not_correlate():
    c = run([ev("network", "port_scan", host="HOST-01", src="192.168.1.20"),
             ev("authentication", "failed_login", 5, host="HOST-02", src="192.168.1.99", sev="low")])
    assert c is None


def test_same_source_ip_links_different_hosts():
    c = run([ev("network", "port_scan", host="HOST-01"),
             ev("authentication", "failed_login", 5, host="HOST-02", sev="low")])
    assert c is not None and c.primary_rule["id"] == "R2"


def test_events_outside_time_window_do_not_correlate():
    assert run([ev("network", "port_scan", 0), ev("authentication", "failed_login", 301, sev="low")]) is None
    assert run([ev("network", "port_scan", 0), ev("authentication", "failed_login", 300, sev="low")]) is not None


def test_duplicates_are_ignored():
    engine = CorrelationEngine()
    a = ev("network", "port_scan")
    assert engine.register(a) is True
    assert engine.register(a) is False                      # same event id
    twin = SecurityEvent("OTHER-ID", a.timestamp, a.source, a.event_type, a.host, a.src_ip, None, a.base_severity, {})
    assert engine.register(twin) is False                   # identical content
    assert engine.duplicates == 2


def test_duplicate_does_not_inflate_counts():
    engine = CorrelationEngine()
    e = ev("authentication", "failed_login", sev="low")
    for _ in range(5):
        engine.ingest(e)
    assert engine.ingest(ev("authentication", "failed_login", 1, sev="low")) is None      # only 2 unique


def test_info_events_are_context_not_signals():
    engine = CorrelationEngine()
    for t in range(5):
        assert engine.ingest(ev("authentication", "successful_login", t, sev="info")) is None


def test_confidence_grows_with_more_evidence():
    small = run([ev("network", "port_scan"), ev("authentication", "failed_login", 10, sev="low")])
    big = run([ev("network", "port_scan"), ev("authentication", "failed_login", 10, sev="low"),
               ev("network", "traffic_spike", 20), ev("usb", "unknown_usb", 30, src=None),
               ev("endpoint", "suspicious_process", 40, src=None, sev="high")])
    assert big.confidence > small.confidence and big.confidence <= 0.99


def test_rules_are_configurable():
    rule = {"id": "X1", "name": "Custom", "incident_type": "custom", "description": "", "window_sec": 60,
            "rank": 1, "base_confidence": 0.5, "severity_bonus": 0,
            "all_of": [{"types": ["service_stopped"], "min_count": 2}]}
    engine = CorrelationEngine(rules=[rule])
    assert run([ev("system", "service_stopped", 0), ev("system", "service_stopped", 10)], engine).primary_rule["id"] == "X1"


def test_rule8_device_trust_needs_two_trust_sources():
    one = run([ev("wifi", "weak_security", 0, src=None, sev="low"), ev("wifi", "network_anomaly", 5, src=None)])
    assert one is None                                                        # same source twice: not enough
    two = run([ev("wifi", "weak_security", 0, src=None, sev="medium"), ev("usb", "suspicious_usb", 5, src=None, sev="high")])
    assert two.primary_rule["id"] == "R8" and two.primary_rule["incident_type"] == "device_trust_degradation"
    other = run([ev("network", "port_scan", src=None), ev("usb", "unknown_usb", 5, src=None)])
    assert other is None or "R8" not in ids(other)                            # non-trust sources ignored by R8
