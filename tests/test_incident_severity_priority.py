import pytest

from conftest import T0, make_incident
from soc import priority_engine, response_engine, severity_engine
from soc.incident_manager import IncidentManager, IncidentNotFound, InvalidTransition
from soc.models import to_iso
from datetime import timedelta


def E(etype, source, sev="medium"):
    return {"event_id": etype + source, "event_type": etype, "source": source, "base_severity": sev}


# ---- incident manager ------------------------------------------------------
def test_ids_increment_and_defaults(mgr):
    a, b = make_incident(mgr), make_incident(mgr)
    assert (a["incident_id"], b["incident_id"]) == ("INC-001", "INC-002")
    assert a["status"] == "NEW" and a["assigned_analyst"] is None


def test_status_transitions(mgr):
    inc = make_incident(mgr)["incident_id"]
    mgr.set_status(inc, "ASSIGNED")
    mgr.set_status(inc, "INVESTIGATING")
    mgr.set_status(inc, "RESOLVED")
    with pytest.raises(InvalidTransition):
        mgr.set_status(inc, "NEW")
    with pytest.raises(InvalidTransition):
        mgr.set_status(inc, "BOGUS")
    with pytest.raises(IncidentNotFound):
        mgr.get("INC-999")


def test_statistics(mgr):
    make_incident(mgr, severity="CRITICAL")
    make_incident(mgr, severity="LOW")
    r = make_incident(mgr)
    mgr.set_status(r["incident_id"], "RESOLVED")
    s = mgr.statistics()
    assert s["total"] == 3 and s["active"] == 2 and s["by_severity"]["CRITICAL"] == 1 and s["terminal"] == 1


def test_find_open_match_respects_window_and_terminal(mgr):
    inc = make_incident(mgr)
    assert mgr.find_open_match("HOST-01", None, T0 + timedelta(seconds=100), 300)
    assert mgr.find_open_match("HOST-09", "192.168.1.20", T0, 300)          # same source ip
    assert mgr.find_open_match("HOST-09", "10.0.0.1", T0, 300) is None
    assert mgr.find_open_match("HOST-01", None, T0 + timedelta(seconds=900), 300) is None
    mgr.set_status(inc["incident_id"], "FALSE_POSITIVE")
    assert mgr.find_open_match("HOST-01", None, T0, 300) is None


def test_sqlite_persistence(tmp_path):
    path = str(tmp_path / "soc.db")
    IncidentManager(path).create({"title": "x", "host": "H", "created_at": to_iso(T0)})
    assert IncidentManager(path).get("INC-001")["title"] == "x"


# ---- severity --------------------------------------------------------------
def test_threshold_boundaries():
    lf = severity_engine.label_for
    assert [lf(0), lf(25), lf(26), lf(50), lf(51), lf(75), lf(76), lf(100)] == \
           ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL"]


def test_score_is_sum_of_explained_lines():
    events = [E("port_scan", "network"), E("failed_login", "authentication", "low"),
              E("failed_login", "authentication", "low")]
    r = severity_engine.score_incident(events, [], None)
    assert r["score"] == sum(b["points"] for b in r["breakdown"]) == 20 + 10 + 2 + 5
    assert "+20 Port scanning" in r["explanation"] and "WHY" in r["explanation"]


def test_single_failed_login_scores_less_than_multiple():
    one = severity_engine.score_incident([E("failed_login", "authentication", "low")], [], None)["score"]
    two = severity_engine.score_incident([E("failed_login", "authentication", "low")] * 2, [], None)["score"]
    assert one == 5 and two > 10


def test_score_capped_at_100_and_trust_is_context_only():
    events = [E(t, s) for t, s in [("port_scan", "network"), ("failed_login", "authentication"),
                                   ("traffic_spike", "network"), ("unknown_usb", "usb"),
                                   ("suspicious_process", "endpoint")]]
    rules = [{"name": "Possible Coordinated Intrusion", "id": "R3", "rank": 60, "severity_bonus": 10}]
    low_trust = severity_engine.score_incident(events, rules, 20)
    high_trust = severity_engine.score_incident(events, rules, 95)
    assert low_trust["score"] == 100 and "capped" in low_trust["explanation"]
    assert low_trust["raw_total"] > high_trust["raw_total"]                    # small context bonus only
    assert any(b["label"] == "Low environment trust" for b in low_trust["breakdown"])
    assert not any(b["label"] == "Low environment trust" for b in high_trust["breakdown"])


def test_unknown_event_type_uses_base_severity_points():
    r = severity_engine.score_incident([E("brand_new_type", "system", "high")], [], None)
    assert r["score"] == 15


# ---- priority --------------------------------------------------------------
def prio(mgr, **kw):
    return priority_engine.score_incident(make_incident(mgr, **kw), T0)


def test_priority_uses_more_than_severity(mgr):
    base = prio(mgr, severity_score=60, confidence=0.5)["priority_score"]
    assert prio(mgr, severity_score=60, confidence=0.95)["priority_score"] > base
    assert prio(mgr, severity_score=60, confidence=0.5, host="DC-01")["priority_score"] > base
    assert prio(mgr, severity_score=90, confidence=0.5, severity="CRITICAL")["priority_score"] > base


def test_priority_grows_with_age_sla(mgr):
    inc = make_incident(mgr, severity="CRITICAL", severity_score=90)
    young = priority_engine.score_incident(inc, T0)
    old = priority_engine.score_incident(inc, T0 + timedelta(hours=2))
    assert old["priority_score"] > young["priority_score"] and "SLA at risk" in old["priority_reason"]


def test_priority_reason_and_ranking(mgr):
    a = make_incident(mgr, severity_score=95, severity="CRITICAL", confidence=0.95, n_events=4)
    b = make_incident(mgr, severity_score=30, severity="MEDIUM", confidence=0.6)
    for i in (a, b):
        i.update(priority_engine.score_incident(i, T0))
    assert "Critical severity" in a["priority_reason"] and "high confidence" in a["priority_reason"]
    ranks = priority_engine.rank([a, b])
    assert ranks[a["incident_id"]] == 1 and ranks[b["incident_id"]] == 2


# ---- response --------------------------------------------------------------
@pytest.mark.parametrize("itype,expected", [
    ("credential_attack", "Review authentication logs"),
    ("network_reconnaissance", "Review scan sources"),
    ("endpoint_compromise", "Investigate the suspicious process"),
    ("coordinated_intrusion", "Consider network containment"),
])
def test_recommendations_per_type(itype, expected):
    actions = response_engine.recommend({"type": itype, "host": "HOST-01", "source_ip": "192.168.1.20",
                                         "severity": "HIGH"})
    assert any(expected in a for a in actions) and len(actions) == len(set(actions))
    assert any("HOST-01" in a for a in actions)


def test_critical_escalates_and_unknown_type_has_fallback():
    assert any("Escalate" in a for a in response_engine.recommend({"type": "credential_attack", "severity": "CRITICAL"}))
    assert response_engine.recommend({"type": "mystery", "severity": "LOW"})


def test_response_engine_only_returns_text():
    import soc.response_engine as r
    src = open(r.__file__).read()
    assert "subprocess" not in src and "os.system" not in src
    assert all(isinstance(a, str) for a in response_engine.recommend({"type": "credential_attack"}))
