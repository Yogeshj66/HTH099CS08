import pytest

from conftest import FakeClock, wait_until
from soc import attack_scenarios, config
from soc.runtime import ScenarioError, SocRuntime
from soc.trust_adapter import TrustAdapter


def fresh(clock=None):
    s = config.Settings(db_path=":memory:", scenario_step_delay=0.0)
    return SocRuntime(s, live_trust_fn=lambda: (_ for _ in ()).throw(RuntimeError("no hw")), clock=clock or FakeClock())


# ---- scenario replay -------------------------------------------------------
def test_benign_creates_no_incident(runtime):
    runtime.replay_scenario("benign")
    assert runtime.incidents.list() == []


@pytest.mark.parametrize("name,itype,min_sev", [
    ("credential_attack", "credential_attack", "MEDIUM"),
    ("network_recon", "network_reconnaissance", "MEDIUM"),
    ("endpoint_compromise", "endpoint_compromise_high_confidence", "CRITICAL"),
    ("coordinated_intrusion", "coordinated_intrusion", "CRITICAL"),
])
def test_scenarios_produce_expected_single_incident(runtime, name, itype, min_sev):
    runtime.replay_scenario(name)
    incs = runtime.incidents.list()
    assert len(incs) == 1, "one composite incident, not one per alert"
    inc = incs[0]
    assert inc["type"] == itype == attack_scenarios.SCENARIOS[name]["expected_incident_type"]
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert order.index(inc["severity"]) >= order.index(min_sev)
    assert inc["explanation"] and inc["recommended_actions"] and inc["severity_breakdown"]


def test_coordinated_intrusion_details(runtime):
    runtime.replay_scenario("coordinated_intrusion")
    inc = runtime.incidents.list()[0]
    assert inc["event_count"] == 6 and inc["host"] == "HOST-01" and inc["source_ip"] == "192.168.1.20"
    assert inc["severity"] == "CRITICAL" and inc["severity_score"] == 100
    assert {"R2", "R3", "R6"} <= {r["id"] for r in inc["matched_rules"]}
    assert inc["status"] == "ASSIGNED" and inc["assigned_analyst"] == "Analyst 1"
    assert inc["confidence"] >= 0.85 and inc["priority_rank"] == 1


def test_incident_grows_progressively_not_duplicated(runtime):
    seen = [i and (i["incident_id"], i["severity_score"]) for i in runtime.replay_scenario("coordinated_intrusion")]
    real = [s for s in seen if s]
    assert {r[0] for r in real} == {"INC-001"}
    scores = [r[1] for r in real]
    assert scores == sorted(scores) and scores[0] < scores[-1]


def test_replay_is_deterministic():
    results = []
    for _ in range(2):
        rt = fresh()
        rt.replay_scenario("coordinated_intrusion")
        inc = rt.incidents.list()[0]
        results.append((inc["severity_score"], inc["confidence"], inc["priority_score"],
                        [e["event_id"] for e in inc["related_events"]]))
    assert results[0] == results[1]


def test_attacks_on_separate_hosts_make_separate_incidents(runtime):
    runtime.replay_scenario("credential_attack")
    for raw in attack_scenarios.build_scenario_events("endpoint_compromise", runtime._clock()):
        raw["hostname"] = "HOST-03"
        raw.pop("src", None)
        runtime.ingest_raw(raw)
    assert len(runtime.incidents.list()) == 2


def test_new_attack_after_window_is_a_new_incident(runtime, clock):
    runtime.replay_scenario("credential_attack", clock())
    clock.advance(3600)
    runtime.replay_scenario("credential_attack", clock())
    assert len(runtime.incidents.list()) == 2


def test_replayed_duplicates_are_dropped(runtime):
    events = attack_scenarios.build_scenario_events("credential_attack", runtime._clock())
    for raw in events + events:
        raw["id"] = raw["ts"] + raw["details"].get("user", "")     # source-provided ids
        runtime.ingest_raw(raw)
    assert runtime.correlation.duplicates >= 5
    assert len(runtime.incidents.list()) == 1


def test_malformed_events_do_not_break_pipeline(runtime):
    for bad in [None, "junk", {}, {"event": 5}, {"event": "port_scan", "ts": object()}]:
        runtime.ingest_raw(bad)
    runtime.replay_scenario("credential_attack")
    assert len(runtime.incidents.list()) == 1 and runtime.normalizer.rejected >= 3


def test_full_analyst_flow_and_stats(runtime):
    runtime.replay_scenario("coordinated_intrusion")
    inc = runtime.incidents.list()[0]["incident_id"]
    assert runtime.acknowledge(inc)["status"] == "INVESTIGATING"
    before = runtime.trust_score()["final_score"]
    assert runtime.resolve(inc)["status"] == "RESOLVED"
    stats = runtime.statistics()
    assert stats["incidents"]["active"] == 0 and stats["incidents"]["by_status"]["RESOLVED"] == 1
    assert stats["analysts"]["available"] == 3
    assert runtime.trust_score()["final_score"] > before               # closed incident stops dragging trust down


def test_capacity_with_many_incidents(clock):
    rt = fresh(clock)
    for n in range(8):
        rt.replay_scenario("credential_attack", clock())
        clock.advance(3600)
    view = rt.analyst_queue()
    assert len(rt.incidents.list()) == 8 and view["active_count"] == 3 and len(view["waiting"]) == 5


def test_threaded_scenario_runs_and_stops(runtime):
    runtime.start_scenario("coordinated_intrusion")
    assert wait_until(lambda: not runtime.scenario["running"])
    assert len(runtime.incidents.list()) == 1
    with pytest.raises(ScenarioError):
        runtime.start_scenario("nope")


def test_random_simulation_starts_and_stops(settings, clock):
    settings.sim_event_rate = 20
    rt = SocRuntime(settings, clock=clock)
    rt.start_scenario("random")
    assert wait_until(lambda: len(rt.events) > 3)
    rt.stop_scenario()
    assert not rt.scenario["running"]


# ---- trust score integration ----------------------------------------------
FAKE_LIVE = {
    "final_score": 34.0, "status": "Untrusted",
    "sub_scores": {
        "wifi": {"module": "wifi", "score": 40, "flags": ["Open network - no encryption"], "raw_features": {}},
        "usb": {"module": "usb", "score": 30, "flags": ["Unknown USB device"], "raw_features": {}},
        "bluetooth": {"module": "bluetooth", "score": 70, "flags": [], "raw_features": {}},
    },
    "contributions_ranked": [],
}


def test_existing_fusion_engine_is_unchanged(monkeypatch):
    import fusion.engine as fe
    monkeypatch.setattr(fe, "get_wifi_subscore", lambda: {"module": "wifi", "score": 40, "flags": [], "raw_features": {}})
    monkeypatch.setattr(fe, "get_usb_subscore", lambda: {"module": "usb", "score": 30, "flags": [], "raw_features": {}})
    monkeypatch.setattr(fe, "get_bluetooth_subscore", lambda: {"module": "bluetooth", "score": 70, "flags": [], "raw_features": {}})
    result = fe.compute_trust_score()
    assert result["final_score"] == round(40 * .40 + 30 * .35 + 70 * .25, 1) == 44.0


def test_simulated_score_has_same_shape_and_weights_as_live():
    import fusion.engine as fe
    sim = TrustAdapter(config.Settings()).simulated([])
    assert {"final_score", "status", "sub_scores", "contributions_ranked"} <= set(sim)
    for sub in sim["sub_scores"].values():
        assert {"module", "score", "flags", "raw_features"} <= set(sub)
    expected = round(sum(sim["sub_scores"][m]["score"] * w for m, w in fe.WEIGHTS.items()), 1)
    assert sim["final_score"] == expected            # weighted fusion, not a plain sum


def test_trust_and_severity_are_separate_and_both_present(runtime):
    runtime.replay_scenario("coordinated_intrusion")
    inc = runtime.incidents.list()[0]
    trust = runtime.trust_score()
    assert inc["trust_score"] == trust["final_score"] and trust["status"] == "Untrusted"
    assert inc["severity"] == "CRITICAL" and inc["trust_score"] < 50
    assert inc["severity_score"] != inc["trust_score"]


def test_trust_drops_with_signals_in_simulation(runtime):
    base = runtime.trust_score()["final_score"]
    runtime.replay_scenario("benign")
    assert runtime.trust_score()["final_score"] >= 80          # one stray failed login: still Trusted
    runtime.replay_scenario("endpoint_compromise")
    assert runtime.trust_score()["final_score"] < base - 20


def test_low_module_scores_become_soc_signals():
    ta = TrustAdapter(config.Settings(), live_fn=lambda: FAKE_LIVE)
    raws = ta.signals_from_trust(FAKE_LIVE)
    kinds = {r["category"]: r["event"] for r in raws}
    assert kinds == {"wifi": "weak_security", "usb": "suspicious_usb"}      # bluetooth 70 is fine
    assert ta.signals_from_trust(FAKE_LIVE) == []                          # unchanged: no flood


def test_trust_signals_feed_the_incident_pipeline(runtime):
    for raw in runtime.trust.signals_from_trust(FAKE_LIVE):
        runtime.ingest_raw(raw)
    assert len(runtime.events) == 2 and {e.source for e in runtime.events} == {"wifi", "usb"}


def test_live_mode_falls_back_when_collectors_missing(runtime):
    r = runtime.trust.refresh_live()
    assert r["data_source"] == "simulated_fallback" and runtime.trust.live_available is False
    assert "no hardware" in runtime.trust.last_live_error


def test_live_mode_uses_real_engine_result_and_blocks_scenarios(settings, clock):
    settings.live_poll_sec = 0.05
    rt = SocRuntime(settings, live_trust_fn=lambda: dict(FAKE_LIVE), clock=clock)
    rt.set_mode("live")
    assert wait_until(lambda: rt.trust.cached_live() is not None)
    assert rt.trust_score()["final_score"] == 34.0 and rt.trust_score()["data_source"] == "live"
    with pytest.raises(ScenarioError):
        rt.start_scenario("benign")
    assert wait_until(lambda: len(rt.events) >= 2)                # trust signals became events
    assert wait_until(lambda: len(rt.incidents.list()) == 1)      # weak Wi-Fi + USB -> live incident
    inc = rt.incidents.list()[0]
    assert inc["type"] == "device_trust_degradation" and inc["recommended_actions"]
    assert any(e.event_type == "trust_check" and not e.is_signal for e in rt.events)   # feed shows every scan
    rt.set_mode("simulation")
    assert rt.mode == "simulation"


def test_snapshot_events_are_informational_and_cover_every_module():
    ta = TrustAdapter(config.Settings(), live_fn=lambda: FAKE_LIVE)
    raws = ta.snapshot_events(FAKE_LIVE)
    assert {r["category"] for r in raws} == {"wifi", "usb", "bluetooth"}
    assert all(r["event"] == "trust_check" and r["severity"] == "info" for r in raws)


def test_statistics_alerts_by_source(runtime):
    runtime.replay_scenario("coordinated_intrusion")
    runtime.replay_scenario("benign")
    alerts = runtime.statistics()["alerts_by_source"]
    assert alerts["network"] == 2 and alerts["authentication"] >= 2 and alerts["usb"] == 1 and alerts["endpoint"] == 1
    assert "system" not in alerts                       # info events are not alerts
