import pytest

from conftest import wait_until
from app import create_app
from soc import config
from soc.runtime import SocRuntime


@pytest.fixture
def client(settings, clock):
    rt = SocRuntime(settings, live_trust_fn=lambda: (_ for _ in ()).throw(RuntimeError("boom")), clock=clock)
    app = create_app(rt)
    yield app.test_client()
    rt.stop_scenario()


def run_scenario(client, name):
    r = client.post("/api/scenarios/start", json={"scenario": name})
    assert r.status_code == 202
    assert wait_until(lambda: not client.get("/api/system-status").json["data"]["scenario"]["running"])


def test_trust_score_endpoint_keeps_existing_shape(client):
    d = client.get("/api/trust-score").json
    assert {"final_score", "status", "sub_scores", "contributions_ranked"} <= set(d)
    assert set(d["sub_scores"]) == {"wifi", "usb", "bluetooth"}


def test_trust_score_live_source_never_500s_without_hardware(client):
    r = client.get("/api/trust-score?source=live")
    assert r.status_code == 200 and r.json["data_source"] == "simulated_fallback"
    assert client.get("/api/trust-score?source=bogus").status_code == 400


def test_index_page_served(client):
    r = client.get("/")
    assert r.status_code == 200 and b"Unified Trust Score" in r.data and b"score-number" in r.data


def test_consistent_json_envelope(client):
    for path in ("/api/events", "/api/incidents", "/api/analyst-queue", "/api/statistics", "/api/system-status"):
        j = client.get(path).json
        assert j["status"] == "ok" and "data" in j, path


def test_full_demo_flow_over_api(client):
    run_scenario(client, "coordinated_intrusion")
    incs = client.get("/api/incidents").json["data"]
    assert len(incs) == 1
    iid = incs[0]["incident_id"]
    detail = client.get(f"/api/incidents/{iid}").json["data"]
    assert detail["severity"] == "CRITICAL" and detail["explanation"] and detail["recommended_actions"]
    assert detail["status"] == "ASSIGNED"

    q = client.get("/api/analyst-queue").json["data"]
    assert q["capacity"] == 3 and q["active_count"] == 1 and q["available"] == 2 and q["queue"][0]["rank"] == 1

    ev = client.get("/api/events?limit=3").json["data"]
    assert len(ev) == 3 and ev[0]["timestamp"] >= ev[-1]["timestamp"]
    assert len(client.get("/api/events?source=usb").json["data"]) == 1

    assert client.post(f"/api/incidents/{iid}/acknowledge").json["data"]["status"] == "INVESTIGATING"
    assert client.post(f"/api/incidents/{iid}/resolve").json["data"]["status"] == "RESOLVED"
    stats = client.get("/api/statistics").json["data"]
    assert stats["incidents"]["active"] == 0 and stats["analysts"]["available"] == 3
    assert stats["signals"]["usb"]["events"] == 1


def test_false_positive_endpoint(client):
    run_scenario(client, "credential_attack")
    iid = client.get("/api/incidents").json["data"][0]["incident_id"]
    assert client.post(f"/api/incidents/{iid}/false-positive").json["data"]["status"] == "FALSE_POSITIVE"
    assert client.get("/api/incidents?status=FALSE_POSITIVE").json["data"][0]["incident_id"] == iid


def test_input_validation(client):
    assert client.post("/api/scenarios/start", json={"scenario": "rm -rf /"}).status_code == 400
    assert client.post("/api/scenarios/start", json={"scenario": 5}).status_code == 400
    assert client.post("/api/scenarios/start", data="not json").status_code == 400
    assert client.post("/api/scenarios/start").status_code == 400
    assert client.get("/api/events?limit=abc").status_code == 400
    assert client.get("/api/events?source=nope").status_code == 400
    assert client.get("/api/incidents?status=NOPE").status_code == 400
    assert client.post("/api/mode", json={"mode": "chaos"}).status_code == 400


def test_error_responses_are_clean_json(client):
    r = client.get("/api/incidents/INC-404")
    assert r.status_code == 404 and r.json["status"] == "error" and "Traceback" not in r.get_data(as_text=True)
    assert client.post("/api/incidents/INC-404/resolve").status_code == 404
    assert client.get("/api/nope").status_code == 404
    assert client.delete("/api/incidents").status_code == 405


def test_invalid_state_is_409(client):
    run_scenario(client, "credential_attack")
    iid = client.get("/api/incidents").json["data"][0]["incident_id"]
    client.post(f"/api/incidents/{iid}/resolve")
    r = client.post(f"/api/incidents/{iid}/acknowledge")
    assert r.status_code == 409 and r.json["error"]["code"] == "invalid_state"


def test_stop_reset_and_mode(client):
    run_scenario(client, "coordinated_intrusion")
    assert client.post("/api/scenarios/stop").json["data"]["running"] is False
    assert client.post("/api/reset").json["data"]["reset"] is True
    assert client.get("/api/incidents").json["data"] == []
    assert client.post("/api/mode", json={"mode": "live"}).json["data"]["mode"] == "live"
    assert client.post("/api/scenarios/start", json={"scenario": "benign"}).status_code == 409
    assert client.post("/api/mode", json={"mode": "simulation"}).json["data"]["mode"] == "simulation"


def test_system_status_and_scenarios_list(client):
    s = client.get("/api/system-status").json["data"]
    assert s["mode"] == "simulation" and s["analyst_capacity"] == 3 and "live_collectors" in s
    names = [x["name"] for x in client.get("/api/scenarios").json["data"]]
    assert "coordinated_intrusion" in names and "random" in names


def test_settings_from_env_are_validated():
    s = config.load_settings({"SOC_MODE": "weird", "SOC_ANALYST_CAPACITY": "abc", "FLASK_DEBUG": "0"})
    assert s.mode == "simulation" and s.analyst_capacity == 3 and s.debug is False
    assert config.load_settings({"SOC_ANALYST_CAPACITY": "999"}).analyst_capacity == 20
    assert config.load_settings({}).debug is False
