"""
Flask Dashboard - Signal-Fused Intrusion Detection & Response Prioritization
----------------------------------------------------------------------------
Serves the SOC dashboard and JSON API on top of the Unified Trust Score Engine.

Run:
    cd dashboard
    python app.py
Then open http://127.0.0.1:5000

Environment (all optional): SOC_MODE=simulation|live, SOC_ANALYST_CAPACITY,
SOC_DB_PATH, SOC_SCENARIO_STEP_DELAY, FLASK_DEBUG=1, SOC_HOST, SOC_PORT
"""

import logging
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, jsonify, render_template, request

from soc import attack_scenarios
from soc.config import load_settings
from soc.incident_manager import IncidentNotFound, InvalidTransition
from soc.models import INCIDENT_STATUSES, SOURCES
from soc.runtime import ScenarioError, SocRuntime

log = logging.getLogger("soc.api")


def ok(data=None, http=200):
    return jsonify({"status": "ok", "data": data}), http


def fail(code, message, http):
    return jsonify({"status": "error", "error": {"code": code, "message": message}}), http


def create_app(runtime=None):
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False
    rt = runtime or SocRuntime(load_settings())
    app.soc = rt

    # ---- pages -----------------------------------------------------------
    @app.route("/")
    def index():
        return render_template("index.html")

    # ---- existing API (kept; now never 500s when collectors are missing) --
    @app.route("/api/trust-score")
    def api_trust_score():
        source = request.args.get("source")
        if source == "live":
            result = dict(rt.trust.live())
            result["mode"] = "live"
            return jsonify(result)
        if source not in (None, "", "simulated"):
            return fail("bad_request", "source must be 'live' or 'simulated'", 400)
        return jsonify(rt.trust_score())

    # ---- read endpoints ----------------------------------------------------
    @app.route("/api/events")
    def api_events():
        try:
            limit = max(1, min(500, int(request.args.get("limit", 100))))
        except ValueError:
            return fail("bad_request", "limit must be an integer", 400)
        source = request.args.get("source")
        if source and source not in SOURCES:
            return fail("bad_request", f"unknown source '{source[:30]}'", 400)
        return ok(rt.list_events(limit, source))

    @app.route("/api/incidents")
    def api_incidents():
        status = request.args.get("status")
        if status and status not in INCIDENT_STATUSES:
            return fail("bad_request", f"status must be one of {', '.join(INCIDENT_STATUSES)}", 400)
        return ok(rt.list_incidents(status))

    @app.route("/api/incidents/<incident_id>")
    def api_incident(incident_id):
        rt.queue.rebalance()
        return ok(rt.incidents.get(incident_id))

    @app.route("/api/analyst-queue")
    def api_queue():
        return ok(rt.analyst_queue())

    @app.route("/api/statistics")
    def api_statistics():
        return ok(rt.statistics())

    @app.route("/api/system-status")
    def api_system_status():
        return ok(rt.system_status())

    @app.route("/api/scenarios")
    def api_scenarios():
        return ok(attack_scenarios.list_scenarios())

    # ---- scenario / mode control -----------------------------------------
    def body():
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}

    @app.route("/api/scenarios/start", methods=["POST"])
    def api_scenario_start():
        name = body().get("scenario")
        if not isinstance(name, str) or name not in attack_scenarios.SCENARIO_NAMES:
            return fail("bad_request", "scenario must be one of: " + ", ".join(attack_scenarios.SCENARIO_NAMES), 400)
        return ok(rt.start_scenario(name), 202)

    @app.route("/api/scenarios/stop", methods=["POST"])
    def api_scenario_stop():
        return ok(rt.stop_scenario())

    @app.route("/api/mode", methods=["POST"])
    def api_mode():
        mode = body().get("mode")
        if mode not in ("simulation", "live"):
            return fail("bad_request", "mode must be 'simulation' or 'live'", 400)
        return ok({"mode": rt.set_mode(mode)})

    @app.route("/api/reset", methods=["POST"])
    def api_reset():
        rt.reset()
        return ok({"reset": True})

    # ---- analyst actions -------------------------------------------------
    @app.route("/api/incidents/<incident_id>/acknowledge", methods=["POST"])
    def api_ack(incident_id):
        return ok(rt.acknowledge(incident_id))

    @app.route("/api/incidents/<incident_id>/resolve", methods=["POST"])
    def api_resolve(incident_id):
        return ok(rt.resolve(incident_id))

    @app.route("/api/incidents/<incident_id>/false-positive", methods=["POST"])
    def api_false_positive(incident_id):
        return ok(rt.false_positive(incident_id))

    # ---- error handling: JSON only, never a stack trace -------------------
    @app.errorhandler(IncidentNotFound)
    def _nf(_):
        return fail("not_found", "incident not found", 404)

    @app.errorhandler(InvalidTransition)
    def _bad_transition(exc):
        return fail("invalid_state", str(exc), 409)

    @app.errorhandler(ScenarioError)
    def _scenario(exc):
        return fail("scenario_error", str(exc), 409)

    @app.errorhandler(404)
    def _404(_):
        return fail("not_found", "resource not found", 404)

    @app.errorhandler(405)
    def _405(_):
        return fail("method_not_allowed", "method not allowed", 405)

    @app.errorhandler(Exception)
    def _500(exc):
        log.exception("unhandled error")
        return fail("internal_error", "internal server error", 500)

    return app


app = create_app()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    s = app.soc.settings
    app.run(host=s.host, port=s.port, debug=s.debug, use_reloader=False)
