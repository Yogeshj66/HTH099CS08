# Signal-Fused Intrusion Detection & Response Prioritization Dashboard

A SOC-oriented dashboard built on top of the **Unified Device & Network Trust Score Engine**.
It fuses Wi-Fi, USB and Bluetooth trust signals with simulated SOC events (authentication, network,
firewall, endpoint, system), correlates weak signals into composite incidents, explains a 0-100
severity score, ranks incidents by priority, respects limited analyst capacity and recommends
(never executes) response actions.

> **The MVP/demo uses simulated security events** and can later be connected to real SOC log sources
> (SIEM, syslog, EDR). Simulation mode needs no special hardware.

## 1. Problem statement
Analysts drown in isolated low-value alerts. One failed login or one port scan means little; together
with an unknown USB and a strange process they mean a lot. The system must (a) connect related weak
signals, (b) say *how serious* the result is and *why*, (c) decide *what to work on first* given that
only N analysts exist, and (d) suggest safe next steps.

## 2. Existing Trust Engine (preserved, untouched)
```
wifi_module / usb_module / bluetooth_module  ->  fusion.engine.compute_trust_score()  ->  Unified Trust Score
```
Weighted fusion (Wi-Fi 0.40, USB 0.35, Bluetooth 0.25). `get_wifi_subscore()`, `get_usb_subscore()`,
`get_bluetooth_subscore()` and `compute_trust_score()` are unchanged. **Trust Score** = how trustworthy the
environment is. **Severity Score** = how serious a detected incident is. They are different measures and
both appear on the dashboard (e.g. *Trust 42/100, Incident severity CRITICAL*). Trust is only used as a small
context bonus in severity, never added to it.

## 3-4. New SOC architecture
```
 Wi-Fi / USB / Bluetooth ─► existing modules ─► Fusion ─► Unified Trust Score ─┐
                                                                               ▼
 Authentication / Network / Firewall / Endpoint / System logs ─► trust_adapter (sub-scores -> signals)
                        │                                                     │
                        └──────────────► event_normalizer ◄───────────────────┘
                                              ▼
                                     correlation_engine  (rules in soc/config.py)
                                              ▼
                                      incident_manager   (SQLite)
                                              ▼
                                       severity_engine ─► priority_engine
                                              ▼
                                  analyst_queue (capacity)  ─► response_engine
                                              ▼
                                        Flask SOC dashboard
```
| File | Single responsibility |
|---|---|
| `soc/models.py` | Common `SecurityEvent` and shared constants |
| `soc/config.py` | **All** tuning: settings, rules, score tables, thresholds, playbooks |
| `soc/log_generator.py` | Safe simulated raw logs (normal, suspicious, random, seedable, rate) |
| `soc/event_normalizer.py` | Raw dict -> `SecurityEvent`; never crashes on bad input |
| `soc/correlation_engine.py` | Relate weak signals using configurable rules |
| `soc/incident_manager.py` | SQLite storage, statuses, allowed transitions |
| `soc/severity_engine.py` | Transparent 0-100 severity + explanation |
| `soc/priority_engine.py` | Priority score / rank / reason |
| `soc/analyst_queue.py` | Capacity-limited assignment, acknowledge/resolve/false positive |
| `soc/response_engine.py` | Recommendation text only |
| `soc/attack_scenarios.py` | Five deterministic scenarios |
| `soc/trust_adapter.py` | Bridge to the Trust Engine (live, simulated, trust -> signals) |
| `soc/runtime.py` | Wires the pipeline, scenario/live threads |

## 5. Security signal sources
`authentication`, `network`, `firewall`, `endpoint`, `system`, `wifi`, `usb`, `bluetooth`
(event types per source: `soc/config.py -> EVENT_CATALOG`).

## 6. Event normalization
Common schema: `event_id, timestamp (UTC ISO), source, event_type, host, src_ip, dst_ip, base_severity, metadata`.
Handles aliased field names, epoch/ISO timestamps, severity aliases (`warn`, `crit`, numbers), missing host
(`UNKNOWN-HOST`), invalid IPs, oversized metadata, unknown sources (inferred from event type when unambiguous).
Unusable events are counted and dropped, never raised.

## 7. Signal correlation
Events are related by **same host or source IP** inside a **time window**. Informational events are context,
not signals; duplicates (same id or identical content) are ignored. Rules are data in `RULES`:

| Rule | Pattern (5 min) | Incident type |
|---|---|---|
| R1 | 3+ failed logins | credential_attack |
| R2 | port scan + failed login | possible_credential_attack |
| R3 | port scan + failed login + traffic spike | coordinated_intrusion |
| R4 | unknown USB + suspicious process | endpoint_compromise |
| R5 | R4 + network anomaly | endpoint_compromise_high_confidence |
| R6 | weak signals from 3+ sources | composite_incident |
| R7 | port scan + probing signal | network_reconnaissance |
| R8 | weak Wi-Fi/USB/Bluetooth trust signals from 2+ sources (10 min; the LIVE-mode rule) | device_trust_degradation |

## 8. Incident detection
A match creates (or grows) **one** incident per host/IP campaign: further correlated events are merged, the
title/type upgrade to the strongest rule, and every matched rule is kept as evidence. Statuses:
`NEW, PENDING, ASSIGNED, INVESTIGATING, RESOLVED, FALSE_POSITIVE`.

## 9. Severity scoring
Points per distinct signal (port scan +20, traffic anomaly +20, unknown USB +20, suspicious process +20,
multiple failed logins +10, ...), repeated-activity bonus, cross-source bonus, pattern bonus, small low-trust
bonus, capped at 100. Thresholds (configurable): 0-25 LOW, 26-50 MEDIUM, 51-75 HIGH, 76-100 CRITICAL.
Every incident carries its explanation, e.g.:
```
SEVERITY SCORE: 100 (CRITICAL)
WHY:
+20 Port scanning
+10 Multiple failed logins
+20 Traffic anomaly
+20 Unknown USB
+20 Suspicious process
+02 Repeated activity
+10 Multi-source correlation
+10 Pattern: Possible Coordinated Intrusion
+05 Low environment trust
Total 117, capped at 100
```

## 10. Analyst prioritization
`priority = 0.45 severity + 0.20 confidence + 0.15 host impact + 0.10 correlated-event volume + 0.10 SLA age`
(weights, host criticality and SLA times in `config.py`). Output: `priority_score`, `priority_rank`, `priority_reason`.
`ANALYST_CAPACITY` (default 3) limits active work: `INVESTIGATING` incidents are never pre-empted, remaining
slots go to the highest-priority incidents, the rest wait as `PENDING`. The queue rebalances on new incident,
acknowledge, resolve, false positive and capacity change.

## 11. Response recommendations
Playbooks for credential attack, network intrusion, endpoint compromise, reconnaissance and composite incidents.
**Recommendations only.** Nothing is executed: no shutdowns, file deletion, account changes or IP blocking.

## 12. Dashboard
Top to bottom: scenario buttons and **Run guided demo**, KPI cards, **incidents in priority order** (rank #1, priority
score) next to the **live event feed** (events plus "incident raised" notices; in LIVE mode a Trust check per
module every scan), analyst queue next to the **incident / alert distribution pie charts** (open incidents by
severity, alerts by source), the selected incident (plain-words summary, timeline, why this score, response),
and signal tiles. KPI cards (Trust Score, active, critical/high/medium/low, analyst capacity/available), incident cards,
analyst slots + ranked queue, incident timeline, "why this score" panel with the priority reason, response
panel, signal tiles (Wi-Fi/USB/Bluetooth show their real sub-scores), live event feed, scenario buttons,
Simulation/Live switch and Reset. All server data is rendered with `textContent` (no HTML injection).

## 13. Demo scenarios
Normal Activity (no incident), Credential Attack, Network Recon, Endpoint Compromise, Coordinated Intrusion
(T+0 port scan, T+10/20 failed logins, T+30 traffic spike, T+40 unknown USB, T+50 suspicious process ->
**one** composite CRITICAL incident), plus an endless Random Simulation.

**Guided demo:** the *Run guided demo* button runs the whole flow below automatically (reset, start Coordinated Intrusion, tick each step as it really happens, acknowledge, resolve). *Stop demo* aborts it.

**Demo flow:** start the app -> note the Trust Score -> click *Coordinated intrusion* -> watch events arrive
one by one -> the incident appears and its severity climbs -> read "why this score" -> see priority and analyst
assignment -> read the recommended actions -> *Acknowledge* (INVESTIGATING) -> *Resolve* -> queue and KPIs update.

## 14. Installation
```bash
git clone https://github.com/Yogeshj66/unified-trust-score-engine
cd unified-trust-score-engine
python -m venv venv
venv\Scripts\activate          # Windows   (source venv/bin/activate on Linux/macOS)
pip install -r requirements.txt
```

## 15. Running
```bash
cd dashboard
python app.py                  # http://127.0.0.1:5000  (simulation mode, no hardware needed)
```
Optional environment variables: `SOC_MODE=simulation|live`, `SOC_ANALYST_CAPACITY=3`, `SOC_DB_PATH=...`
(`:memory:` for no persistence), `SOC_SCENARIO_STEP_DELAY=2.0`, `SOC_SIM_SEED`, `SOC_HOST`, `SOC_PORT`,
`FLASK_DEBUG=1` (off by default: the Werkzeug debugger allows remote code execution).

**LIVE mode** (Windows, uses your real Wi-Fi/USB/Bluetooth via the existing modules): switch in the header or
`SOC_MODE=live`. Scenarios are disabled in live mode. If the collectors are unavailable the dashboard shows a
warning and falls back to simulated values instead of failing. Real collectors run in the background and are
cached, so the 6-second Bluetooth scan no longer blocks page polling. Every scan adds a Trust check event to the live feed, and weak module scores become SOC signals; two or more degraded modules raise a `device_trust_degradation` incident (rule R8).

Console replay without a browser: `python -m soc.runtime coordinated_intrusion`

## 16. API
All new endpoints return `{"status":"ok","data":...}` or `{"status":"error","error":{"code","message"}}`
(400 bad input, 404 unknown id, 409 invalid state, 500 generic; no stack traces).

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/trust-score` | **Existing shape kept.** Adds `mode`, `data_source`. `?source=live` forces the real engine |
| GET | `/api/events?limit=&source=` | Recent normalized events, newest first |
| GET | `/api/incidents?status=` | Incidents, priority order |
| GET | `/api/incidents/<id>` | One incident with timeline, explanation, actions |
| GET | `/api/analyst-queue` | Capacity, analyst slots, ranked queue, waiting list |
| GET | `/api/statistics` | Incident counts, analyst usage, per-source signal stats |
| GET | `/api/system-status` | Mode, scenario progress, collectors, uptime |
| GET | `/api/scenarios` | Available scenarios |
| POST | `/api/scenarios/start` | `{"scenario": "coordinated_intrusion"}` (simulation only) |
| POST | `/api/scenarios/stop` | Stop the running scenario |
| POST | `/api/incidents/<id>/acknowledge` | ASSIGNED -> INVESTIGATING |
| POST | `/api/incidents/<id>/resolve` | -> RESOLVED, frees the analyst |
| POST | `/api/incidents/<id>/false-positive` | -> FALSE_POSITIVE, frees the analyst |
| POST | `/api/mode` | `{"mode": "simulation"|"live"}` |
| POST | `/api/reset` | Clear events and incidents (demo repeatability) |

## 17. Testing
```bash
pip install -r requirements.txt
python -m pytest
```
98 tests cover generation, normalization (malformed input), correlation (one weak signal, many weak signals,
unrelated events, outside-window, duplicates), incident creation, severity, priority, analyst capacity (no
free analysts, resolve, false positive, capacity change), response recommendations, Trust Score integration
(existing fusion unchanged, simulated vs live, fallback), scenario replay determinism and all API endpoints.

## 18. Limitations
* Security events are **simulated**; no real SOC log ingestion yet.
* Live collectors (`netsh`, PowerShell) are Windows-only; Wi-Fi deauth detection is a placeholder in the original module.
* Simulated Trust Score maps SOC events onto module sub-scores illustratively (`SIM_TRUST_MODULE_MAP`).
* Correlation is rule-based, evaluated in arrival order (a very late out-of-order event will not retro-trigger rules).
* Single-process, single-user demo: no authentication on the dashboard/API. Do not expose it to a network.
* Priority weights, host criticality and SLA values are illustrative defaults.

## 19. Future work
Real log ingestion (syslog/Windows Event Log/SIEM), ML anomaly scoring feeding the same event model,
authenticated multi-analyst UI, incident notes/audit trail, MITRE ATT&CK tagging, approval-gated response
automation, alert/notification integrations.

## Requirement matrix
| Requirement | Status | Evidence |
|---|---|---|
| Multi-source log stream | PASS | 8 sources, generator + normalizer tests |
| Signal fusion | PASS | Trust sub-scores become events; correlation across sources |
| Composite incidents | PASS | Coordinated scenario -> exactly one incident |
| Severity scoring | PASS | Table-driven, thresholds configurable, boundary tests |
| Explainability | PASS | `explanation` + `severity_breakdown` on every incident |
| Analyst capacity | PASS | Never exceeds capacity; tests incl. 10 incidents |
| Priority queue | PASS | Priority score/rank/reason, auto-rebalance |
| Live dashboard | PASS | Polling UI verified end-to-end against running server (jsdom) |
| Attack scenarios | PASS | 5 deterministic + random |
| Response recommendations | PASS | Playbooks, text only |
| Trust engine preserved | PASS | wifi/usb/bluetooth/fusion files unmodified; test on `compute_trust_score` |
| Simulation mode | PASS | Runs on Linux with no hardware |
| Testing | PASS | 98 passing |
| Documentation | PASS | This README |

## License
See `LICENSE`.
