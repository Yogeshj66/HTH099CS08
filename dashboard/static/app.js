/* SOC dashboard. All server data is written with textContent (never innerHTML),
   because SSIDs, device names and log fields are attacker-controlled. */

const POLL_MS = 1500;
const SEV_COLOR = { CRITICAL: 'var(--critical)', HIGH: 'var(--high)', MEDIUM: 'var(--medium)', LOW: 'var(--low)',
                    critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)', info: 'var(--muted)' };
const SIGNAL_TILES = [
  ['wifi', 'Wi-Fi'], ['usb', 'USB'], ['bluetooth', 'Bluetooth'], ['authentication', 'Authentication'],
  ['network', 'Network'], ['firewall', 'Firewall'], ['endpoint_system', 'Endpoint / System'],
];

const state = { selected: null, incidents: [], trust: null, mode: 'simulation', busy: false };

function el(tag, cls, text, children) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = text;
  (children || []).forEach(c => c && node.appendChild(c));
  return node;
}
const $ = id => document.getElementById(id);
const clear = node => { while (node.firstChild) node.removeChild(node.firstChild); };
const pretty = s => String(s || '').replace(/_/g, ' ').replace(/^./, c => c.toUpperCase());
const clock = iso => new Date(iso).toLocaleTimeString([], { hour12: false });

async function api(path, options) {
  const res = await fetch(path, options);
  let body = null;
  try { body = await res.json(); } catch (e) { /* non-JSON error page */ }
  if (!res.ok) {
    const msg = body && body.error ? body.error.message : `Request failed (${res.status})`;
    throw new Error(msg);
  }
  return body && body.status === 'ok' ? body.data : body;
}
const post = (path, payload) => api(path, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload || {}),
});

let bannerHoldUntil = 0;
function banner(msg, holdMs) {
  if (!holdMs && Date.now() < bannerHoldUntil) return;      // keep a recent action error readable
  if (holdMs) bannerHoldUntil = Date.now() + holdMs;
  const b = $('banner');
  b.hidden = !msg;
  b.textContent = msg || '';
}

/* ---------- trust score (original card, preserved) ---------- */
function statusClass(status) {
  if (status === 'Trusted') return 'status-trusted';
  if (status === 'Caution') return 'status-caution';
  return 'status-untrusted';
}
function renderTrust(data) {
  $('score-number').textContent = data.final_score;
  const st = $('score-status');
  st.textContent = data.status;
  st.className = 'score-status ' + statusClass(data.status);
}

/* ---------- KPIs ---------- */
function renderKpis(stats) {
  const inc = stats.incidents, an = stats.analysts;
  $('kpi-active').textContent = inc.active;
  $('kpi-critical').textContent = inc.by_severity.CRITICAL || 0;
  $('kpi-high').textContent = inc.by_severity.HIGH || 0;
  $('kpi-medium').textContent = inc.by_severity.MEDIUM || 0;
  $('kpi-low').textContent = inc.by_severity.LOW || 0;
  $('kpi-capacity').textContent = an.capacity;
  $('kpi-available').textContent = an.available;
}

/* ---------- incidents ---------- */
function sevBadge(sev) { return el('span', 'badge sev-' + String(sev).toLowerCase(), sev); }
function statusPill(st) { return el('span', 'pill st-' + st, st.replace('_', ' ')); }

function renderIncidents(list) {
  const box = $('incident-list');
  clear(box);
  state.incidents = list;
  const active = list.filter(i => ['NEW', 'PENDING', 'ASSIGNED', 'INVESTIGATING'].includes(i.status));
  const closed = list.filter(i => !active.includes(i));
  if (!list.length) {
    box.appendChild(el('div', 'empty', 'No incidents yet. Start a scenario above to generate signals.'));
    return;
  }
  [...active, ...closed].forEach(inc => {
    const card = el('button', `incident-card sev-${inc.severity.toLowerCase()}` + (inc.incident_id === state.selected ? ' selected' : ''));
    card.type = 'button';
    card.appendChild(el('div', 'row', null, [
      el('span', null, null, [
        inc.priority_rank ? el('span', 'rank', '#' + inc.priority_rank) : null,
        el('span', 'mono', inc.incident_id + '  '), el('span', 'title', inc.title)]),
      el('span', null, null, [sevBadge(inc.severity), document.createTextNode(' '), statusPill(inc.status)]),
    ]));
    card.appendChild(el('div', 'meta', null, [
      inc.priority_rank ? el('span', 'prio', `Priority ${inc.priority_score}`) : null,
      el('span', null, `Severity ${inc.severity_score}`),
      el('span', null, `Trust ${inc.trust_score}`),
      el('span', null, `Confidence ${Math.round(inc.confidence * 100)}%`),
      el('span', null, `Host ${inc.host}`),
      el('span', null, `Source IP ${inc.source_ip || 'n/a'}`),
    ]));
    card.addEventListener('click', () => { state.selected = inc.incident_id; renderIncidents(state.incidents); renderDetail(); });
    box.appendChild(card);
  });
}

/* ---------- analyst queue ---------- */
function renderQueue(q) {
  const slots = $('analyst-slots');
  clear(slots);
  q.analysts.forEach(a => {
    const busy = !!a.incident;
    slots.appendChild(el('div', 'slot' + (busy ? ' busy' : ''), null, [
      el('div', 'who', a.analyst),
      el('div', null, busy ? `${a.incident.incident_id}  ${a.incident.status.toLowerCase()}` : 'Available'),
    ]));
  });
  $('queue-hint').textContent = `${q.active_count} of ${q.capacity} analysts busy, ${q.waiting.length} waiting.`;

  const body = document.querySelector('#queue-table tbody');
  clear(body);
  if (!q.queue.length) {
    const tr = el('tr'); const td = el('td', 'empty', 'Queue is empty.'); td.colSpan = 6; tr.appendChild(td); body.appendChild(tr);
    return;
  }
  q.queue.forEach(r => {
    const tr = el('tr', 'clickable', null, [
      el('td', 'mono', '#' + r.rank), el('td', 'mono', r.incident_id),
      el('td', null, null, [sevBadge(r.severity)]),
      el('td', null, String(r.priority_score)),
      el('td', null, r.assigned_analyst || 'Waiting'),
      el('td', null, null, [statusPill(r.status)]),
    ]);
    tr.title = r.priority_reason;
    tr.addEventListener('click', () => { state.selected = r.incident_id; renderIncidents(state.incidents); renderDetail(); });
    body.appendChild(tr);
  });
}

/* ---------- incident detail ---------- */
function selectedIncident() {
  const list = state.incidents;
  let inc = list.find(i => i.incident_id === state.selected);
  if (!inc) { inc = list.find(i => ['NEW', 'PENDING', 'ASSIGNED', 'INVESTIGATING'].includes(i.status)) || list[0]; if (inc) state.selected = inc.incident_id; }
  return inc;
}

function plainSummary(inc) {
  const ip = inc.source_ip ? ` (source ${inc.source_ip})` : '';
  const rank = inc.priority_rank ? ` It is ranked #${inc.priority_rank} for analysts: ${String(inc.priority_reason || '').toLowerCase()}.` : '';
  return `In plain words: ${inc.related_events.length} related signals from ${inc.sources.join(', ')} on ${inc.host}${ip} together match "${inc.title}". ` +
    `Severity ${inc.severity_score}/100 means ${inc.severity}. Environment trust is ${inc.trust_score}/100, a separate measure.${rank}`;
}

async function act(id, action) {
  if (state.busy) return;
  state.busy = true;
  try { await post(`/api/incidents/${encodeURIComponent(id)}/${action}`); banner(''); }
  catch (e) { banner(e.message, 6000); }
  state.busy = false;
  refresh();
}

function renderDetail() {
  const head = $('detail-head'), tl = $('timeline'), ex = $('explanation'), ac = $('actions');
  [head, tl, ex, ac].forEach(clear);
  const inc = selectedIncident();
  $('plain').textContent = inc ? plainSummary(inc) : '';
  if (!inc) {
    head.appendChild(el('div', 'empty', 'Select an incident to see why it was raised.'));
    $('response-note').textContent = '';
    return;
  }
  const isActive = ['NEW', 'PENDING', 'ASSIGNED', 'INVESTIGATING'].includes(inc.status);
  const btn = (label, action, cls, enabled) => {
    const b = el('button', 'btn ' + cls, label); b.type = 'button'; b.disabled = !enabled;
    b.addEventListener('click', () => act(inc.incident_id, action)); return b;
  };
  head.appendChild(el('div', null, null, [
    el('div', 'detail-title', `${inc.incident_id}  ${inc.title}`),
    el('div', 'pair', null, [
      el('div', 'cell', null, [el('div', 'lab', 'Environment trust (how trustworthy)'), el('div', 'val', `${inc.trust_score}/100`)]),
      el('div', 'cell', null, [el('div', 'lab', 'Incident severity (how serious)'), (() => { const v = el('div', 'val', `${inc.severity} ${inc.severity_score}`); v.style.color = SEV_COLOR[inc.severity]; return v; })()]),
      el('div', 'cell', null, [el('div', 'lab', 'Confidence'), el('div', 'val', Math.round(inc.confidence * 100) + '%')]),
      el('div', 'cell', null, [el('div', 'lab', 'Status'), el('div', 'val', inc.status.replace('_', ' ') + (inc.assigned_analyst ? ` (${inc.assigned_analyst})` : ''))]),
    ]),
  ]));
  head.appendChild(el('div', 'detail-actions', null, [
    btn('Acknowledge', 'acknowledge', 'btn-primary', inc.status === 'ASSIGNED'),
    btn('Resolve', 'resolve', '', isActive),
    btn('Mark false positive', 'false-positive', 'btn-ghost', isActive),
  ]));

  inc.related_events.forEach(e => {
    const li = el('li', null, null, [
      el('span', 't', clock(e.timestamp)), el('strong', null, pretty(e.event_type)),
      el('div', 'src', `${e.source} on ${e.host}` + (e.src_ip ? ` from ${e.src_ip}` : '')),
    ]);
    li.style.setProperty('--dot', SEV_COLOR[e.base_severity] || 'var(--muted)');
    tl.appendChild(li);
  });

  ex.appendChild(el('div', 'why-score', `Severity score ${inc.severity_score} (${inc.severity})`));
  inc.severity_breakdown.forEach(b => ex.appendChild(el('div', 'why-row', null, [
    el('span', null, b.label), el('span', 'pts', '+' + String(b.points).padStart(2, '0')),
  ])));
  ex.appendChild(el('div', 'why-note', 'Trust Score and Severity are different measures: trust describes the environment, severity describes this incident. Low trust only adds a small context bonus.'));
  const pf = inc.priority_factors || {};
  ex.appendChild(el('div', 'priority-box', null, [
    el('div', null, `Priority score ${inc.priority_score ?? 'n/a'}` + (inc.priority_rank ? `, rank #${inc.priority_rank}` : '')),
    el('div', 'hint', inc.priority_reason || ''),
    el('div', 'hint', inc.matched_rules.map(r => `${r.id} ${r.name}`).join('; ')),
  ]));

  inc.recommended_actions.forEach(a => ac.appendChild(el('li', null, a)));
  $('response-note').textContent = 'Recommendations only. Nothing is executed automatically: no shutdowns, file deletion, account changes or IP blocking.';
}

/* ---------- signals and feed ---------- */
function renderSignals(stats, trust) {
  const grid = $('signals-grid');
  clear(grid);
  const sig = stats.signals;
  const combined = (a, b) => ({
    signals: (sig[a]?.signals || 0) + (sig[b]?.signals || 0),
    events: (sig[a]?.events || 0) + (sig[b]?.events || 0),
    last_event: sig[b]?.last_event || sig[a]?.last_event,
  });
  SIGNAL_TILES.forEach(([key, label]) => {
    const s = key === 'endpoint_system' ? combined('endpoint', 'system') : (sig[key] || { signals: 0, events: 0 });
    const tile = el('div', 'signal' + (s.signals ? ' hot' : ''));
    const name = el('div', 'name', null, [el('span', null, label)]);
    const module = trust && trust.sub_scores && trust.sub_scores[key];
    if (module) name.appendChild(el('span', module.score >= 70 ? 'status-trusted' : module.score >= 50 ? 'status-caution' : 'status-untrusted', String(module.score)));
    tile.appendChild(name);
    tile.appendChild(el('div', 'sub', module ? module.flags[0] : (s.signals ? `${s.signals} suspicious in last 15 min` : 'No suspicious signals')));
    if (module || s.events) tile.appendChild(el('div', 'sub', `${s.events} event(s) seen`));
    grid.appendChild(tile);
  });
}
function renderFeed(events, incidents) {
  const ul = $('feed');
  clear(ul);
  const live = state.mode === 'live';
  $('feed-title').textContent = live ? 'Live event feed (live scan)' : 'Live event feed (simulation)';
  const items = events.map(e => ({ t: new Date(e.timestamp).getTime(), kind: 'event', e }))
    .concat(incidents.map(i => ({ t: new Date(i.created_at).getTime() + 0.5, kind: 'incident', i })));
  items.sort((a, b) => b.t - a.t);
  if (!items.length) {
    ul.appendChild(el('li', 'empty', live ? 'Waiting for the first live scan (about every 15 seconds)...' : 'Waiting for events. Start a scenario above.'));
    return;
  }
  items.slice(0, 24).forEach(it => {
    if (it.kind === 'incident') {
      const inc = it.i;
      ul.appendChild(el('li', 'feed-incident', null, [
        el('span', 't', clock(inc.created_at)), sevBadge(inc.severity),
        el('span', null, `Incident ${inc.incident_id} raised: ${inc.title}`),
      ]));
      return;
    }
    const e = it.e;
    const dot = el('span', 'sev-dot'); dot.style.background = SEV_COLOR[e.base_severity] || 'var(--muted)';
    const label = e.event_type === 'trust_check' && e.metadata
      ? `Trust check: ${e.source} sub-score ${e.metadata.trust_subscore}`
      : `${pretty(e.event_type)} (${e.source}, ${e.host})`;
    ul.appendChild(el('li', e.base_severity === 'info' ? 'quiet' : null, null, [dot, el('span', 't', clock(e.timestamp)), el('span', null, label)]));
  });
}

/* ---------- pie charts ---------- */
const SOURCE_LABELS = { wifi: 'Wi-Fi', usb: 'USB', bluetooth: 'Bluetooth' };
const SOURCE_COLORS = { authentication: '#6cb6ff', network: '#b58cff', firewall: '#ff9f43', endpoint: '#ff5d73',
                        system: '#98a1b3', wifi: '#4cc9a4', usb: '#f2c94c', bluetooth: '#5ad1e6' };
function drawPie(box, data) {
  clear(box);
  const total = data.reduce((a, d) => a + d.value, 0);
  if (!total) { box.appendChild(el('div', 'empty', 'No data yet')); return; }
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 120 120'); svg.setAttribute('class', 'pie'); svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', data.map(d => `${d.label} ${d.value}`).join(', '));
  const cx = 60, cy = 60, r = 54, r2 = 30;
  let angle = -Math.PI / 2;
  data.filter(d => d.value > 0).forEach(d => {
    const frac = d.value / total, next = angle + frac * 2 * Math.PI;
    let path;
    if (frac >= 0.9999) {
      path = document.createElementNS(NS, 'circle'); path.setAttribute('cx', cx); path.setAttribute('cy', cy);
      path.setAttribute('r', (r + r2) / 2); path.setAttribute('fill', 'none'); path.setAttribute('stroke', d.color);
      path.setAttribute('stroke-width', r - r2);
    } else {
      const pt = (rad, a) => [cx + rad * Math.cos(a), cy + rad * Math.sin(a)];
      const [x1, y1] = pt(r, angle), [x2, y2] = pt(r, next), [x3, y3] = pt(r2, next), [x4, y4] = pt(r2, angle);
      const big = frac > 0.5 ? 1 : 0;
      path = document.createElementNS(NS, 'path');
      path.setAttribute('d', `M${x1} ${y1} A${r} ${r} 0 ${big} 1 ${x2} ${y2} L${x3} ${y3} A${r2} ${r2} 0 ${big} 0 ${x4} ${y4} Z`);
      path.setAttribute('fill', d.color);
    }
    const title = document.createElementNS(NS, 'title'); title.textContent = `${d.label}: ${d.value}`; path.appendChild(title);
    svg.appendChild(path);
    angle = next;
  });
  const num = document.createElementNS(NS, 'text');
  num.setAttribute('x', cx); num.setAttribute('y', cy + 6); num.setAttribute('text-anchor', 'middle');
  num.setAttribute('class', 'pie-total'); num.textContent = String(total);
  svg.appendChild(num);
  const legend = el('ul', 'legend', null, data.filter(d => d.value > 0).map(d => {
    const sw = el('span', 'swatch'); sw.style.background = d.color;
    return el('li', null, null, [sw, el('span', null, `${d.label}: ${d.value} (${Math.round(d.value / total * 100)}%)`)]);
  }));
  box.appendChild(el('div', 'pie-wrap', null, [svg, legend]));
}
function renderPies(stats) {
  const sev = stats.incidents.by_severity;
  drawPie($('pie-incidents'), ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(k => ({ label: pretty(k.toLowerCase()), value: sev[k] || 0, color: SEV_COLOR[k] })));
  const alerts = stats.alerts_by_source || {};
  drawPie($('pie-alerts'), Object.keys(alerts).sort((a, b) => alerts[b] - alerts[a])
    .map(k => ({ label: SOURCE_LABELS[k] || pretty(k), value: alerts[k], color: SOURCE_COLORS[k] || '#98a1b3' })));
}

/* ---------- scenarios / mode ---------- */
function renderStatus(sys) {
  state.mode = sys.mode;
  $('mode-simulation').classList.toggle('on', sys.mode === 'simulation');
  $('mode-live').classList.toggle('on', sys.mode === 'live');
  document.querySelectorAll('[data-scenario]').forEach(b => { b.disabled = sys.mode !== 'simulation'; });
  const s = sys.scenario, box = $('scenario-status');
  box.classList.toggle('running', !!s.running);
  box.textContent = s.running ? `Running ${s.title}: event ${s.step}${s.total ? ' of ' + s.total : ''}`
    : (s.name ? `${s.title} finished` : (sys.mode === 'live' ? 'Live mode: scenarios are disabled' : 'No scenario running'));
  const err = sys.live_collectors && !sys.live_collectors.available && sys.mode === 'live';
  banner(err ? 'Live collectors are unavailable on this machine (needs Windows netsh/PowerShell). Showing simulated values instead. ' + (sys.live_collectors.error || '') : '');
}

document.querySelectorAll('[data-scenario]').forEach(b => b.addEventListener('click', async () => {
  try { await post('/api/scenarios/start', { scenario: b.dataset.scenario }); banner(''); } catch (e) { banner(e.message, 6000); }
  refresh();
}));
$('btn-stop').addEventListener('click', async () => { try { await post('/api/scenarios/stop'); } catch (e) { banner(e.message, 6000); } refresh(); });
$('btn-reset').addEventListener('click', async () => { try { await post('/api/reset'); state.selected = null; } catch (e) { banner(e.message, 6000); } refresh(); });
['simulation', 'live'].forEach(m => $('mode-' + m).addEventListener('click', async () => {
  try { await post('/api/mode', { mode: m }); } catch (e) { banner(e.message, 6000); } refresh();
}));

/* ---------- guided demo (the final demo flow, automated) ---------- */
const DEMO_STEPS = [
  'Dashboard is open and the Trust Score is visible',
  'Coordinated Intrusion scenario started',
  'Events arrive one by one in the live feed',
  'Several weak signals are collected',
  'Correlation recognises a composite incident',
  'Severity score is calculated and explained',
  'Priority is calculated and the incident enters the analyst queue',
  'Analyst capacity is respected',
  'Recommended response actions appear',
  'Analyst acknowledges: status becomes INVESTIGATING',
  'Analyst resolves: queue and statistics update',
];
const demo = { running: false, done: 0 };
const sleep = ms => new Promise(r => setTimeout(r, ms));

function renderDemo() {
  const ol = $('demo-steps');
  clear(ol);
  DEMO_STEPS.forEach((text, i) => ol.appendChild(el('li', i < demo.done ? 'done' : (i === demo.done && demo.running ? 'now' : ''), text)));
}
function demoMark(n) { if (n > demo.done) { demo.done = n; renderDemo(); } }

async function runDemo() {
  if (demo.running) return;
  if (state.mode !== 'simulation') { banner('The guided demo runs in Simulation mode. Switch the mode first.', 6000); return; }
  demo.running = true; demo.done = 0;
  $('demo-panel').hidden = false; $('btn-demo').disabled = true;
  renderDemo();
  try {
    await post('/api/reset'); state.selected = null;
    demoMark(1);
    await post('/api/scenarios/start', { scenario: 'coordinated_intrusion' });
    demoMark(2);
    let inc = null;
    while (demo.running) {                                    // follow the scenario and tick steps as they really happen
      await sleep(600);
      const [events, incidents, queue, sys] = await Promise.all([api('/api/events?limit=50'), api('/api/incidents'), api('/api/analyst-queue'), api('/api/system-status')]);
      if (events.length >= 1) demoMark(3);
      if (events.length >= 3) demoMark(4);
      inc = incidents[0] || null;
      if (inc) {
        state.selected = inc.incident_id;
        demoMark(5);
        if (inc.severity_breakdown.length && inc.explanation) demoMark(6);
        if (inc.priority_rank) demoMark(7);
        if (queue.active_count <= queue.capacity) demoMark(8);
        if (inc.recommended_actions.length) demoMark(9);
      }
      if (!sys.scenario.running && inc && demo.done >= 9) break;
    }
    if (demo.running) {
      await sleep(2500); await post(`/api/incidents/${encodeURIComponent(inc.incident_id)}/acknowledge`); demoMark(10);
      await sleep(3000); await post(`/api/incidents/${encodeURIComponent(inc.incident_id)}/resolve`); demoMark(11);
    }
  } catch (e) { banner('Demo stopped: ' + e.message, 6000); }
  demo.running = false; $('btn-demo').disabled = false; renderDemo(); refresh();
}
$('btn-demo').addEventListener('click', runDemo);
$('btn-demo-stop').addEventListener('click', async () => {
  demo.running = false;
  try { await post('/api/scenarios/stop'); } catch (e) { /* ignore */ }
  $('demo-panel').hidden = true; $('btn-demo').disabled = false; refresh();
});

/* ---------- polling ---------- */
async function refresh() {
  try {
    const [trust, stats, incidents, queue, events, sys] = await Promise.all([
      api('/api/trust-score'), api('/api/statistics'), api('/api/incidents'),
      api('/api/analyst-queue'), api('/api/events?limit=30'), api('/api/system-status'),
    ]);
    state.trust = trust;
    renderTrust(trust); renderKpis(stats); renderIncidents(incidents); renderQueue(queue);
    renderDetail(); renderSignals(stats, trust); renderPies(stats); renderStatus(sys); renderFeed(events, incidents);
  } catch (err) {
    console.error('Dashboard refresh failed:', err);
    banner('Cannot reach the SOC server. Retrying...');
  }
}
refresh();
setInterval(refresh, POLL_MS);
