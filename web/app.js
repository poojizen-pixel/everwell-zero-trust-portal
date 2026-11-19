'use strict';
/*
 * Everwell Health Portal - browser client of the Zero Trust hospital information system demonstration (academic, SYNTHETIC patient data only).
 *
 * Rules this file follows (checked by tests/e2e/run_e2e.ps1):
 *   - no API that parses HTML strings is used anywhere (the runner greps for them): every piece of server data is inserted as TEXT
 *   - the session token and the step-up PIN live only in JavaScript memory; nothing secret is written to any browser storage
 *     (the only stored value is a random, non-secret device identifier, key "zt_device_id")
 *   - the client never decides access: roles, assignments, wards, risk and emergency access are decided by the server on every request;
 *     what is hidden in the interface is hidden for convenience only (the demonstration tools prove it by calling the API directly)
 *   - simulated signals are always labelled as simulated; only the signed laptop agent produces measured values
 */
(function () {
  // ================================================================ small DOM helpers
  function h(tag, attrs) {
    const e = document.createElement(tag);
    const a = attrs || {};
    for (const k of Object.keys(a)) {
      const v = a[k];
      if (k === 'class') e.className = v;
      else if (k === 'text') e.textContent = v;
      else if (k === 'style') setStyle(e, String(v));      // CSSOM only: the page's CSP (style-src 'self') forbids inline style attributes
      else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2), v);
      else if (v === true) e.setAttribute(k, '');
      else if (v !== false && v != null) e.setAttribute(k, String(v));
    }
    for (let i = 2; i < arguments.length; i++) add(e, arguments[i]);
    return e;
  }
  function setStyle(e, css) {
    css.split(';').forEach((d) => {
      const i = d.indexOf(':');
      if (i > 0) e.style.setProperty(d.slice(0, i).trim(), d.slice(i + 1).trim());
    });
  }
  function add(parent, kid) {
    if (kid == null || kid === false) return;
    if (Array.isArray(kid)) { kid.forEach((k) => add(parent, k)); return; }
    parent.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); return node; }
  const $ = (id) => document.getElementById(id);

  // Icons are built with the DOM (never from markup strings); stroke icons on a 24 x 24 grid.
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const ICONS = {
    menu: 'M3 6h18|M3 12h18|M3 18h18',
    x: 'M18 6 6 18|M6 6l12 12',
    users: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2|M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z|M23 21v-2a4 4 0 0 0-3-3.87|M16 3.13a4 4 0 0 1 0 7.75',
    user: 'M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2|M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z',
    calendar: 'M5 4h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z|M16 2v4|M8 2v4|M3 10h18',
    shield: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
    'shield-check': 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z|M9 12l2 2 4-4',
    activity: 'M22 12h-4l-3 9L9 3l-3 9H2',
    clipboard: 'M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2|M9 2h6a1 1 0 0 1 1 1v2a1 1 0 0 1-1 1H9a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1z|M9 12h6|M9 16h6',
    file: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z|M14 2v6h6|M16 13H8|M16 17H8|M10 9H8',
    laptop: 'M4 5h16a1 1 0 0 1 1 1v10H3V6a1 1 0 0 1 1-1z|M1 19h22',
    phone: 'M7 2h10a2 2 0 0 1 2 2v16a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2z|M12 18h.01',
    sliders: 'M4 21v-7|M4 10V3|M12 21v-9|M12 8V3|M20 21v-5|M20 12V3|M1 14h6|M9 8h6|M17 16h6',
    alert: 'M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z|M12 9v4|M12 17h.01',
    bell: 'M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9|M13.73 21a2 2 0 0 1-3.46 0',
    list: 'M8 6h13|M8 12h13|M8 18h13|M3 6h.01|M3 12h.01|M3 18h.01',
    lock: 'M5 11h14a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2z|M7 11V7a5 5 0 0 1 10 0v4',
    logout: 'M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4|M16 17l5-5-5-5|M21 12H9',
    search: 'M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16z|M21 21l-4.35-4.35',
    'chevron-left': 'M15 18l-6-6 6-6',
    'chevron-right': 'M9 18l6-6-6-6',
    clock: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z|M12 6v6l4 2',
    wifi: 'M5 12.55a11 11 0 0 1 14.08 0|M1.42 9a16 16 0 0 1 21.16 0|M8.53 16.11a6 6 0 0 1 6.95 0|M12 20h.01',
    refresh: 'M23 4v6h-6|M1 20v-6h6|M3.51 9a9 9 0 0 1 14.85-3.36L23 10|M1 14l4.64 4.36A9 9 0 0 0 20.49 15',
    pill: 'M10.5 20.5 3.5 13.5a4.95 4.95 0 0 1 7-7l7 7a4.95 4.95 0 0 1-7 7z|M8.5 8.5l7 7',
    info: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z|M12 16v-4|M12 8h.01',
    'check-circle': 'M22 11.08V12a10 10 0 1 1-5.93-9.14|M22 4 12 14.01l-3-3',
    'x-circle': 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z|M15 9l-6 6|M9 9l6 6',
    flask: 'M9 3h6|M10 3v6L4 20a1 1 0 0 0 .9 1.5h14.2A1 1 0 0 0 20 20l-6-11V3',
    download: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4|M7 10l5 5 5-5|M12 15V3',
    plus: 'M12 5v14|M5 12h14',
    grid: 'M3 3h7v9H3z|M14 3h7v5h-7z|M14 12h7v9h-7z|M3 16h7v5H3z',
    monitor: 'M2 4h20v12H2z|M8 20h8|M12 16v4',
    pause: 'M6 4h4v16H6z|M14 4h4v16h-4z',
    play: 'M5 3l14 9-14 9z'
  };
  function icon(name, cls) {
    const s = document.createElementNS(SVG_NS, 'svg');
    s.setAttribute('class', 'icon' + (cls ? ' ' + cls : ''));
    s.setAttribute('viewBox', '0 0 24 24');
    s.setAttribute('aria-hidden', 'true');
    s.setAttribute('focusable', 'false');
    String(ICONS[name] || ICONS.info).split('|').forEach((d) => { const p = document.createElementNS(SVG_NS, 'path'); p.setAttribute('d', d); s.appendChild(p); });
    return s;
  }

  // ================================================================ formatting and vocabulary
  const pad = (n) => String(n).padStart(2, '0');
  // Branding: one place for the names shown to users (hospital name, portal name, tagline).
  const BRAND = { hospital: 'Everwell Hospital', portal: 'Everwell Health Portal', tagline: 'Compassionate Care. Trusted Access.' };
  const ROLE = { doctor: 'Doctor', nurse: 'Nurse', receptionist: 'Receptionist', security_admin: 'Security administrator' };
  // Evaluation mode is the one place where a CLINICAL session shows its own risk, device posture and network status and offers the simulation
  // controls (it exists so the academic demonstration can show those decisions). It is off unless the page is opened with ?evaluation=1 AND the
  // security administrator has left the evaluation tools enabled (policy simulation.enabled). The normal clinical workspace never shows them.
  const EVALUATION = (() => { try { return new URLSearchParams(location.search).get('evaluation') === '1'; } catch (e) { return false; } })();
  function fmtTime(ts) { if (!ts) return '-'; const d = new Date(ts * 1000); return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()); }
  function fmtDay(ts) { if (!ts) return '-'; const d = new Date(ts * 1000); return d.toLocaleDateString([], { day: 'numeric', month: 'short' }) + ', ' + pad(d.getHours()) + ':' + pad(d.getMinutes()); }
  function parseAppt(s) { const m = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2})$/.exec(String(s || '')); return m ? new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5]) : null; }
  function fmtAppt(s) {
    const d = parseAppt(s);
    if (!d) return s ? String(s) : 'Not scheduled';
    return d.toLocaleDateString([], { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric' }) + ', ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  }
  function relAppt(s) {
    const d = parseAppt(s);
    if (!d) return '';
    const day = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
    const n = Math.round((day(d) - day(new Date(serverNow()))) / 86400000);       // "today" is the server's today, not this device's clock
    if (n === 0) return 'today';
    if (n === 1) return 'tomorrow';
    if (n > 1) return 'in ' + n + ' days';
    if (n === -1) return 'yesterday';
    return Math.abs(n) + ' days ago';
  }
  function fmtDob(s) { const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(s || '')); return m ? new Date(+m[1], +m[2] - 1, +m[3]).toLocaleDateString([], { day: 'numeric', month: 'short', year: 'numeric' }) : String(s || '-'); }
  function ageOf(dob) {
    const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(dob || ''));
    if (!m) return null;
    const n = new Date(serverNow());
    let a = n.getFullYear() - +m[1];
    if (n.getMonth() + 1 < +m[2] || (n.getMonth() + 1 === +m[2] && n.getDate() < +m[3])) a--;
    return a;
  }
  function initials(name) {
    const w = String(name || '').split(/\s+/).filter((x) => x && !x.endsWith('.'));
    return ((w[0] || '?')[0] + ((w[1] || '')[0] || '')).toUpperCase();
  }
  function mmss(ms) { const s = Math.max(0, Math.ceil(ms / 1000)); return pad(Math.floor(s / 60)) + ':' + pad(s % 60); }
  function spanWords(seconds) { return seconds >= 120 ? Math.round(seconds / 60) + ' minutes' : seconds + ' seconds'; }
  // A short, stable fingerprint of a device id: administrators can tell devices apart without a computer name ever appearing on screen.
  function fingerprint(id) {
    let x = 0x811c9dc5;
    const s = String(id || '');
    for (let i = 0; i < s.length; i++) { x ^= s.charCodeAt(i); x = Math.imul(x, 16777619) >>> 0; }
    return x.toString(16).toUpperCase().padStart(8, '0').slice(0, 6);
  }
  // What kind of browser this page runs in, from its user agent. It is sent at sign-in as the device label, so a desktop browser is never
  // called a phone. The server keeps only these three names (anything else becomes "Browser").
  function browserKindLabel() {
    const ua = navigator.userAgent || '';
    if (/iPad|Tablet|Android(?!.*Mobile)/i.test(ua) || (/Macintosh/i.test(ua) && navigator.maxTouchPoints > 1)) return 'Tablet browser';
    if (/iPhone|iPod|Android.*Mobile|Mobile/i.test(ua)) return 'Phone browser';
    return 'Desktop browser';
  }
  const BROWSER_LABELS = ['Phone browser', 'Tablet browser', 'Desktop browser'];
  // The name shown for a device. Whether it is a signed laptop agent or a browser is the server's knowledge; a browser's own description is
  // shown only when it is one of the known labels, and a laptop is never named after its computer.
  function deviceLabel(kind, label) { return kind === 'agent' ? 'Registered laptop' : BROWSER_LABELS.includes(label) ? label : 'Browser'; }
  function deviceName(kind, id, label) { return deviceLabel(kind, label) + ' ' + fingerprint(id); }

  // What the server's evidence about a device supports. The vocabulary is exact: Verified (measured, fresh, nothing wrong), Unhealthy (the
  // evidence shows a problem), Stale (the last report is older than the server trusts), Unknown (nothing verifiable: a browser can only
  // report about itself), Simulated (a demonstration value, not a measurement), Unavailable (no record or no report at all). "Not applicable"
  // is listed per device kind: signals that do not exist for that kind are never shown as healthy or as missing.
  function deviceAssessment(d) {
    const agent = d.kind === 'agent';
    const age = typeof d.heartbeat_age === 'number' && d.heartbeat_age >= 0 ? d.heartbeat_age : null;
    const limit = typeof d.stale_after_seconds === 'number' ? d.stale_after_seconds : null;
    const reason = String(d.block_reason || '');
    const sigs = d.signals || [];
    const bad = sigs.filter((s) => /^(off|none|disabled|outdated|inactive|invalid)$/i.test(String(s.value)));
    const unknown = sigs.filter((s) => /^(unknown|not exposed by this browser)$/i.test(String(s.value))).map((s) => s.name);
    const notApplicable = agent ? 'screen lock, OS patch level, device protection and installed-app state (browser-only signals)' : 'firewall, antivirus and agent signature (laptop-agent-only signals)';
    const base = { age, limit, agent, unknown, notApplicable, source: agent ? 'Signed laptop agent: measured (firewall, antivirus), signed with a key shared with the server' : 'The web page: self-reported. Screen lock, OS patch level and device protection cannot be read by a browser, so those three are simulated defaults' };
    if (age === null) return Object.assign(base, { state: 'unavailable', label: 'Unavailable', kind: 'unknown', why: 'The server has no report from this device.' });
    if (/signature invalid/i.test(reason)) return Object.assign(base, { state: 'unhealthy', label: 'Unhealthy', kind: 'bad', why: 'The signed report was rejected: ' + reason + '.' });
    if (d.posture === 'blocked' && (/heartbeat stale|agent stopped/i.test(reason) || (limit !== null && age > limit))) return Object.assign(base, { state: 'stale', label: 'Stale', kind: 'warn', why: 'The last report is ' + age + ' s old; the server trusts a report for ' + (limit === null ? 'a limited time' : limit + ' s') + '.' });
    if (d.posture === 'blocked') return Object.assign(base, { state: 'unhealthy', label: 'Unhealthy', kind: 'bad', why: reason || 'The device does not meet the policy.' });
    if (d.posture === 'degraded' || bad.length) return Object.assign(base, { state: 'unhealthy', label: 'Unhealthy', kind: 'bad', why: 'Reported as not in order: ' + (bad.map((s) => s.name + ' ' + s.value + (/^SIMULATED/i.test(String(s.source)) ? ' (simulated)' : '')).join(', ') || 'posture score above the baseline') + '.' });
    if (agent && d.agent_simulated) return Object.assign(base, { state: 'simulated', label: 'Simulated', kind: 'sim', why: 'The agent runs in demonstration mode: firewall and antivirus values are simulated, not measured.' });
    if (agent) return Object.assign(base, { state: 'verified', label: 'Verified', kind: 'ok', why: 'Measured by the signed agent ' + age + ' s ago (trusted for ' + (limit === null ? 'a limited time' : limit + ' s') + '): firewall on, a security product registered.' });
    return Object.assign(base, { state: 'unknown', label: 'Unknown', kind: 'unknown', why: 'Self-reported only; a browser cannot be measured.' + (unknown.length ? ' No value yet for: ' + unknown.join(', ') + '.' : '') });
  }
  // What the server's evidence about the network of a session supports.
  function networkEvidence(n) {
    if (!n || !n.origin_ip) return { state: 'unknown', label: 'Unknown', kind: 'unknown', text: 'No address evidence from the server.' };
    const loop = /^(127\.|::1$|0:0:0:0:0:0:0:1$)/.test(String(n.effective_ip || n.origin_ip));
    const where = loop ? ' The address is a local one: on a local test connection or a USB route the server cannot see the real network, so a change could not be detected.' : '';
    if (n.simulated_ip) {
      return n.change === 'none'
        ? { state: 'simulated', label: 'Unchanged (simulated address)', kind: 'sim', text: 'A demonstration setting makes the server evaluate this session as coming from ' + n.simulated_ip + '; the session already adopted that address as its baseline (after the step-up PIN), so nothing differs from it now.' }
        : { state: 'simulated', label: 'Changed (simulated)', kind: 'sim', text: 'A demonstration setting makes the server evaluate this session as coming from ' + n.simulated_ip + '.' };
    }
    if (n.change === 'none') return { state: 'unchanged', label: loop ? 'Unchanged (local address)' : 'Unchanged', kind: loop ? 'unknown' : 'ok', text: 'The server saw the same address at sign-in and at this check.' + where };
    return { state: 'changed', label: 'Changed', kind: 'warn', text: 'The address seen now differs from the address at sign-in (' + (n.change === 'same_subnet' ? 'same subnet' : 'different subnet') + ').' };
  }
  // Server text such as audit reasons can quote a raw device identifier (the laptop's identifier is derived from the computer name): show the fingerprint form instead.
  function scrub(text) {
    return String(text == null ? '' : text).replace(/\b(DEV|WEB|PHONE)-[A-Za-z0-9._:-]{3,}/g, (m, kind) => (kind === 'DEV' ? 'Registered laptop ' : 'Browser ') + fingerprint(m));
  }

  function badge(text, kind) { return h('span', { class: 'badge ' + (kind || ''), text: String(text == null ? '-' : text) }); }
  const DECISION = { ALLOW: ['Allowed', 'ok'], STEP_UP: ['Step-up required', 'warn'], DENY: ['Denied', 'bad'], REVOKE: ['Session revoked', 'solid-bad'], REJECTED: ['Rejected', 'warn'], OFFLINE: ['Offline', 'warn'] };
  function decisionBadge(code) { const d = DECISION[code]; return d ? badge(d[0], d[1]) : badge(code || '-', ''); }
  function riskInfo(points, threshold) {
    const pct = threshold > 0 ? Math.min(100, Math.round((points * 100) / threshold)) : 0;
    return pct >= 60 ? { pct, level: 'High', kind: 'bad' } : pct >= 25 ? { pct, level: 'Elevated', kind: 'warn' } : { pct, level: 'Low', kind: 'ok' };
  }
  function meter(pct, kind) { const m = h('div', { class: 'meter ' + (kind || ''), role: 'img', 'aria-label': 'Risk ' + pct + ' percent of the limit' }, h('span')); m.firstChild.style.setProperty('--pct', String(pct)); return m; }
  function dl(pairs) {
    const el = h('dl', { class: 'kv' });
    pairs.filter(Boolean).forEach(([k, v]) => { el.append(h('dt', { text: k }), h('dd', {}, v == null ? '-' : v)); });
    return el;
  }
  function panel(title, bodyNodes, opts) {
    const o = opts || {};
    return h('section', { class: 'panel' + (o.class ? ' ' + o.class : ''), id: o.id },
      title || o.head ? h('div', { class: 'panel-head' }, title ? h('h' + (o.level || 2), {}, o.icon ? icon(o.icon, 'sm') : null, title) : null, o.head || null) : null,
      h('div', { class: 'panel-body' + (o.flush ? ' flush' : '') }, bodyNodes));
  }
  function skeleton(lines) { const box = h('div', { 'aria-busy': 'true', 'aria-label': 'Loading' }); for (let i = 0; i < (lines || 3); i++) box.append(h('span', { class: 'skeleton ' + ['w80', '', 'w60', 'w40'][i % 4] })); return box; }
  function emptyState(iconName, title, text) { return h('div', { class: 'empty' }, icon(iconName || 'info'), h('strong', { text: title }), text ? h('span', { text }) : null); }
  function alertBox(kind, title, text, opts) {
    const o = opts || {};
    const mark = { ok: 'check-circle', warn: 'alert', bad: 'x-circle', info: 'info' };
    const body = h('div', { class: 'a-body' }, title ? h('span', { class: 'a-title', text: title }) : null, text ? h('p', { text }) : null);
    if (o.detail) body.append(h('details', {}, h('summary', { text: 'Technical detail' }), h('p', { class: 'small', text: o.detail })));
    add(body, o.actions);
    return h('div', { class: 'alert ' + kind, role: kind === 'bad' || kind === 'warn' ? 'alert' : 'status' }, icon(mark[kind] || 'info'), body);
  }
  function toast(text) {
    let region = $('toasts');
    if (!region) { region = h('div', { id: 'toasts', class: 'toast-region', 'aria-live': 'polite' }); document.body.append(region); }
    const t = h('div', { class: 'toast', role: 'status', text });
    region.append(t);
    setTimeout(() => t.remove(), 4500);
  }

  // ================================================================ state (memory only)
  const state = {
    token: null, pin: null, user: null, session: null, ttl: 90,
    deviceId: null, deviceKind: 'browser', agentId: null,
    timers: {}, installPrompt: null, online: navigator.onLine,
    viewToken: 0, shell: null, log: [], grants: {},
    // session timing, from the server: when this page last made a protected request (that is what the server's idle timer counts), the idle limit,
    // the maximum session end, the server's clock relative to this page's, and when the session was last confirmed by the server
    lastActivity: Date.now(), idleSeconds: 0, absoluteExpires: 0, clockOffsetMs: 0, checkedAt: 0
  };
  const serverNow = () => Date.now() + state.clockOffsetMs;
  const app = $('app');

  function browserDeviceId() {
    let id = null;
    try { id = localStorage.getItem('zt_device_id'); } catch (e) { id = null; }
    if (!id || !/^[A-Za-z0-9._:-]{6,80}$/.test(id)) {
      const b = new Uint8Array(9);
      crypto.getRandomValues(b);
      id = (/Android|iPhone|iPad|Mobile/i.test(navigator.userAgent) ? 'PHONE-' : 'WEB-') + Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
      try { localStorage.setItem('zt_device_id', id); } catch (e) { /* storage unavailable: the id is simply not remembered */ }
    }
    return id;
  }
  function platformName() { return (navigator.userAgentData && navigator.userAgentData.platform) || (/Android/i.test(navigator.userAgent) ? 'Android' : /Windows/i.test(navigator.userAgent) ? 'Windows' : 'Web'); }
  function collectSignals() {
    const c = navigator.connection || {};
    return {
      secure_context: window.isSecureContext === true,
      standalone: (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) || navigator.standalone === true,
      online: navigator.onLine,
      visible: document.visibilityState === 'visible',
      connection: c.effectiveType || c.type || 'not exposed',
      platform: platformName()
    };
  }

  // ================================================================ API
  const ENDED = new Set(['session_revoked', 'session_expired', 'session_ended', 'session_unknown', 'account_locked', 'token_invalid', 'token_expired', 'token_missing']);

  async function api(method, path, body, opts) {
    const o = opts || {};
    const headers = { 'X-Device-Id': state.deviceId || '' };
    if (state.token && !o.noToken) headers.Authorization = 'Bearer ' + state.token;
    if (state.pin && !o.noToken && !o.noPin) headers['X-StepUp-Pin'] = state.pin;
    if (body !== undefined && body !== null) headers['Content-Type'] = 'application/json';
    let res;
    try {
      res = await fetch(path, { method, headers, body: body == null ? undefined : JSON.stringify(body), cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
    } catch (e) {
      setOnline(false);
      return { status: 0, data: { error: 'offline', message: 'The hospital network cannot be reached.' } };
    }
    setOnline(true);
    let data = {};
    try { data = await res.json(); } catch (e) { data = {}; }
    return { status: res.status, data };
  }

  // What the page can truthfully say about the outcome of one request.
  function decisionOf(r) {
    const d = r.data || {};
    if (r.status >= 200 && r.status < 300) return 'ALLOW';
    if (r.status === 0) return 'OFFLINE';
    if (d.error === 'step_up_required') return 'STEP_UP';
    if (d.session_revoked || ENDED.has(d.error)) return 'REVOKE';
    if (r.status === 401 || r.status === 403) return 'DENY';
    return 'REJECTED';
  }
  function requestLabel(method, path) {
    const role = state.user && state.user.role;
    let m;
    if (path === '/api/patients/list') return role === 'receptionist' ? 'Patient registry' : 'Patient list';
    if ((m = /^\/api\/patients\/(\d+)\/(summary|records|export-pdf|appointment)$/.exec(path))) {
      if (role === 'receptionist' && (m[2] === 'records' || m[2] === 'export-pdf')) return 'Restricted request (patient ' + m[1] + ')';
      return 'Patient ' + m[1] + ': ' + ({ summary: 'demographics', records: 'clinical record', 'export-pdf': 'record export', appointment: 'appointment change' })[m[2]];
    }
    if (path === '/ctl/break-glass') return 'Emergency access request';
    if (path === '/ctl/simulate') return 'Simulation change';
    if (path === '/api/public/info') return 'Hospital information';
    if (path.startsWith('/admin/')) return 'Administration: ' + path.slice(7).replace(/\//g, ' ');
    return path;
  }
  function note(method, path, r) {
    const decision = decisionOf(r);
    state.log.unshift({ at: Date.now() / 1000, label: requestLabel(method, path), decision, status: r.status, title: decision === 'ALLOW' ? '' : explain(r).title });
    if (state.log.length > 30) state.log.length = 30;
  }

  // A protected call: handles the step-up challenge and the end of the session in one place.
  async function call(method, path, body, opts) {
    const o = opts || {};
    let r = await api(method, path, body, o);
    for (let attempt = 0; attempt < 3 && r.status === 401 && r.data.error === 'step_up_required' && !o.noPrompt; attempt++) {
      const pin = await askPin(r.data.message, attempt > 0);
      if (!pin) break;
      state.pin = pin;
      r = await api(method, path, body, o);
    }
    if (r.data && r.data.error === 'bad_step_up_pin') state.pin = null;
    if (typeof (r.data || {}).session_risk === 'number' && state.session && state.session.session) {
      state.session.session.risk_points = r.data.session_risk;
      updateStatus();
    }
    if (!o.quiet) note(method, path, r);
    if (r.status !== 0) state.lastActivity = Date.now();       // a protected request the server counted as activity (renewals and heartbeats go through api(), not here)
    if (r.data && ENDED.has(r.data.error) && state.token) endSession(r.data);
    return r;
  }

  function setOnline(on) {
    if (state.online === on) return;
    state.online = on;
    const b = $('offline-banner');
    if (b) b.classList.toggle('hidden', on);
  }

  // ---- friendly explanations of what the server decided (title, own wording; the server's text stays available as technical detail)
  // [kind, title, own text (null = use the server's), true = never show the server's wording as the main text (it carries policy numbers or addresses)]
  const EXPLAIN = {
    step_up_required: ['warn', 'Additional verification required', 'The policy asks for your step-up PIN before this request can continue.'],
    bad_step_up_pin: ['bad', 'PIN not accepted', 'Wrong PINs add to your session risk, and repeated failures end the session.'],
    not_assigned: ['bad', 'Patient not assigned to you', 'Only patients assigned to you can be opened. In a genuine emergency a doctor can request time-limited emergency access.'],
    ward_denied: ['bad', 'Patient is on another ward', 'Nurses can open patients on their own ward only. Ask the charge nurse if this patient has been transferred.'],
    role_denied: ['bad', 'Not permitted for your role', 'Your role does not include this function. The attempt was recorded and added to your session risk.'],
    forbidden_at_resource: ['bad', 'Refused by the records service', 'The records service checked your role and assignment again and refused this request.'],
    export_not_permitted: ['bad', 'Export not available', 'Emergency access allows reading the summary and clinical record only. Only a doctor assigned to the patient can export.'],
    not_found: ['warn', 'No such patient', 'Check the patient number and try again.'],
    posture_blocked: ['bad', 'This device does not meet the security policy', 'Fix the device condition shown under Session & access, then try again.', true],
    network_blocked: ['bad', 'Network change not allowed', 'The network of this session changed and the policy does not allow it. Return to the original network or sign in again.', true],
    risk_too_high: ['bad', 'Request blocked: risk too high', 'The combined risk of this device, network and request is above the allowed level. Resolve the device or network condition and try again.', true],
    managed_device_required: ['bad', 'Registered laptop required', 'This function is only available from the agent-verified laptop.'],
    unknown_endpoint: ['warn', 'Unsupported request', 'The server does not offer this function.'],
    invalid_appointment: ['warn', 'Appointment not saved', null],
    bad_request: ['warn', 'Request not understood', null],
    rate_limited: ['warn', 'Too many attempts', 'Wait a few minutes and try again.'],
    justification_required: ['warn', 'Justification required', null],
    justification_too_long: ['warn', 'Justification too long', null],
    break_glass_limit: ['warn', 'Emergency access limit reached', null],
    break_glass_disabled: ['warn', 'Emergency access is switched off', 'The security policy currently disables emergency access.'],
    not_needed: ['info', 'You already have access', null],
    simulation_disabled: ['warn', 'Simulation is switched off', 'The security administrator has disabled the simulation controls.'],
    not_simulatable: ['info', 'Posture is measured on this device', 'The signed laptop agent measures this device, so it cannot be simulated here.'],
    offline: ['warn', 'Cannot reach the hospital network', 'Check your connection and try again. Nothing is stored on this device while you are offline.'],
    already_ended: ['info', 'Session already ended', null],
    bad_policy_change: ['warn', 'Policy change rejected', null]
  };
  // The same outcomes in plain words for people who work with patients: what happened and what to do. No risk, score, policy or device wording.
  const EXPLAIN_PLAIN = {
    step_up_required: ['warn', 'Additional verification required', 'Enter your step-up PIN to continue.'],
    bad_step_up_pin: ['bad', 'PIN not accepted', 'Check your PIN and try again. Repeated wrong PINs end your session.'],
    not_assigned: ['bad', 'Patient not on your list', 'Only patients assigned to you can be opened. If the number is wrong, check it and try again. In a genuine emergency a doctor can request time-limited emergency access.'],
    ward_denied: ['bad', 'Patient not on your ward', 'Nurses can open patients of their own ward only. If the number is wrong, check it and try again. Ask the charge nurse if this patient has been transferred.'],
    role_denied: ['bad', 'Not available for your role', 'Your role does not include this function. The attempt was recorded.'],
    forbidden_at_resource: ['bad', 'Not available', 'The records service did not allow this request.'],
    posture_blocked: ['bad', 'Access unavailable on this device', 'This device does not currently meet the hospital\'s security requirements. Contact IT support or the security team.'],
    network_blocked: ['bad', 'Access unavailable from this network', 'The network connection of this session changed. Return to the original network or sign in again.'],
    risk_too_high: ['bad', 'Request blocked for security reasons', 'Try again later, or contact the security team if you need this now.']
  };
  // Who may see the server's own wording, reference codes and policy figures: the security administrator and, in evaluation mode, the person
  // evaluating. Everybody else gets plain language only.
  function evaluationOn() { return EVALUATION && !!state.user && state.user.role !== 'security_admin' && !!state.session && state.session.simulation_enabled === true && state.session.detail === 'full'; }
  const techVisible = () => !!state.user && (state.user.role === 'security_admin' || evaluationOn());
  function explain(r) {
    const d = (r && r.data) || {};
    const code = d.error || (r && r.status === 0 ? 'offline' : '');
    const server = String(d.message || '');
    const tech = techVisible();
    const e = (!tech && EXPLAIN_PLAIN[code]) || EXPLAIN[code];
    if (!e) return { kind: r && r.status >= 500 ? 'bad' : 'warn', title: 'The request was refused', text: tech ? (server || 'The server did not accept this request.') : 'The request could not be completed. Try again, and contact IT support if it keeps failing.', detail: tech && code ? 'Reference: ' + code : '', code };
    const own = e[2];
    const text = own || server;
    const parts = [];
    if (tech) {
      if (own && server && server !== own) parts.push(server);
      if (code) parts.push('Reference: ' + code + (r && r.status ? ' (HTTP ' + r.status + ')' : ''));
    }
    return { kind: e[0], title: e[1], text, detail: parts.join(' - '), code };
  }
  function errorAlert(r, actions) { const e = explain(r); return alertBox(e.kind, e.title, e.text, { detail: e.detail, actions }); }

  // ================================================================ session lifecycle
  function stopTimers() { Object.keys(state.timers).forEach((k) => { clearInterval(state.timers[k]); clearTimeout(state.timers[k]); }); state.timers = {}; }

  function resetSessionState() {
    stopTimers();
    teardownView();
    state.token = null; state.pin = null; state.user = null; state.session = null; state.log = []; state.grants = {};
    state.lastActivity = Date.now(); state.idleSeconds = 0; state.absoluteExpires = 0; state.checkedAt = 0;
    unmountShell();
  }
  function endSession(data) {
    const tech = techVisible();          // decided before the state is cleared: the security administrator and evaluation mode see the detail
    resetSessionState();
    renderEnded(data || {}, tech);
  }

  function scheduleRenew() {
    clearTimeout(state.timers.renew);
    state.timers.renew = setTimeout(renewToken, Math.max(10, state.ttl * 0.6) * 1000);
  }
  async function renewToken() {
    if (!state.token) return;
    const r = await api('POST', '/ctl/renew');
    if (r.status === 200 && r.data.token) { state.token = r.data.token; state.ttl = r.data.expires_in || state.ttl; scheduleRenew(); return; }
    if (r.data && ENDED.has(r.data.error)) { if (state.token) endSession(r.data); return; }
    if (r.status === 0) { state.timers.renew = setTimeout(renewToken, 5000); return; }   // offline: try again soon
    scheduleRenew();
    if (r.data && r.data.message) toast(explain(r).title);
  }

  function startHeartbeat() {
    clearInterval(state.timers.heartbeat);
    if (state.deviceKind !== 'browser') return;    // a laptop is reported by its posture agent, not by the page
    const beat = async () => {
      if (!state.token) return;
      const r = await api('POST', '/ctl/heartbeat', { signals: collectSignals() });
      if (r.data && ENDED.has(r.data.error) && state.token) endSession(r.data);     // revoked elsewhere (administrator, policy): show it now
    };
    state.timers.heartbeat = setInterval(beat, 10000);
    beat();
  }

  async function resume() {
    if (!state.token) return;
    await renewToken();
    if (state.token) { await api('POST', '/ctl/heartbeat', { signals: collectSignals() }); await refreshSession(); }
  }

  // Puts the SIMULATED signals of this browser device back to normal (posture switches on, real network address). Works even while the device
  // is blocked, because the simulate endpoint is one of the few that stay reachable for exactly this reason.
  async function resetSimulation() {
    await call('POST', '/ctl/simulate', { kind: 'posture', screen_lock: true, os_current: true, protection: true }, { noPrompt: true, quiet: true });
    const r = await call('POST', '/ctl/simulate', { kind: 'network', ip: 'reset' }, { noPrompt: true, quiet: true });
    if (state.token) { await refreshSession(); toast(r.status === 200 ? 'Simulated signals reset' : explain(r).title); }
    return r;
  }

  async function refreshSession() {
    if (!state.token) return null;
    const r = await call('GET', '/ctl/session', null, { noPrompt: true, quiet: true });
    if (r.status === 200) {
      state.session = r.data;
      state.checkedAt = Date.now();
      const s = r.data.session || {};
      state.idleSeconds = s.idle_timeout_seconds || 0;
      state.absoluteExpires = s.absolute_expires_at || 0;
      if (typeof r.data.server_time === 'number') state.clockOffsetMs = r.data.server_time * 1000 - Date.now();
      updateStatus();
    }
    return r.status === 200 ? r.data : null;
  }

  async function doLogin(username, password, mode) {
    state.deviceKind = mode === 'laptop' ? 'agent' : 'browser';
    state.deviceId = mode === 'laptop' ? state.agentId : browserDeviceId();
    const r = await api('POST', '/ctl/login', {
      username, password, device_kind: state.deviceKind,
      device_label: mode === 'laptop' ? 'Registered laptop' : browserKindLabel(),
      platform: platformName(), signals: collectSignals()
    }, { noToken: true });
    if (r.status === 200 && r.data.token) {
      state.token = r.data.token; state.ttl = r.data.expires_in || 90; state.user = r.data.user; state.pin = null; state.log = []; state.grants = {};
      state.lastActivity = Date.now();
      scheduleRenew(); startHeartbeat();
      await refreshSession();
      const first = navFor(state.user.role).find((n) => n.id);
      history.replaceState(null, '', '#/' + (first ? first.id : 'patients'));
      render();
      return { ok: true };
    }
    return { ok: false, message: (r.data && r.data.message) || (r.status === 0 ? 'The hospital network cannot be reached.' : 'Sign-in failed.') };
  }

  async function doLogout() {
    if (state.token) await api('POST', '/ctl/logout');
    resetSessionState();
    renderLogin('You signed out. The session was closed on the server.');
  }

  // ================================================================ dialogs (native <dialog>: focus is trapped, Escape cancels, focus returns)
  let dialogSeq = 0;
  function openDialog(o) {
    return new Promise((resolve) => {
      const opener = document.activeElement;
      const id = 'dlg-' + (++dialogSeq);
      let result = null;
      const message = h('div', { class: 'dlg-message', 'aria-live': 'polite' });
      const submit = o.submitLabel === null ? null : h('button', { class: 'btn ' + (o.submitKind || 'primary'), type: 'submit', text: o.submitLabel || 'OK' });
      const cancel = o.cancelLabel === null ? null : h('button', { class: 'btn', type: 'button', text: o.cancelLabel || 'Cancel', onclick: () => dlg.close() });
      const ctx = {
        close: (v) => { result = v === undefined ? true : v; dlg.close(); },
        busy: (b) => { if (submit) submit.disabled = !!b; if (cancel) cancel.disabled = !!b; dlg.setAttribute('aria-busy', b ? 'true' : 'false'); },
        say: (node) => { clear(message); if (node) message.append(node); },
        dialog: null
      };
      const form = h('form', { novalidate: true, onsubmit: async (ev) => {
        ev.preventDefault();
        if (!o.onSubmit) { ctx.close(true); return; }
        ctx.busy(true);
        try { await o.onSubmit(ctx); } finally { if (dlg.open) ctx.busy(false); }
      } },
      h('div', { class: 'modal-head' }, h('h2', { id: id + '-title', text: o.title })),
      h('div', { class: 'modal-body' }, o.body, message),
      h('div', { class: 'modal-foot' }, cancel, submit));
      const dlg = h('dialog', { class: 'modal', 'aria-labelledby': id + '-title' }, form);
      ctx.dialog = dlg;
      dlg.addEventListener('close', () => {
        dlg.remove();
        if (opener && opener.isConnected && typeof opener.focus === 'function') opener.focus();
        resolve(result);
      });
      dlg.addEventListener('click', (ev) => { if (ev.target === dlg && !dlg.getAttribute('aria-busy')) dlg.close(); });
      document.body.append(dlg);
      if (typeof dlg.showModal === 'function') dlg.showModal(); else dlg.setAttribute('open', '');
      if (o.onOpen) o.onOpen(ctx);
    });
  }

  let pinPrompt = null;
  function askPin(reason, again) {
    if (pinPrompt) return pinPrompt;                 // several requests waiting for the same PIN share one prompt
    const input = h('input', { class: 'input', id: 'pin-input', type: 'password', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '12', 'aria-label': 'Step-up PIN', autofocus: true });
    pinPrompt = openDialog({
      title: 'Additional verification',
      body: [
        alertBox(again ? 'bad' : 'warn', again ? 'That PIN was not accepted' : 'Verification required', again ? (techVisible() ? 'Wrong PINs add to your session risk.' : 'Check the PIN and try again. Repeated wrong PINs end your session.') : (techVisible() ? 'The security policy needs your step-up PIN before this request can continue.' : 'Enter your step-up PIN to continue with this request.'), { detail: techVisible() ? (reason || '') : '' }),
        h('div', { class: 'field' }, h('label', { class: 'label', for: 'pin-input', text: 'Step-up PIN' }), input)
      ],
      submitLabel: 'Verify',
      onSubmit: (ctx) => ctx.close(input.value.trim() || null)
    }).finally(() => { pinPrompt = null; });
    return pinPrompt;
  }

  // ================================================================ sign-in
  // The page can only truthfully report the protocol it was loaded with. (window.isSecureContext is also true for http://localhost and
  // http://127.0.0.1, so it must never be used to claim HTTPS.)
  function connectionStatus() {
    if (location.protocol === 'https:') return { kind: 'ok', text: 'Secure connection (HTTPS)' };
    const local = ['localhost', '127.0.0.1', '[::1]'].includes(location.hostname);
    return { kind: 'warn', text: local ? 'Local test connection (HTTP): not encrypted, this device only' : 'Connection not encrypted (HTTP)' };
  }
  const DEVICE_HINT = {
    browser: 'Posture is self-reported by this page. Screen lock, OS patch level and device protection are simulated: a browser cannot read them.',
    browserNoAgent: ' The registered laptop is unavailable here: no signed posture agent is reporting.',
    laptop: 'Firewall and antivirus posture are measured by the signed posture agent on this laptop.'
  };

  function brandBar(cls) {
    return h('div', { class: cls },
      h('img', { class: 'brand-mark', src: '/icons/icon-192.png', alt: '' }),
      h('div', {}, h('span', { class: 'brand-name', text: BRAND.hospital }), h('span', { class: 'brand-sub', text: BRAND.tagline })));
  }

  async function renderLogin(notice) {
    stopTimers();
    clear(app);
    document.title = 'Sign in - ' + BRAND.hospital;
    try { history.replaceState(null, '', location.pathname + location.search); } catch (e) { /* the address bar simply keeps its fragment */ }
    let agents = [];
    const ar = await api('GET', '/ctl/agents', null, { noToken: true });
    if (ar.status === 200 && ar.data.agents) agents = ar.data.agents;
    state.agentId = agents.length ? agents[0].device_id : null;          // used only to address the registered laptop; never displayed

    const user = h('input', { class: 'input', type: 'text', id: 'u', name: 'username', autocomplete: 'username', autocapitalize: 'none', spellcheck: 'false', required: true });
    const pass = h('input', { class: 'input', type: 'password', id: 'p', name: 'password', autocomplete: 'current-password', required: true });
    const reveal = h('button', { class: 'reveal', type: 'button', 'aria-pressed': 'false', 'aria-controls': 'p', text: 'Show', onclick: () => {
      const on = pass.type === 'password';
      pass.type = on ? 'text' : 'password';
      reveal.textContent = on ? 'Hide' : 'Show';
      reveal.setAttribute('aria-pressed', on ? 'true' : 'false');
    } });
    const msg = h('div', { id: 'login-msg', 'aria-live': 'polite' });
    const modeBrowser = h('input', { type: 'radio', name: 'mode', value: 'browser', id: 'mode-browser', checked: true });
    const modeLaptop = h('input', { type: 'radio', name: 'mode', value: 'laptop', id: 'mode-laptop', disabled: !state.agentId });
    const hint = h('p', { class: 'hint', id: 'device-hint', 'aria-live': 'polite' });
    const showHint = () => { hint.textContent = modeLaptop.checked ? DEVICE_HINT.laptop : DEVICE_HINT.browser + (state.agentId ? '' : DEVICE_HINT.browserNoAgent); };
    modeBrowser.addEventListener('change', showHint);
    modeLaptop.addEventListener('change', showHint);
    showHint();
    const seg = h('div', { class: 'seg', role: 'radiogroup', 'aria-labelledby': 'device-label' },
      h('label', { class: 'seg-opt' }, modeBrowser, h('span', { text: 'This browser' })),
      h('label', { class: 'seg-opt' + (state.agentId ? '' : ' is-disabled'), title: state.agentId ? null : 'No signed posture agent is reporting on this device' }, modeLaptop, h('span', { text: 'Registered laptop' })));
    const install = h('button', { class: 'btn block hidden', type: 'button', id: 'install-btn', text: 'Install app on this device', onclick: async () => {
      if (!state.installPrompt) return;
      state.installPrompt.prompt();
      await state.installPrompt.userChoice;
      state.installPrompt = null;
      install.classList.add('hidden');
    } });
    if (state.installPrompt) install.classList.remove('hidden');
    const submit = h('button', { class: 'btn primary block', type: 'submit', text: 'Sign in' });
    const form = h('form', { onsubmit: async (ev) => {
      ev.preventDefault();
      submit.disabled = true; clear(msg);
      const mode = modeLaptop.checked ? 'laptop' : 'browser';
      const res = await doLogin(user.value.trim(), pass.value, mode);
      pass.value = '';
      if (!res.ok) { msg.append(alertBox('bad', null, res.message)); submit.disabled = false; }
    } },
      h('div', { class: 'field' }, h('label', { class: 'label', for: 'u', text: 'Username' }), user),
      h('div', { class: 'field' }, h('label', { class: 'label', for: 'p', text: 'Password' }), h('div', { class: 'input-group' }, pass, reveal)),
      h('div', { class: 'field' }, h('span', { class: 'label', id: 'device-label', text: 'Device' }), seg, hint),
      msg,
      h('div', { class: 'stack tight' }, submit, install));

    const conn = connectionStatus();
    app.append(h('div', { class: 'login' },
      brandBar('login-bar'),
      h('div', { class: 'banner-stack' }, h('div', { id: 'offline-banner', class: state.online ? 'hidden' : '' }, alertBox('warn', 'You are offline', 'The portal needs the hospital network.'))),
      h('main', { class: 'login-main', id: 'main' }, h('div', { class: 'login-card' },
        notice ? alertBox('info', null, notice) : null,
        h('section', { class: 'panel' }, h('div', { class: 'panel-body' },
          h('p', { class: 'login-eyebrow', text: BRAND.portal }),
          h('h1', { text: 'Staff sign-in' }),
          h('p', { class: 'muted small lead', text: 'Use your hospital account. Every request is checked again for identity, device, network and patient access.' }),
          form)),
        h('p', { class: 'conn ' + conn.kind, id: 'conn-status', role: 'status' }, h('span', { class: 'dot', 'aria-hidden': 'true' }), conn.text),
        h('p', { class: 'login-note', text: 'Authorised staff only. Activity is monitored and recorded.' }),
        h('p', { class: 'login-note', text: 'Academic demonstration - synthetic patient data only.' })))));
    user.focus();
  }

  // The end-of-session screen. People who work with patients are told in plain words what happened and what to do; the decision, the risk figures
  // and the reference code are shown only to the security administrator and in evaluation mode (tech).
  function renderEnded(d, tech) {
    clear(app);
    document.title = 'Session ended - ' + BRAND.hospital;
    try { history.replaceState(null, '', location.pathname + location.search); } catch (e) { /* ignore */ }
    const lockedNow = d.error === 'account_locked';                                    // the account was already locked when this request arrived
    const lockMatch = /locked until (\d{1,2}:\d{2})/i.exec(d.message || '');            // a risk revocation also locks the account for a while
    const expired = d.error === 'session_expired';
    const revoked = !expired && (d.session_revoked === true || d.error === 'session_revoked');
    const risk = tech && typeof d.session_risk === 'number' && d.revoke_threshold ? riskInfo(d.session_risk, d.revoke_threshold) : null;
    let headline, alertTitle, alertText;
    if (tech) {
      headline = lockedNow ? 'Account locked' : 'Session ended';
      alertTitle = revoked ? 'Session revoked' : lockedNow ? 'Sign-in blocked' : 'Sign-in required';
      alertText = d.message || 'Your session is no longer valid.';
    } else if (lockedNow) {
      headline = 'Account locked'; alertTitle = 'Sign-in blocked';
      alertText = 'This account is locked' + (lockMatch ? ' until ' + lockMatch[1] : '') + '. Wait, or ask a security administrator to unlock it.';
    } else if (expired) {
      headline = 'Session expired'; alertTitle = 'Please sign in again';
      alertText = /maximum length/i.test(d.message || '') ? 'Your session reached its maximum length.' : 'Your session expired after a period without activity.';
    } else if (revoked) {
      headline = 'Session ended'; alertTitle = 'Your session was ended for security reasons';
      alertText = (lockMatch ? 'Your account is locked until ' + lockMatch[1] + '. ' : '') + 'Please sign in again.';
    } else {
      headline = 'Session ended'; alertTitle = 'Sign-in required'; alertText = 'Please sign in again to continue.';
    }
    app.append(h('div', { class: 'login' },
      brandBar('login-bar'),
      h('main', { class: 'ended', id: 'main' },
        h('section', { class: 'panel' }, h('div', { class: 'panel-body' },
          h('h1', {}, icon(lockedNow ? 'lock' : 'shield', 'lg'), headline),
          alertBox(expired ? 'warn' : 'bad', alertTitle, alertText),
          tech ? dl([
            ['Decision', decisionBadge(revoked || lockedNow ? 'REVOKE' : 'DENY')],
            risk ? ['Session risk at the end', h('span', {}, badge(risk.level, risk.kind), ' ', d.session_risk + ' of ' + d.revoke_threshold + ' points')] : null,
            lockMatch ? ['Account', 'Locked until ' + lockMatch[1]] : null,
            ['Reference', h('span', { class: 'mono', text: d.error || 'n/a' })]
          ]) : null,
          h('p', { class: 'small muted', text: tech ? 'The old session can no longer be used: not by this page, another tab, the back button or a direct API call. Signing in again starts a new session with a fresh risk count.' : 'The old session can no longer be used. Signing in again starts a new session.' }),
          h('div', { class: 'btn-row' }, h('button', { class: 'btn primary', id: 'signin-again', type: 'button', text: 'Sign in again', onclick: () => renderLogin() })))))));
  }

  // ================================================================ navigation, shell and router
  // [id, label, icon, optional tag]  /  { group: label }
  // Explicit, role-aware navigation. Clinical workspaces and security operations are separate: no clinical role has a security screen, and the
  // security administrator has no patient screen. The interface offers only what the work of the role needs; the server enforces access on every
  // request either way (a hidden item or a disabled button is a convenience, never the control).
  const NAV = {
    doctor: [{ group: 'Clinical' }, { id: 'patients', label: 'My patients', icon: 'users' }],
    nurse: [{ group: 'Clinical' }, { id: 'patients', label: 'Ward patients', icon: 'users' }],
    receptionist: [{ group: 'Front desk' }, { id: 'patients', label: 'Patient registry', icon: 'users' }, { id: 'appointments', label: 'Appointments', icon: 'calendar' }],
    security_admin: [{ group: 'Security operations' }, { id: 'overview', label: 'Overview', icon: 'grid' }, { id: 'sessions', label: 'Sessions', icon: 'activity' }, { id: 'devices', label: 'Devices & posture', icon: 'laptop' }, { id: 'decisions', label: 'Access decisions', icon: 'shield-check' }, { id: 'audit', label: 'Audit log', icon: 'list' },
      { group: 'Administration' }, { id: 'users', label: 'Users & access', icon: 'user' }, { id: 'policy', label: 'Policy', icon: 'sliders' }, { group: 'Account' }, { id: 'session', label: 'My session', icon: 'lock' }]
  };
  // Added to a clinical role's navigation only in evaluation mode (see EVALUATION): the screens that show the user's own session, device and
  // network evidence and the simulation controls.
  const EVAL_NAV = [{ group: 'Evaluation mode (demonstration only)' }, { id: 'session', label: 'My session', icon: 'shield-check' }, { id: 'demo', label: 'Demonstration tools', icon: 'flask' }];
  function navFor(role) { return (NAV[role] || []).concat(role !== 'security_admin' && evaluationOn() ? EVAL_NAV : []); }
  const VIEWS = {};      // filled further down: id -> function (root, ctx) returning an optional { update(param), destroy() }
  let current = null;    // { id, token, api, cleanups }

  function parseHash() {
    const m = /^#\/([a-z]+)(?:\/(\d{1,9}))?$/.exec(location.hash);
    return m ? { view: m[1], param: m[2] ? Number(m[2]) : null } : null;
  }
  function go(view, param, replace) {
    const target = '#/' + view + (param != null ? '/' + param : '');
    if (location.hash === target) { render(); return; }
    if (replace) { history.replaceState(null, '', target); render(); } else location.hash = target;     // a hash change triggers render()
  }

  function teardownView() {
    if (!current) return;
    const c = current;
    current = null;
    state.viewToken++;
    c.cleanups.forEach((fn) => { try { fn(); } catch (e) { /* a view failing to clean up must not block navigation */ } });
    if (c.api && c.api.destroy) { try { c.api.destroy(); } catch (e) { /* same */ } }
  }

  function chipEl(id, kind, text, href) {
    const dot = h('span', { class: 'dot', 'aria-hidden': 'true' });
    const el = href ? h('a', { class: 'chip ' + (kind || ''), id, href }, dot, h('span', { text })) : h('span', { class: 'chip ' + (kind || ''), id }, dot, h('span', { text }));
    return el;
  }
  function setChip(id, kind, text, title) {
    const el = $(id);
    if (!el) return;
    el.className = 'chip ' + (kind || '') + (el.classList.contains('chip-extra') ? ' chip-extra' : '');
    el.lastChild.textContent = text;
    if (title) el.setAttribute('title', title);
  }

  function navLinks() {
    const links = h('ul', { class: 'nav-list' });
    navFor(state.user.role).forEach((n) => {
      if (n.group) { links.append(h('li', { class: 'nav-label', 'aria-hidden': 'true', text: n.group })); return; }
      // choosing the screen that is already open changes no address (so no render): the drawer must close all the same
      links.append(h('li', {}, h('a', { class: 'nav-link', href: '#/' + n.id, 'data-view': n.id, onclick: () => closeNav(false) }, icon(n.icon), h('span', { text: n.label }), n.tag ? h('span', { class: 'tag', text: n.tag }) : null)));
    });
    return links;
  }
  function markCurrentNav(id) {
    document.querySelectorAll('.nav-link').forEach((a) => { if (a.getAttribute('data-view') === id) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); });
  }
  // The navigation follows what the role is offered right now: evaluation mode appears or disappears when the administrator changes the policy.
  function syncNav() {
    const s = state.shell;
    if (!s || !state.user) return;
    const key = navFor(state.user.role).map((n) => n.id || n.group).join('|');
    if (key === s.navKey) return;
    s.navKey = key;
    clear(s.navScroll).append(navLinks());
    if (current) markCurrentNav(current.id);
    syncChips();
    if (current && !navFor(state.user.role).some((n) => n.id === current.id)) render();      // the open screen is no longer offered
  }
  // The status chips exist only in evaluation mode: a clinical user's session, device and network are the server's business, not a dashboard.
  // (The security administrator's console has no chips either: a chip about one's own session next to other users' alerts reads as system status.)
  function syncChips() {
    const s = state.shell;
    if (!s) return;
    if (!evaluationOn()) { clear(s.chipHost); s.chipHost.hidden = true; return; }
    s.chipHost.hidden = false;
    if ($('chip-risk')) return;
    const chipSession = chipEl('chip-session', 'unknown', 'Session ...', '#/session'); chipSession.classList.add('chip-extra');
    const chipNet = chipEl('chip-net', 'unknown', 'Network ...'); chipNet.classList.add('chip-extra');
    const chipDevice = chipEl('chip-device', 'unknown', 'Device ...'); chipDevice.classList.add('chip-extra');
    const chipRisk = chipEl('chip-risk', 'unknown', 'Session risk ...', '#/session');
    s.chipHost.append(h('span', { class: 'eval-pill', id: 'eval-pill', title: 'This page was opened in evaluation mode and the security administrator has the evaluation tools switched on.', text: 'Evaluation mode' }), chipSession, chipNet, chipDevice, chipRisk);
    updateStatus();
  }

  function mountShell() {
    if (state.shell) return;
    const u = state.user;
    clear(app);
    const links = navLinks();
    const toggle = h('button', { class: 'icon-btn nav-toggle', id: 'nav-toggle', type: 'button', 'aria-label': 'Open menu', 'aria-expanded': 'false', 'aria-controls': 'sidenav', onclick: () => (shellEl.dataset.nav === 'open' ? closeNav(true) : openNav()) }, icon('menu'));
    const closeBtn = h('button', { class: 'icon-btn nav-close', id: 'nav-close', type: 'button', 'aria-label': 'Close menu', onclick: () => closeNav(true) }, icon('x'));
    const scrim = h('div', { class: 'scrim', hidden: true, onclick: () => closeNav(true) });
    const roleText = (ROLE[u.role] || u.role) + (u.role === 'nurse' && u.ward ? ' - Ward ' + u.ward : '');
    const chipHost = h('div', { class: 'status-chips', 'aria-label': 'Evaluation mode: status of this session', hidden: true });
    const accountBtn = h('button', { class: 'icon-btn account-btn', id: 'account-btn', type: 'button', 'aria-haspopup': 'dialog', 'aria-label': 'Account: ' + u.display_name + ', ' + roleText, title: 'Account', onclick: openAccount }, h('span', { class: 'avatar sm', 'aria-hidden': 'true', text: initials(u.display_name) }));
    const navScroll = h('nav', { class: 'nav-scroll', 'aria-label': 'Primary' }, links);
    const sideNav = h('aside', { class: 'sidenav', id: 'sidenav', 'aria-label': 'Main navigation' },
      h('div', { class: 'sidenav-head' }, h('img', { class: 'brand-mark', src: '/icons/icon-192.png', alt: '' }), h('div', {}, h('span', { class: 'brand-name', text: BRAND.hospital }), h('span', { class: 'brand-sub', text: 'Health Portal' })), closeBtn),
      navScroll,
      h('div', { class: 'sidenav-foot' },
        h('div', { class: 'user-card' }, h('span', { class: 'avatar', 'aria-hidden': 'true', text: initials(u.display_name) }), h('div', { class: 'who' }, h('strong', { id: 'user-name', text: u.display_name }), h('span', { id: 'user-role', text: roleText }))),
        h('button', { class: 'btn', id: 'signout-btn', type: 'button', onclick: doLogout }, icon('logout', 'sm'), 'Sign out')));
    const mainCol = h('div', { class: 'main-col', id: 'main-col' },
      h('header', { class: 'topbar' }, toggle, h('div', { class: 'title-block' }, h('span', { class: 'topbar-eyebrow', text: u.role === 'security_admin' ? BRAND.hospital + ' - Security operations' : BRAND.hospital }), h('h1', { id: 'page-title', tabindex: '-1', text: '' })), chipHost, accountBtn),
      h('div', { class: 'banner-stack' }, h('div', { id: 'offline-banner', class: state.online ? 'hidden' : '' }, alertBox('warn', 'You are offline', 'Nothing is stored on this device. Reconnect to continue.')), h('div', { id: 'session-notice', 'aria-live': 'polite' })),
      h('main', { class: 'page', id: 'main', tabindex: '-1' }));
    const shellEl = h('div', { class: 'shell', id: 'shell', 'data-nav': 'closed' },
      h('button', { class: 'skip-link', type: 'button', text: 'Skip to main content', onclick: () => $('main').focus() }), sideNav, scrim, mainCol);
    app.append(shellEl);
    state.shell = { el: shellEl, toggle, scrim, sideNav, mainCol, navScroll, chipHost, navKey: navFor(u.role).map((n) => n.id || n.group).join('|') };
    syncChips();
    clearInterval(state.timers.notice);
    state.timers.notice = setInterval(paintNotice, 1000);
    paintNotice();
  }
  function unmountShell() { state.shell = null; }

  function openNav() {
    const s = state.shell;
    if (!s) return;
    s.el.dataset.nav = 'open';
    s.toggle.setAttribute('aria-expanded', 'true');
    s.toggle.setAttribute('aria-label', 'Close menu');
    s.scrim.hidden = false;
    s.mainCol.inert = true;
    const target = s.sideNav.querySelector('.nav-link[aria-current="page"]') || s.sideNav.querySelector('.nav-link');
    if (target) target.focus();
  }
  function closeNav(returnFocus) {
    const s = state.shell;
    if (!s || s.el.dataset.nav !== 'open') return;
    s.el.dataset.nav = 'closed';
    s.toggle.setAttribute('aria-expanded', 'false');
    s.toggle.setAttribute('aria-label', 'Open menu');
    s.scrim.hidden = true;
    s.mainCol.inert = false;
    if (returnFocus) s.toggle.focus();
  }

  // The chips (evaluation mode only) say what the SERVER's evidence supports, with the time it was confirmed, and name the thing they refer to
  // (this session, this device, this session's network). Unknown stays unknown: a browser is never "healthy", an address that cannot change is
  // never "unchanged", and a session not confirmed for a minute says so.
  function updateStatus() {
    const s = state.session;
    if (!s || !state.shell) return;
    syncNav();
    const sess = s.session || {};
    if ($('chip-risk') && s.detail === 'full' && s.device && s.network) {
      const r = riskInfo(sess.risk_points, sess.revoke_threshold);
      setChip('chip-risk', r.kind, 'Session risk: ' + r.level, 'Risk of YOUR session: ' + sess.risk_points + ' of ' + sess.revoke_threshold + ' penalty points. At the limit the server ends the session.');
      const d = s.device;
      const a = deviceAssessment(d);
      setChip('chip-device', a.kind, deviceLabel(d.kind, d.label) + ' - ' + a.label, 'YOUR device. ' + a.why);
      const n = networkEvidence(s.network);
      setChip('chip-net', n.kind, 'Network: ' + n.label, 'YOUR session\'s network. ' + n.text);
      paintSessionChip();
    }
    document.querySelectorAll('[data-live-risk]').forEach((el) => { el.dispatchEvent(new CustomEvent('riskchange')); });
  }
  function paintSessionChip() {
    if (!$('chip-session') || !state.checkedAt) return;
    const when = fmtTime(state.checkedAt / 1000);
    if (Date.now() - state.checkedAt <= 60000) setChip('chip-session', 'ok', 'Session confirmed ' + when, 'The server confirmed YOUR session at this time.');
    else setChip('chip-session', 'unknown', 'Session unconfirmed (last check ' + when + ')', 'The server last confirmed your session more than a minute ago.');
  }

  // The compact account menu: who is signed in, when the session ends, sign out. Asks the server first, so what it shows has just been confirmed.
  async function openAccount() {
    if (!state.user) return;
    const u = state.user;
    const info = await refreshSession();
    if (!state.token) return;                   // the session had ended: the end-of-session screen is showing
    const s = (info && info.session) || {};
    const idle = state.idleSeconds;
    const rows = [
      ['Signed in as', u.display_name],
      ['Role', (ROLE[u.role] || u.role) + (u.role === 'nurse' && u.ward ? ', Ward ' + u.ward : '')],
      s.created_at ? ['Signed in at', fmtDay(s.created_at)] : null,
      ['Session', info ? 'Active - confirmed by the server at ' + fmtTime(state.checkedAt / 1000) : 'Could not be confirmed just now'],
      idle ? ['Automatic sign-out', 'after ' + (idle >= 120 ? Math.round(idle / 60) + ' minutes' : idle + ' seconds') + ' without activity'] : null,
      state.absoluteExpires ? ['Longest session', 'ends at ' + fmtDay(state.absoluteExpires)] : null
    ];
    const res = await openDialog({ title: 'Account', body: [dl(rows)], submitLabel: 'Sign out', cancelLabel: 'Close' });
    if (res && state.token) doLogout();
  }

  // Minimal, actionable session feedback: the idle sign-out and the end of the longest session are announced shortly before they happen, from the
  // limits the server reports. (The session ending for other reasons shows the end-of-session screen.)
  let noticeKey = '';
  function paintNotice() {
    const box = $('session-notice');
    if (!box || !state.token) return;
    paintSessionChip();
    const idleLeft = state.idleSeconds > 0 ? state.lastActivity + state.idleSeconds * 1000 - Date.now() : Infinity;
    const absLeft = state.absoluteExpires > 0 ? state.absoluteExpires * 1000 - serverNow() : Infinity;
    const showIdle = idleLeft > 0 && idleLeft <= 120000;
    const showAbs = absLeft > 0 && absLeft <= 300000;
    const key = (showIdle ? 'i' : '') + (showAbs ? 'a' : '');
    if (key === noticeKey) return;
    noticeKey = key;
    clear(box);
    if (showIdle) {
      const idle = alertBox('warn', 'You will be signed out soon', 'Because of inactivity your session ends at ' + fmtTime((state.lastActivity + state.idleSeconds * 1000) / 1000) + '.', { actions: [h('button', { class: 'btn small', id: 'stay-signed-in', type: 'button', text: 'Stay signed in', onclick: async () => { await refreshSession(); paintNotice(); } })] });
      idle.id = 'idle-notice';
      box.append(idle);
    }
    if (showAbs) {
      const max = alertBox('info', 'Maximum session length', 'Sessions have a maximum length. This one ends at ' + fmtDay(state.absoluteExpires) + '. Finish what you are doing and sign in again afterwards.');
      max.id = 'max-notice';
      box.append(max);
    }
  }

  function viewLabel(id) { const n = navFor(state.user.role).find((x) => x.id === id); return n ? n.label : 'Portal'; }

  function render() {
    if (!state.token || !state.user) return;
    const items = navFor(state.user.role).filter((n) => n.id);
    const ids = items.map((n) => n.id);
    const r = parseHash();
    const id = r && ids.includes(r.view) ? r.view : ids[0];
    const param = r && r.view === id ? r.param : null;
    if (!r || r.view !== id) { try { history.replaceState(null, '', '#/' + id); } catch (e) { /* ignore */ } }
    mountShell();
    closeNav(false);
    markCurrentNav(id);
    if (current && current.id === id && current.api && current.api.update) { current.api.update(param); return; }
    const sameView = current && current.id === id;
    teardownView();
    const token = ++state.viewToken;
    const cur = { id, token, api: null, cleanups: [] };
    current = cur;
    const title = viewLabel(id);
    $('page-title').textContent = title;
    document.title = title + ' - ' + BRAND.hospital;
    const root = clear($('main'));
    const ctx = {
      id, param, root,
      stale: () => token !== state.viewToken || !state.token,
      every: (fn, ms) => { const t = setInterval(fn, ms); const stop = () => clearInterval(t); cur.cleanups.push(stop); return stop; },
      later: (fn, ms) => { const t = setTimeout(fn, ms); cur.cleanups.push(() => clearTimeout(t)); return t; },
      onDestroy: (fn) => { cur.cleanups.push(fn); }
    };
    const view = VIEWS[id] || VIEWS.session;
    cur.api = view(root, ctx) || null;
    if (!sameView) { window.scrollTo(0, 0); }
  }

  // ================================================================ tables
  // Real tables, shown as compact tables on desktop and as cards on phones (CSS only). Explicit ARIA roles keep the table semantics when
  // the layout changes. A column is { label, cell }, cell being 'cell-primary', 'cell-actions', 'wrap' or 'num'.
  function dataTable(cols, o) {
    const opts = o || {};
    const body = h('tbody', { role: 'rowgroup' });
    const table = h('table', { class: 'data' + (opts.stack === false ? '' : ' stack') + (opts.cls ? ' ' + opts.cls : ''), role: 'table', id: opts.id, 'aria-label': opts.label },
      h('thead', { role: 'rowgroup' }, h('tr', { role: 'row' }, cols.map((c) => h('th', { role: 'columnheader', scope: 'col', class: c.head || '', text: c.label })))), body);
    return { table, body, wrap: h('div', { class: 'table-wrap' }, table) };
  }
  function tableRow(cols, vals, attrs) {
    const row = h('tr', Object.assign({ role: 'row' }, attrs || {}));
    cols.forEach((c, i) => { const v = vals[i]; row.append(h('td', { role: 'cell', 'data-label': c.label, class: c.cell || '' }, v == null || v === '' ? '-' : v)); });
    return row;
  }
  function fmtApptShort(s) { const d = parseAppt(s); return d ? d.toLocaleDateString([], { day: 'numeric', month: 'short' }) + ', ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) : (s ? String(s) : 'Not scheduled'); }
  function fmtStamp(d) { return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()); }

  // ================================================================ patients (doctor, nurse, receptionist)
  function patientBanner(sum, basis) {
    const age = ageOf(sum.dob);
    const role = state.user.role;
    return h('div', { class: 'patient-banner', id: 'patient-banner' },
      h('span', { class: 'avatar', 'aria-hidden': 'true', text: initials(sum.name) }),
      h('div', { class: 'pb-main' },
        h('h2', { class: 'patient-name', text: sum.name }),
        h('div', { class: 'patient-meta' },
          h('span', {}, h('b', { text: 'ID' }), String(sum.patient_id)),
          h('span', {}, h('b', { text: 'DOB' }), fmtDob(sum.dob) + (age != null ? ' (' + age + ' y)' : '')),
          h('span', {}, h('b', { text: 'Ward' }), sum.ward),
          role === 'receptionist' ? null : h('span', {}, h('b', { text: 'Next visit' }), fmtApptShort(sum.next_appointment)))),
      role === 'doctor' ? (basis === 'break_glass' ? badge('Emergency access', 'warn') : badge('Assigned', 'ok')) : null);
  }
  function textPanel(title, iconName, text, id) {
    return h('section', { class: 'panel chart-section', id }, h('div', { class: 'panel-head' }, h('h3', {}, icon(iconName, 'sm'), title)), h('div', { class: 'panel-body' }, h('p', { class: 'record-text', text: text || 'None recorded.' })));
  }

  // One date and time pair -> "YYYY-MM-DD HH:MM" (the only format the server accepts); the server validates it again.
  function rescheduleDialog(p) {
    const now = new Date(serverNow());
    const cur = parseAppt(p.next_appointment) || now;
    const dateIn = h('input', { class: 'input', id: 'appt-date', type: 'date', required: true, min: fmtStamp(now).slice(0, 10), max: fmtStamp(new Date(now.getTime() + 365 * 86400000)).slice(0, 10), value: fmtStamp(cur).slice(0, 10) });
    const timeIn = h('input', { class: 'input', id: 'appt-time', type: 'time', required: true, step: '300', value: fmtStamp(cur).slice(11, 16) });
    return openDialog({
      title: 'Reschedule appointment',
      body: [
        dl([['Patient', p.name], ['ID', String(p.patient_id)], ['Current appointment', fmtAppt(p.next_appointment)]]),
        h('div', { class: 'grid two mt' },
          h('div', { class: 'field' }, h('label', { class: 'label', for: 'appt-date', text: 'New date' }), dateIn),
          h('div', { class: 'field' }, h('label', { class: 'label', for: 'appt-time', text: 'New time' }), timeIn)),
        h('p', { class: 'hint', text: 'Appointments can be moved up to 12 months ahead. The hospital system checks the new time again before saving.' })
      ],
      submitLabel: 'Save appointment',
      onSubmit: async (dctx) => {
        dctx.say(null);
        if (!dateIn.value || !timeIn.value) { dctx.say(alertBox('warn', 'Choose a date and a time', null)); return; }
        const value = dateIn.value + ' ' + timeIn.value.slice(0, 5);
        const r = await call('POST', '/api/patients/' + p.patient_id + '/appointment', { next_appointment: value });
        if (!state.token) { dctx.close(null); return; }
        if (r.status === 200) { dctx.close(r.data.next_appointment); return; }
        dctx.say(errorAlert(r));
      }
    });
  }

  // Emergency (break-glass) access: scoped, time-limited, justified. The server decides and enforces; this only collects the justification.
  function emergencyDialog(patientId) {
    const bg = (state.session && state.session.policy && state.session.policy.break_glass) || {};
    const min = bg.min_justification_chars || 20;
    const ta = h('textarea', { class: 'input', id: 'bg-justification', maxlength: '500', 'aria-describedby': 'bg-count', autofocus: true });
    const count = h('p', { class: 'hint', id: 'bg-count', text: '0 of at least ' + min + ' characters' });
    ta.addEventListener('input', () => { count.textContent = ta.value.trim().length + ' of at least ' + min + ' characters'; });
    const sure = h('input', { type: 'checkbox', id: 'bg-confirm' });
    return openDialog({
      title: 'Emergency access to patient ' + patientId,
      body: [
        alertBox('warn', 'Use only in a genuine emergency', null),
        h('ul', { class: 'scope-list' },
          h('li', { text: 'Read-only: the summary and clinical record of patient ' + patientId + ' only. No export.' }),
          h('li', { text: bg.duration_seconds ? 'Time-limited: ends automatically after ' + spanWords(bg.duration_seconds) + '.' : 'Time-limited: ends automatically.' }),
          h('li', { text: 'Valid for this sign-in only. Another session or a later sign-in does not inherit it.' }),
          h('li', { text: 'Recorded with your name and this justification, and reviewed by the security team. Repeated emergency requests can end your session.' })),
        h('div', { class: 'field' }, h('label', { class: 'label', for: 'bg-justification', text: 'Justification' }), ta, count,
          h('p', { class: 'hint', text: 'Give the reason for the emergency. Do not write diagnoses or other clinical details here: the security team reads this text.' })),
        h('label', { class: 'check', for: 'bg-confirm' }, sure, h('span', { text: 'I confirm this is a genuine emergency and understand the access is recorded.' }))
      ],
      submitLabel: 'Request emergency access',
      submitKind: 'danger',
      onSubmit: async (dctx) => {
        dctx.say(null);
        const just = ta.value.trim();
        if (just.length < min) { dctx.say(alertBox('warn', 'Justification too short', 'Please explain the emergency in at least ' + min + ' characters.')); ta.focus(); return; }
        if (!sure.checked) { dctx.say(alertBox('warn', 'Confirmation needed', 'Tick the confirmation to continue.')); return; }
        const r = await call('POST', '/ctl/break-glass', { patient_id: patientId, justification: just });
        if (!state.token) { dctx.close(null); return; }
        if (r.status === 200) { dctx.close(r.data); return; }
        dctx.say(errorAlert(r));
      }
    });
  }

  function maskedValue(value) {
    const s = String(value || '');
    const out = h('span', { class: 'masked', text: s.replace(/[0-9A-Za-z]/g, (c, i) => (i >= s.length - 4 ? c : '•')) });
    const btn = h('button', { class: 'link-btn', type: 'button', 'aria-pressed': 'false', text: 'Show' });
    btn.addEventListener('click', () => {
      const shown = btn.getAttribute('aria-pressed') === 'true';
      btn.setAttribute('aria-pressed', shown ? 'false' : 'true');
      btn.textContent = shown ? 'Show' : 'Hide';
      out.textContent = shown ? s.replace(/[0-9A-Za-z]/g, (c, i) => (i >= s.length - 4 ? c : '•')) : s;
    });
    return h('span', {}, out, ' ', btn);
  }
  function exportDialog(d) {
    return openDialog({
      title: 'Clinical summary export',
      body: [
        h('div', { class: 'doc' },
          h('h3', { text: d.name }),
          dl([['Date of birth', fmtDob(d.dob)], ['Ward', d.ward], ['Diagnosis', d.diagnosis], ['Medication', d.medication], ['National identifier', maskedValue(d.ssn)], ['Billing reference', maskedValue(d.billing)], ['Exported', new Date(d.exported_at).toLocaleString()]]),
          h('p', { class: 'doc-note', text: 'Simulated export document with synthetic identifiers. A real system would render a PDF here.' }))
      ],
      submitLabel: null,
      cancelLabel: 'Close'
    });
  }

  VIEWS.patients = function viewPatients(root, ctx) {
    const role = state.user.role;
    const isDoctor = role === 'doctor';
    const isRecep = role === 'receptionist';
    let patients = [];
    let selected = null;
    let chartSeq = 0;
    let stopCountdown = null;
    const noun = isRecep ? 'patient registry' : isDoctor ? 'assigned patients' : 'ward patients';

    const cols = [{ label: 'Patient', cell: 'cell-primary' }, { label: 'Ward' }, { label: isRecep ? 'Next appointment' : 'Next visit' }].concat(isDoctor ? [{ label: 'Access' }] : []);
    const dt = dataTable(cols, { id: 'patient-table', label: 'Patients: ' + noun, cls: 'patients' });
    const listBody = h('div', { class: 'list-scroll' });
    const countEl = h('span', { class: 'count', id: 'patient-count', text: '' });
    const search = h('input', { class: 'input', id: 'patient-search', type: 'search', placeholder: 'Search name, ID or ward', 'aria-label': 'Search patients by name, ID or ward', autocomplete: 'off' });
    const lookupIn = h('input', { class: 'input', id: 'lookup-id', type: 'text', inputmode: 'numeric', autocomplete: 'off', placeholder: 'Patient ID', 'aria-label': 'Patient ID' });
    const lookupMsg = h('p', { class: 'hint', 'aria-live': 'polite' });
    const emergencyBox = h('div', { id: 'emergency-list' });
    const upcomingBox = h('div', { class: 'upcoming', id: 'upcoming-visits' });
    const chartBody = h('div', { id: 'chart-body' });
    const backLink = h('a', { class: 'back-link', href: '#/patients' }, icon('chevron-left', 'sm'), 'All patients');
    const detail = h('div', { class: 'pane-detail', id: 'detail' }, backLink, chartBody);
    const workspace = h('div', { class: 'workspace', 'data-pane': 'list' });

    function paintRows() {
      const q = search.value.trim().toLowerCase();
      const rows = patients.filter((p) => !q || p.name.toLowerCase().includes(q) || String(p.patient_id) === q || String(p.patient_id).startsWith(q) || String(p.ward).toLowerCase().includes(q));
      clear(dt.body);
      rows.forEach((p) => {
        const open = () => go('patients', p.patient_id);
        const cells = [
          h('span', {}, h('a', { class: 'row-link primary', href: '#/patients/' + p.patient_id, text: p.name }), h('span', { class: 'sub', text: 'ID ' + p.patient_id + ' - DOB ' + fmtDob(p.dob) })),
          p.ward,
          h('span', {}, fmtApptShort(p.next_appointment), h('span', { class: 'sub', text: relAppt(p.next_appointment) }))
        ];
        if (isDoctor) cells.push(badge(p.access_basis === 'break_glass' ? 'Emergency' : 'Assigned', p.access_basis === 'break_glass' ? 'warn' : 'ok'));
        const tr = tableRow(cols, cells, { 'data-id': p.patient_id, 'aria-current': String(selected) === String(p.patient_id) ? 'true' : 'false' });
        tr.addEventListener('click', (ev) => { if (!ev.target.closest('a')) open(); });
        dt.body.append(tr);
      });
      countEl.textContent = rows.length === patients.length ? String(patients.length) : rows.length + ' of ' + patients.length;
      dt.wrap.classList.toggle('hidden', rows.length === 0);
      emptyList.classList.toggle('hidden', rows.length !== 0 || !loaded);
      if (loaded && rows.length === 0) clear(emptyList).append(emptyState('search', 'No match', 'No patient on this list matches "' + search.value.trim() + '".'));
    }
    let loaded = false;
    const emptyList = h('div', { class: 'hidden' });

    // The next visits among the patients on this list (doctor, nurse): the appointment times come from the server's records.
    function paintUpcoming() {
      clear(upcomingBox);
      if (isRecep) return;
      const now = serverNow();
      const next = patients.map((p) => ({ p, d: parseAppt(p.next_appointment) })).filter((x) => x.d && x.d.getTime() >= now).sort((a, b) => a.d - b.d).slice(0, 3);
      if (!next.length) return;
      upcomingBox.append(h('div', { class: 'upcoming-head' }, icon('calendar', 'sm'), h('strong', { text: 'Next visits' })),
        h('ul', { class: 'upcoming-list' }, next.map(({ p }) => h('li', {}, h('a', { class: 'row-link', href: '#/patients/' + p.patient_id, text: p.name }), h('span', { class: 'sub', text: fmtApptShort(p.next_appointment) + ' - ' + relAppt(p.next_appointment) + (isDoctor ? '' : ' - ward ' + p.ward) })))));
    }

    async function loadList() {
      clear(listBody).append(skeleton(5));
      const r = await call('GET', '/api/patients/list');
      if (ctx.stale()) return;
      clear(listBody);
      if (r.status !== 200) { listBody.append(h('div', { class: 'panel-body' }, errorAlert(r, [h('button', { class: 'btn small', type: 'button', text: 'Try again', onclick: loadList })]))); return; }
      patients = r.data.patients || [];
      loaded = true;
      paintUpcoming();
      if (!patients.length) listBody.append(emptyState('users', 'No patients assigned', 'There are no patients on your list at the moment.'));
      else listBody.append(dt.wrap, emptyList);
      paintRows();
    }

    function paintEmergencyList() {
      clear(emergencyBox);
      const ids = Object.keys(state.grants).filter((k) => state.grants[k].until > performance.now());
      if (!isDoctor || !ids.length) return;
      emergencyBox.append(h('div', { class: 'toolbar' }, h('div', { class: 'grow' },
        h('strong', { class: 'small', text: 'Emergency access in this session' }),
        h('ul', { class: 'scope-list' }, ids.map((k) => h('li', {}, h('a', { href: '#/patients/' + k, text: 'Patient ' + k }), ' - ends in ' + mmss(state.grants[k].until - performance.now())))))));
    }

    function showPlaceholder() { clear(chartBody).append(h('div', { class: 'panel' }, h('div', { class: 'detail-placeholder' }, emptyState('users', 'No patient selected', 'Choose a patient from the list to open the chart.')))); }

    function restricted(id, r) {
      const e = explain(r);
      const sec = h('section', { class: 'panel restricted', id: 'restricted' }, h('div', { class: 'panel-body' },
        h('h2', {}, icon('lock'), 'Patient ' + id),
        errorAlert(r, e.code === 'step_up_required' ? [h('button', { class: 'btn small', type: 'button', text: 'Verify and retry', onclick: () => openChart(id) })] : null)));
      if (isDoctor && e.code === 'not_assigned') {
        const bg = (state.session && state.session.policy && state.session.policy.break_glass) || {};
        sec.firstChild.append(h('h3', { text: 'Emergency access' }),
          h('p', { class: 'small', text: 'If this patient needs urgent care, you can request access that is limited in scope and time:' }),
          h('ul', { class: 'scope-list' },
            h('li', { text: 'Read-only: summary and clinical record of this patient only (no export).' }),
            h('li', { text: bg.duration_seconds ? 'Ends automatically after ' + spanWords(bg.duration_seconds) + ' and only in this sign-in.' : 'Ends automatically and only in this sign-in.' }),
            h('li', { text: 'A written justification is required; the request is recorded and reviewed by the security team.' })),
          bg.enabled === false ? alertBox('info', 'Emergency access is switched off by the security policy.', null)
            : h('div', { class: 'btn-row' }, h('button', { class: 'btn danger', id: 'emergency-btn', type: 'button', onclick: async () => {
              const g = await emergencyDialog(id);
              if (!g || !state.token) return;
              state.grants[id] = { until: performance.now() + g.seconds * 1000, seconds: g.seconds };
              toast(g.message || 'Emergency access granted.');
              paintEmergencyList();
              openChart(id);
              refreshSession();
            } }, icon('alert', 'sm'), 'Request emergency access')));
      }
      clear(chartBody).append(sec);
    }

    function expired(id) {
      delete state.grants[id];
      paintEmergencyList();
      clear(chartBody).append(h('section', { class: 'emergency expired', id: 'emergency-banner' },
        h('h2', {}, icon('lock'), 'Emergency access ended'),
        h('p', { text: 'The time-limited access to patient ' + id + ' has ended and the record is no longer shown. Requests for it are refused again.' }),
        h('div', { class: 'btn-row' }, h('button', { class: 'btn', type: 'button', text: 'Open patient again', onclick: () => openChart(id) }))));
    }

    function emergencyPanel(id) {
      const g = state.grants[id];
      const left = h('span', { class: 'countdown', id: 'emergency-left', text: g ? mmss(g.until - performance.now()) : 'time-limited' });
      const box = h('section', { class: 'emergency', id: 'emergency-banner', role: 'region', 'aria-label': 'Emergency access' },
        h('h2', {}, icon('alert'), 'Emergency access - read only'),
        h('p', {}, g ? ['Time remaining: ', left, '. The access ends automatically.'] : 'This access is time-limited and ends automatically.'),
        h('ul', {}, h('li', { text: 'Limited to this patient\'s summary and clinical record. Export is not available.' }), h('li', { text: 'Valid for this sign-in only.' }), h('li', { text: 'Recorded with your name and justification; reviewed by the security team.' })));
      if (g) {
        stopCountdown = ctx.every(() => {
          const ms = g.until - performance.now();
          left.textContent = mmss(ms);
          if (ms <= 0) { if (stopCountdown) stopCountdown(); stopCountdown = null; expired(id); }
        }, 1000);
      }
      return box;
    }

    async function openChart(id) {
      const seq = ++chartSeq;
      if (stopCountdown) { stopCountdown(); stopCountdown = null; }
      selected = id;
      workspace.dataset.pane = 'detail';
      paintRows();
      clear(chartBody).append(h('div', { class: 'panel' }, h('div', { class: 'panel-body' }, skeleton(6))));
      const s = await call('GET', '/api/patients/' + id + '/summary');
      if (ctx.stale() || seq !== chartSeq) return;
      if (s.status !== 200) { restricted(id, s); return; }
      const sum = s.data;
      const out = [patientBanner(sum, sum.access_basis)];
      if (isRecep) {
        out.push(h('div', { class: 'grid two' },
          panel('Demographics', dl([['Patient ID', String(sum.patient_id)], ['Name', sum.name], ['Date of birth', fmtDob(sum.dob)], ['Age', ageOf(sum.dob) != null ? ageOf(sum.dob) + ' years' : '-'], ['Ward', sum.ward]]), { icon: 'user', level: 3, class: 'chart-section' }),
          panel('Appointment', [dl([['Next appointment', h('strong', { text: fmtAppt(sum.next_appointment) })], ['When', relAppt(sum.next_appointment) || '-']]),
            h('div', { class: 'btn-row' }, h('button', { class: 'btn primary', id: 'reschedule-btn', type: 'button', onclick: async () => {
              const v = await rescheduleDialog({ patient_id: sum.patient_id, name: sum.name, next_appointment: sum.next_appointment });
              if (!v || !state.token) return;
              const row = patients.find((x) => x.patient_id === sum.patient_id); if (row) row.next_appointment = v;
              toast('Appointment updated for ' + sum.name + '.');
              openChart(id);
            } }, icon('calendar', 'sm'), 'Reschedule'))], { icon: 'calendar', level: 3, class: 'chart-section' })));
        clear(chartBody).append(...out);
        return;
      }
      const rec = await call('GET', '/api/patients/' + id + '/records');
      if (ctx.stale() || seq !== chartSeq) return;
      if (sum.access_basis === 'break_glass') out.push(emergencyPanel(id));
      if (rec.status !== 200) {
        out.push(h('section', { class: 'panel' }, h('div', { class: 'panel-body' }, errorAlert(rec, explain(rec).code === 'step_up_required' ? [h('button', { class: 'btn small', type: 'button', text: 'Verify and retry', onclick: () => openChart(id) })] : null))));
      } else {
        if (isDoctor) out.push(textPanel('Diagnosis', 'clipboard', rec.data.diagnosis, 'sec-diagnosis'));
        out.push(h('div', { class: 'grid two' }, textPanel('Medication', 'pill', rec.data.medication, 'sec-medication'), textPanel('Care notes', 'file', rec.data.care_notes, 'sec-care-notes')));
        if (isDoctor && sum.access_basis === 'assigned') {
          out.push(h('div', { class: 'btn-row' }, h('button', { class: 'btn', id: 'export-btn', type: 'button', onclick: async () => {
            const x = await call('POST', '/api/patients/' + id + '/export-pdf');
            if (!state.token) return;
            if (x.status === 200) await exportDialog(x.data); else toast(explain(x).title);
          } }, icon('download', 'sm'), 'Export clinical summary')));
        }
        if (!isDoctor) out.push(h('p', { class: 'small muted', text: 'Nursing view: medication and care notes for patients on your ward.' }));
      }
      clear(chartBody).append(...out);
      refreshSession();
    }

    lookupIn.addEventListener('input', () => { lookupMsg.textContent = ''; });
    const lookupForm = h('form', { class: 'lookup', onsubmit: (ev) => {
      ev.preventDefault();
      const v = lookupIn.value.trim();
      if (!/^\d{1,9}$/.test(v)) { lookupMsg.textContent = 'Enter the numeric patient ID.'; lookupIn.focus(); return; }
      lookupMsg.textContent = '';
      go('patients', Number(v));
    } },
      h('div', { class: 'field' }, h('label', { class: 'label', for: 'lookup-id', text: 'Open a patient by ID' }), lookupIn),
      h('button', { class: 'btn', id: 'lookup-btn', type: 'submit', text: 'Open' }));

    search.addEventListener('input', paintRows);
    root.append(workspace);
    workspace.append(
      h('div', { class: 'pane-list' }, h('section', { class: 'panel' },
        h('div', { class: 'panel-head' }, h('h2', {}, isRecep ? 'Patient registry' : isDoctor ? 'Assigned patients' : 'Ward patients', ' ', countEl)),
        emergencyBox,
        upcomingBox,
        h('div', { class: 'toolbar' }, h('div', { class: 'grow search' }, icon('search', 'sm'), search)),
        listBody,
        h('div', { class: 'panel-foot' }, lookupForm, lookupMsg,
          h('p', { class: 'hint', text: isRecep ? 'The registry shows demographics and appointments only.' : isDoctor ? 'Not on the list? You can open a patient by number only if you are allowed to see that patient.' : 'Not on the list? You can open a patient by number only if the patient is on your ward.' })))),
      detail);
    paintEmergencyList();
    if (isDoctor) ctx.every(paintEmergencyList, 15000);
    loadList();
    const api = {
      update(param) {
        selected = param;
        workspace.dataset.pane = param == null ? 'list' : 'detail';
        paintRows();
        if (param == null) { chartSeq++; if (stopCountdown) { stopCountdown(); stopCountdown = null; } showPlaceholder(); return; }
        openChart(param);
      }
    };
    if (ctx.param != null) openChart(ctx.param); else showPlaceholder();
    return api;
  };

  // ================================================================ appointments (receptionist)
  VIEWS.appointments = function viewAppointments(root, ctx) {
    let patients = [];
    let range = 'all';
    const cols = [{ label: 'Appointment', cell: 'cell-primary' }, { label: 'Patient' }, { label: 'Ward' }, { label: 'When' }, { label: 'Action', cell: 'cell-actions' }];
    const dt = dataTable(cols, { id: 'appointment-table', label: 'Upcoming appointments' });
    const holder = h('div');
    const count = h('span', { class: 'count', id: 'appointment-count' });
    const opts = [['all', 'All'], ['week', 'Next 7 days'], ['today', 'Today']];
    const seg = h('div', { class: 'seg filters', role: 'radiogroup', 'aria-label': 'Appointment range' }, opts.map(([v, label]) =>
      h('label', { class: 'seg-opt' }, h('input', { type: 'radio', name: 'appt-range', value: v, checked: v === 'all', onchange: () => { range = v; paint(); } }), h('span', { text: label }))));

    function inRange(d) {
      if (range === 'all') return true;
      const start = new Date(serverNow()); start.setHours(0, 0, 0, 0);
      const end = new Date(start.getTime() + (range === 'today' ? 1 : 7) * 86400000);
      return d && d >= start && d < end;
    }
    function paint() {
      const rows = patients.map((p) => ({ p, d: parseAppt(p.next_appointment) })).filter((x) => inRange(x.d))
        .sort((a, b) => (a.d ? a.d.getTime() : Infinity) - (b.d ? b.d.getTime() : Infinity));
      clear(dt.body);
      rows.forEach(({ p }) => {
        dt.body.append(tableRow(cols, [
          h('span', {}, h('strong', { text: fmtApptShort(p.next_appointment) })),
          h('span', {}, h('span', { class: 'primary', text: p.name }), h('span', { class: 'sub', text: 'ID ' + p.patient_id })),
          p.ward,
          relAppt(p.next_appointment) || '-',
          h('button', { class: 'btn small', type: 'button', 'aria-label': 'Reschedule appointment for ' + p.name, onclick: async () => {
            const v = await rescheduleDialog(p);
            if (!v || !state.token) return;
            p.next_appointment = v;
            toast('Appointment updated for ' + p.name + '.');
            paint();
          } }, icon('calendar', 'sm'), 'Reschedule')
        ], { 'data-id': p.patient_id }));
      });
      count.textContent = String(rows.length);
      dt.wrap.classList.toggle('hidden', !rows.length);
      none.classList.toggle('hidden', rows.length > 0);
    }
    const none = h('div', { class: 'hidden' }, emptyState('calendar', 'No appointments in this range', 'Choose a wider range to see more.'));
    root.append(h('p', { class: 'page-intro', text: 'Appointment management for the front desk. Only the next appointment of a patient can be moved.' }),
      h('section', { class: 'panel' },
        h('div', { class: 'panel-head' }, h('h2', {}, icon('calendar', 'sm'), 'Upcoming appointments ', count), seg),
        holder));
    holder.append(skeleton(5));
    (async () => {
      const r = await call('GET', '/api/patients/list');
      if (ctx.stale()) return;
      clear(holder);
      if (r.status !== 200) { holder.append(h('div', { class: 'panel-body' }, errorAlert(r))); return; }
      patients = r.data.patients || [];
      holder.append(dt.wrap, none);
      paint();
    })();
  };

  // ================================================================ evaluation helpers shared by "Session & access" and the demonstration tools
  function riskNow() { const s = state.session && state.session.session; return s && typeof s.risk_points === 'number' ? { points: s.risk_points, threshold: s.revoke_threshold } : null; }
  function riskText(r) { if (!r) return '-'; const i = riskInfo(r.points, r.threshold); return i.level + ' (' + r.points + ' of ' + r.threshold + ')'; }

  // Sends one harmless, normal request (the patient list) and reports what the server decided for the CURRENT device and network conditions.
  async function evaluateAccess(withPin) {
    const before = riskNow();
    // a request this role is allowed to make (the patient list for clinical roles, the summary for the administrator, who has no patient access):
    // checking access must never be a request that is refused by design and adds to the session's own risk
    const path = state.user.role === 'security_admin' ? '/admin/summary' : '/api/patients/list';
    const r = await call('GET', path, null, { noPrompt: true, noPin: !withPin });
    if (!state.token) return null;                 // the session ended: the sign-in screen already shows the revocation
    await refreshSession();
    return { label: requestLabel('GET', path), r, decision: decisionOf(r), before, after: riskNow(), at: Date.now() / 1000, withPin: !!withPin };
  }
  function outcomeCard(o, onRetry) {
    const kind = o.decision === 'ALLOW' ? 'ok' : o.decision === 'STEP_UP' ? 'warn' : 'bad';
    const e = o.decision === 'ALLOW' ? null : explain(o.r);
    const headline = o.decision === 'ALLOW' ? (o.withPin ? 'Access allowed after step-up verification' : 'Access allowed') : o.decision === 'STEP_UP' ? 'Step-up verification required' : o.decision === 'REVOKE' ? 'Session revoked' : 'Access denied';
    const net = state.session && state.session.network;
    const rows = [
      ['Decision', decisionBadge(o.decision)],
      ['Request', o.label],
      ['Reason', e ? e.text : (o.withPin ? 'The PIN was accepted, so the request was allowed.' : 'Device, network and request risk are within the allowed level.')],
      ['Session', o.decision === 'REVOKE' ? 'Revoked' : 'Active'],
      ['Session risk', o.before && o.after && o.before.points !== o.after.points ? riskText(o.before) + ' → ' + riskText(o.after) : riskText(o.after)],
      o.withPin && net && net.change === 'none' ? ['Network', 'Baseline updated after verification'] : null
    ];
    return h('div', { class: 'result-card ' + kind, role: 'status', 'aria-live': 'polite' },
      h('h3', { text: headline }),
      dl(rows),
      e && e.detail ? h('details', { class: 'small' }, h('summary', { text: 'Technical detail' }), h('p', { class: 'small', text: e.detail })) : null,
      o.decision === 'STEP_UP' && onRetry ? h('div', { class: 'btn-row' }, h('button', { class: 'btn primary', type: 'button', text: 'Enter PIN and re-evaluate', onclick: onRetry })) : null);
  }
  async function pinThenEvaluate(show) {
    const pin = await askPin('Enter your step-up PIN to complete the request.', false);
    if (!pin || !state.token) return;
    state.pin = pin;
    const o = await evaluateAccess(true);
    if (o) show(o);
  }

  // ================================================================ session & access (every role)
  VIEWS.session = function viewSession(root, ctx) {
    const slot = h('div', { class: 'stack' });
    root.append(slot);
    const probeSlot = h('div', { id: 'probe-result', 'aria-live': 'polite' });

    const SIG_NEG = (sg) => /^(off|none|disabled|outdated|inactive|invalid)$/i.test(String(sg.value)) || (/^false$/i.test(String(sg.value)) && /secure context|online/i.test(sg.name));
    function sigKind(sg, agentDemo) {
      const s = String(sg.source || ''), v = String(sg.value || '');
      if (/^SIMULATED/i.test(s) || /--fake/i.test(s) || v.toUpperCase() === 'SIMULATED') return 'sim';
      if (agentDemo && (sg.name === 'firewall' || sg.name === 'antivirus')) return 'sim';
      if (/^measured/i.test(s)) return 'measured';
      return 'reported';
    }
    function sigBadge(kind) { return kind === 'sim' ? badge('Simulated', 'sim') : kind === 'measured' ? badge('Measured', 'measured') : badge('Self-reported', 'reported'); }

    function paint(info) {
      const s = info.session || {}, d = info.device, n = info.network, p = info.policy || {};
      if (info.detail !== 'full' || !d || !n || typeof s.risk_points !== 'number') {
        clear(slot).append(panel('Session details', alertBox('info', 'Detailed session information is switched off', 'The security administrator has not enabled the evaluation tools, so the server does not send risk, device or network details to this role.')));
        return;
      }
      const ri = riskInfo(s.risk_points, s.revoke_threshold);
      const isAdmin = info.user.role === 'security_admin';
      const dev = deviceAssessment(d);
      const net = networkEvidence(n);
      const agentDemo = (d.signals || []).some((x) => x.name === 'agent mode' && String(x.value).toUpperCase() === 'SIMULATED');
      const tally = { sim: 0, measured: 0, reported: 0 };
      const sigList = h('ul', { class: 'signals', id: 'signal-list' }, (d.signals || []).map((sg) => {
        const k = sigKind(sg, agentDemo);
        tally[k]++;
        return h('li', {}, h('span', { class: 's-name', text: sg.name.charAt(0).toUpperCase() + sg.name.slice(1) }), h('span', { class: 's-value' + (SIG_NEG(sg) ? ' neg' : ''), text: String(sg.value) }), sigBadge(k));
      }));
      const sessionPanel = panel('Your session', [
        h('p', { class: 'small muted', text: 'This screen is about YOUR session only: your sign-in, the device it runs on and the network the server sees. Evidence is shown with its source and age. Other people\'s sessions are not shown here.' }),
        h('div', { class: 'status-line' }, badge('Active', 'ok'), badge('Risk: ' + ri.level, ri.kind)),
        h('div', { class: 'meter-line', 'data-live-risk': '' }, meter(ri.pct, ri.kind), h('span', { class: 'small nowrap', text: s.risk_points + ' of ' + s.revoke_threshold + ' points' })),
        h('p', { class: 'hint', text: 'Denied or suspicious requests add points. At the limit the session ends and the account is locked for ' + s.lockout_minutes + ' minutes.' }),
        dl([
          ['Signed in as', info.user.display_name],
          ['Role', (ROLE[info.user.role] || info.user.role) + (info.user.role === 'nurse' && info.user.ward ? ', Ward ' + info.user.ward : '')],
          ['Signed in at', fmtDay(s.created_at)],
          ['Session reference', h('span', { class: 'mono', text: String(s.session_id).slice(-8) })],
          ['Confirmed by the server', fmtTime(state.checkedAt / 1000) + ' (server check just now)'],
          ['Access token', 'Renewed automatically about every ' + Math.round(info.token_ttl_seconds * 0.6) + ' s and kept in memory only']
        ])
      ], { icon: 'shield-check', id: 'panel-session' });

      const devicePanel = panel('Your device', [
        h('div', { class: 'status-line' }, icon(d.kind === 'agent' ? 'laptop' : 'monitor'), h('strong', { text: deviceLabel(d.kind, d.label) }), badge(dev.label, dev.kind)),
        h('p', { class: 'small', id: 'device-why', text: dev.why }),
        dl([
          ['Evidence source', dev.source],
          ['Last report', d.heartbeat_age >= 0 ? d.heartbeat_age + ' s ago (the server trusts a report for ' + d.stale_after_seconds + ' s)' : 'none'],
          ['Not applicable to this device', dev.notApplicable]
        ]),
        agentDemo ? alertBox('warn', 'Laptop agent in demonstration mode', 'This agent was started with a demonstration switch. Its firewall and antivirus values are simulated, not measured.') : null,
        d.block_reason ? alertBox('bad', 'This device is blocked', d.block_reason) : null,
        sigList,
        h('div', { class: 'sig-legend' }, h('span', {}, badge('Measured', 'measured'), 'read by the signed agent or timed by the server'), h('span', {}, badge('Self-reported', 'reported'), 'stated by this web page'), h('span', {}, badge('Simulated', 'sim'), 'a demonstration setting, not a measurement')),
        h('p', { class: 'hint', id: 'signal-tally', text: tally.sim + ' simulated, ' + tally.reported + ' self-reported, ' + tally.measured + ' measured.' }),
        h('div', { class: 'btn-row' },
          h('button', { class: 'btn', id: 'check-access', type: 'button', onclick: async () => {
            clear(probeSlot).append(skeleton(3));
            const o = await evaluateAccess(false);
            if (!o || ctx.stale()) return;
            clear(probeSlot).append(outcomeCard(o, () => pinThenEvaluate((x) => clear(probeSlot).append(outcomeCard(x)))));
            load(true);
          } }, icon('refresh', 'sm'), 'Check access now'),
          d.kind === 'browser' && info.simulation_enabled ? h('button', { class: 'btn', type: 'button', onclick: async () => { await resetSimulation(); if (!ctx.stale()) load(true); } }, 'Reset simulated signals') : null),
        probeSlot
      ], { icon: d.kind === 'agent' ? 'laptop' : 'monitor', id: 'panel-device' });

      const changeWords = n.change === 'none' ? 'Unchanged' : n.change === 'same_subnet' ? 'Changed within the same subnet' : 'Changed to a different subnet';
      const networkPanel = panel('Your network', [
        h('div', { class: 'status-line' }, badge(net.label, net.kind)),
        h('p', { class: 'small', id: 'network-why', text: net.text }),
        n.change !== 'none' ? alertBox(n.action === 'ALLOW' ? 'info' : 'warn', changeWords + (n.simulated_ip ? ' (simulated)' : ''), 'Policy response: ' + (DECISION[n.action] ? DECISION[n.action][0].toLowerCase() : String(n.action).toLowerCase()) + '.') : null,
        dl([
          ['Sign-in address (server view)', h('span', { class: 'mono', text: n.origin_ip })],
          ['Address now (server view)', h('span', {}, h('span', { class: 'mono', text: n.effective_ip }), n.simulated_ip ? [' ', badge('Simulated', 'sim')] : null)],
          ['Checked', n.checked_at ? fmtTime(n.checked_at) + ' (server clock)' : '-'],
          ['Status', changeWords]
        ])
      ], { icon: 'wifi', id: 'panel-network' });

      const rules = [];
      if (!isAdmin && p.session) {
        rules.push(h('li', { text: 'Low-risk requests are allowed.' }), h('li', { text: 'Medium-risk requests need your step-up PIN.' }), h('li', { text: 'High-risk requests are denied.' }));
        rules.push(h('li', { text: 'Each denied or suspicious request adds to your session risk. At ' + p.session.revoke_threshold + ' points the session ends and the account is locked for ' + p.session.lockout_minutes + ' minutes.' }));
        rules.push(h('li', { text: 'A session ends after ' + Math.round(p.session.idle_timeout_seconds / 60) + ' minutes without activity.' }));
        if (p.break_glass) rules.push(h('li', {}, h('strong', { text: 'Emergency access: ' }), p.break_glass.enabled ? 'up to ' + p.break_glass.max_grants_per_session + ' per sign-in, each limited to ' + spanWords(p.break_glass.duration_seconds) + ', read-only, with a written justification of at least ' + p.break_glass.min_justification_chars + ' characters.' : 'switched off by the security policy.'));
      }
      const rulesPanel = isAdmin || !p.session ? null : panel('How access is decided', [
        h('ul', { class: 'scope-list' }, rules),
        p.bands ? h('details', { class: 'small' }, h('summary', { text: 'Show risk thresholds' }), h('p', { class: 'small', text: 'Request risk below ' + p.bands.allow_below + ' is allowed, below ' + p.bands.step_up_below + ' needs the step-up PIN, and anything higher is denied.' })) : null
      ], { icon: 'info', id: 'panel-rules' });

      const logPanel = panel('Recent requests from this screen', state.log.length
        ? h('ul', { class: 'log', id: 'request-log' }, state.log.slice(0, 8).map((e) => h('li', {}, h('time', { text: fmtTime(e.at) }), h('span', { class: 'l-main' }, e.label, ' ', decisionBadge(e.decision)), e.title ? h('span', { class: 'l-sub', text: e.title }) : null)))
        : emptyState('clock', 'No requests yet', 'Requests made from this screen appear here with the decision the server returned.'), { icon: 'clock', id: 'panel-log' });

      clear(slot).append(h('div', { class: 'grid two session-grid' }, h('div', { class: 'stack' }, sessionPanel, networkPanel, rulesPanel), h('div', { class: 'stack' }, devicePanel, logPanel)));
    }
    async function load(quiet) {
      if (!quiet) clear(slot).append(h('div', { class: 'panel' }, h('div', { class: 'panel-body' }, skeleton(6))));
      const info = await refreshSession();
      if (ctx.stale()) return;
      if (!info) { clear(slot).append(panel('Session details unavailable', alertBox('bad', 'The server did not return the session details', 'Try again in a moment.'))); return; }
      const keepProbe = probeSlot.firstChild;
      paint(info);
      if (keepProbe && quiet) { clear(probeSlot).append(keepProbe); }
    }
    load(false);
  };

  // ================================================================ demonstration tools (doctor, nurse, receptionist)
  VIEWS.demo = function viewDemo(root, ctx) {
    const role = state.user.role;
    const isRecep = role === 'receptionist';
    const dev = state.session && state.session.device;
    const sim = !!(state.session && state.session.simulation_enabled);
    const logEntries = [];
    const logList = h('ul', { class: 'log', id: 'decision-log', 'aria-live': 'polite' });
    const logEmpty = emptyState('list', 'Nothing yet', 'Run a test above. Every decision the server returns is listed here.');
    const logBox = h('div', {}, logEmpty, logList);
    function record(entry) {
      logEntries.unshift(entry);
      if (logEntries.length > 25) logEntries.length = 25;
      clear(logList).append(...logEntries.map((e) => h('li', {}, h('time', { text: fmtTime(e.at) }), h('span', { class: 'l-main' }, e.label, ' ', decisionBadge(e.decision)),
        h('span', { class: 'l-sub', text: (e.decision === 'ALLOW' ? 'Allowed' : explain(e.r).title) + (e.after ? ' - session risk ' + riskText(e.after) : '') }))));
      logEmpty.classList.add('hidden');
    }
    const show = (slot, o, withRetry) => { clear(slot).append(outcomeCard(o, withRetry ? () => pinThenEvaluate((x) => { record(x); show(slot, x, false); }) : null)); };
    async function probe(slot, label, method, path) {
      clear(slot).append(skeleton(3));
      const before = riskNow();
      const r = await call(method, path, null, { noPrompt: true, noPin: true });
      if (!state.token) return null;
      await refreshSession();
      const o = { label: requestLabel(method, path), r, decision: decisionOf(r), before, after: riskNow(), at: Date.now() / 1000, withPin: false };
      record(o);
      show(slot, o, true);
      return o;
    }

    // ---- 1. the server enforces access
    const enfSlot = h('div', { id: 'enforce-result' });
    const pid = h('input', { class: 'input', id: 'demo-pid', type: 'text', inputmode: 'numeric', value: role === 'doctor' ? '103' : '102', 'aria-label': 'Patient ID' });
    const pidVal = () => (/^\d{1,9}$/.test(pid.value.trim()) ? Number(pid.value.trim()) : 0);
    const probeBtn = (label, method, suffix) => h('button', { class: 'btn', type: 'button', text: label, onclick: () => { if (!pidVal()) { toast('Enter a numeric patient ID.'); return; } probe(enfSlot, label, method, '/api/patients/' + pidVal() + suffix); } });
    const enforce = panel('Server-side enforcement', isRecep ? [
      h('p', { class: 'small muted', text: 'Sends a request that this role may not make, directly to the server. The server must refuse it, and the refusal is recorded and adds to the session risk.' }),
      h('div', { class: 'btn-row' }, h('button', { class: 'btn', id: 'restricted-test', type: 'button', text: 'Run access-control test', onclick: () => probe(enfSlot, 'Access-control test', 'GET', '/api/patients/101/records') })),
      enfSlot
    ] : [
      h('p', { class: 'small muted', text: 'These buttons call the server directly for any patient ID, including patients that are not on your list. Hiding a button on screen is never the access control: every refusal here comes from the server.' }),
      h('div', { class: 'field' }, h('label', { class: 'label', for: 'demo-pid', text: 'Patient ID' }), pid),
      h('div', { class: 'btn-row' }, probeBtn('Demographics', 'GET', '/summary'), probeBtn('Clinical record', 'GET', '/records'), role === 'doctor' ? probeBtn('Export', 'POST', '/export-pdf') : null),
      enfSlot
    ], { icon: 'shield-check', id: 'demo-enforce' });

    // ---- 2. repeated violations lead to automatic revocation
    const burstSlot = h('div', { id: 'burst-result' });
    const burstMeterLine = h('div', { class: 'meter-line', 'data-live-risk': '' });
    function paintMeter() {
      const r = riskNow();
      clear(burstMeterLine);
      if (!r) return;
      const i = riskInfo(r.points, r.threshold);
      burstMeterLine.append(meter(i.pct, i.kind), h('span', { class: 'small nowrap', text: 'Risk: ' + i.level + ' (' + r.points + ' of ' + r.threshold + ')' }));
    }
    burstMeterLine.addEventListener('riskchange', paintMeter);
    paintMeter();
    const burst = async () => {
      const targets = isRecep ? ['/api/patients/101/records', '/api/patients/102/records', '/api/patients/103/records', '/api/patients/104/records', '/api/patients/105/records']
        : ['/admin/sessions', '/admin/devices', '/admin/events', '/admin/users', '/admin/policy'];
      for (let i = 0; i < targets.length; i++) {
        clear(burstSlot).append(h('p', { class: 'small', role: 'status', text: 'Sending restricted request ' + (i + 1) + ' of ' + targets.length + ' ...' }));
        const o = await probe(burstSlot, 'Restricted request ' + (i + 1), 'GET', targets[i]);
        if (!o) return;                       // the session was revoked: the sign-in screen explains it
        paintMeter();
        if (o.decision === 'REVOKE') return;
      }
    };
    const burstPanel = panel('Repeated violations', [
      h('p', { class: 'small muted', text: 'Each denied request adds points to the session risk. Send five restricted requests and watch the risk rise until the server revokes the session and locks the account for a few minutes.' }),
      burstMeterLine,
      h('div', { class: 'btn-row' }, h('button', { class: 'btn danger', id: 'burst-btn', type: 'button', text: 'Send 5 restricted requests', onclick: burst })),
      burstSlot
    ], { icon: 'alert', id: 'demo-burst' });

    // ---- 3. network change (simulated)
    const netSlot = h('div', { id: 'network-result' });
    const netSelect = h('select', { class: 'input', id: 'sim-network', 'aria-label': 'Simulated network' },
      h('option', { value: 'same', text: 'Same subnet (for example a DHCP renewal)' }), h('option', { value: 'other', text: 'Different subnet (other Wi-Fi or mobile data)' }), h('option', { value: 'reset', text: 'Back to the real network' }));
    const sendNet = async () => {
      clear(netSlot).append(skeleton(3));
      const cur = state.session && state.session.network;
      let ip = 'reset';
      if (netSelect.value === 'same' && cur) { const q = cur.origin_ip.split('.'); if (q.length === 4) { q[3] = String((Number(q[3]) % 200) + 20); ip = q.join('.'); } else ip = cur.origin_ip; }
      if (netSelect.value === 'other') ip = '198.51.100.' + (20 + Math.floor(Math.random() * 200));
      const r = await call('POST', '/ctl/simulate', { kind: 'network', ip }, { noPrompt: true, quiet: true });
      if (!state.token) return;
      if (r.status !== 200) { clear(netSlot).append(errorAlert(r)); return; }
      const o = await evaluateAccess(false);
      if (!o) return;
      record(o);
      show(netSlot, o, true);
    };
    const netPanel = panel('Network change', [
      h('div', { class: 'status-line' }, badge('Simulated', 'sim')),
      h('p', { class: 'small muted', text: sim ? 'The server evaluates this session as if it came from another network address. No real network setting is changed. The policy decides what a network change means: allow, ask for the PIN, deny or revoke.' : 'Simulation is switched off by the security policy.' }),
      h('div', { class: 'field' }, h('label', { class: 'label', for: 'sim-network', text: 'Simulated network' }), netSelect),
      h('div', { class: 'btn-row' }, h('button', { class: 'btn primary', id: 'apply-network', type: 'button', text: 'Apply and re-evaluate', disabled: !sim, onclick: sendNet })),
      netSlot
    ], { icon: 'wifi', id: 'demo-network' });

    // ---- 4. device posture (simulated, browser devices only)
    const postSlot = h('div', { id: 'posture-result' });
    const isBrowser = !!(dev && dev.kind === 'browser');
    const simState = (name, okValue) => { const sg = ((dev && dev.signals) || []).find((x) => x.name === name); return !sg || sg.value === okValue; };
    const toggles = {};
    const spec = { screen_lock: ['screen lock', 'enabled', 'Screen lock enabled'], os_current: ['OS patch level', 'current', 'OS patches current'], protection: ['device protection', 'active', 'Device protection active'] };
    const switchEl = (k) => {
      toggles[k] = h('input', { type: 'checkbox', role: 'switch', id: 'sim-' + k, checked: simState(spec[k][0], spec[k][1]), disabled: !isBrowser || !sim });
      return h('label', { class: 'switch', for: 'sim-' + k }, toggles[k], h('span', { class: 'track' }), h('span', { class: 'sw-text', text: spec[k][2] }));
    };
    const sendPosture = async () => {
      clear(postSlot).append(skeleton(3));
      const r = await call('POST', '/ctl/simulate', { kind: 'posture', screen_lock: toggles.screen_lock.checked, os_current: toggles.os_current.checked, protection: toggles.protection.checked }, { noPrompt: true, quiet: true });
      if (!state.token) return;
      if (r.status !== 200) { clear(postSlot).append(errorAlert(r)); return; }
      const o = await evaluateAccess(false);
      if (!o) return;
      record(o);
      show(postSlot, o, true);
    };
    const postPanel = panel('Device posture', [
      h('div', { class: 'status-line' }, badge('Simulated', 'sim')),
      isBrowser
        ? h('p', { class: 'small muted', text: 'A browser cannot read these three settings, so they are demonstration switches. Switch one off, apply it, and the server re-evaluates the next request with the new posture.' })
        : alertBox('info', 'Posture is measured on this device', 'The signed laptop agent measures firewall and antivirus here, so posture cannot be simulated from this screen. To demonstrate a change the presenter restarts the agent in demonstration mode.'),
      switchEl('screen_lock'), switchEl('os_current'), switchEl('protection'),
      h('div', { class: 'btn-row' },
        h('button', { class: 'btn primary', id: 'apply-posture', type: 'button', text: 'Apply and re-evaluate', disabled: !(isBrowser && sim), onclick: sendPosture }),
        isBrowser && sim ? h('button', { class: 'btn', id: 'reset-sim', type: 'button', text: 'Reset simulated signals', onclick: async () => {
          await resetSimulation(); if (ctx.stale()) return;
          Object.keys(toggles).forEach((k) => { toggles[k].checked = true; });
          const o = await evaluateAccess(false);
          if (o) { record(o); show(postSlot, o, true); }
        } }) : null),
      postSlot
    ], { icon: 'monitor', id: 'demo-posture' });

    root.append(
      alertBox('info', 'Demonstration tools', 'These tools exist to show how the portal enforces access. They call the server directly. Simulated device and network changes are labelled as simulated and are not real measurements.'),
      h('div', { class: 'grid two' }, enforce, burstPanel, netPanel, postPanel),
      h('div', { class: 'mt' }, panel('Decision log', logBox, { icon: 'list', id: 'demo-log' })));
  };

  // ================================================================ security administrator (never shows patient information)
  const adminGet = (path) => call('GET', path, null, { noPrompt: true, quiet: true });
  const EVENT_LABEL = { DECISION: 'Access decision', LOGIN_OK: 'Sign-in', LOGIN_FAIL: 'Sign-in failed', LOGIN_BLOCKED: 'Sign-in blocked', LOGOUT: 'Sign-out', SESSION_REVOKED: 'Session revoked', LOCKOUT: 'Account locked', UNLOCK: 'Account unlocked', BREAK_GLASS: 'Emergency access', POLICY_CHANGE: 'Policy change', SIMULATION: 'Simulation change', ADMIN_ACTION: 'Administration' };
  const SESSION_STATUS = { ACTIVE: ['Active', 'ok'], REVOKED: ['Revoked', 'bad'], LOGGED_OUT: ['Signed out', ''], EXPIRED: ['Expired', ''] };

  // Live data that stays honest about its own state: it refreshes every few seconds, pauses on the first refusal (a page that keeps asking a server
  // that says no only raises its own risk) and offers Resume, asking for the step-up PIN when that is what the server wants.
  function liveData(ctx, fetchAll, paint, ms) {
    let stop = null;
    const status = h('span', { class: 'small muted', id: 'live-status', role: 'status' });
    const toggle = h('button', { class: 'btn small', id: 'live-toggle', type: 'button', onclick: () => (stop ? pause('Paused') : start()) });
    const notice = h('div', { id: 'live-notice' });
    let lastOk = 0;                         // when the data now on screen was read (this device's clock)
    // Data that is no longer refreshed is marked as stale (dimmed, with the time it was read): old numbers must not look current.
    const markStale = (on) => { if (ctx.root) ctx.root.classList.toggle('is-stale', on); };
    function setToggle() { clear(toggle).append(icon(stop ? 'pause' : 'play', 'sm'), stop ? 'Pause' : 'Resume'); }
    function pause(text) { if (stop) { stop(); stop = null; } status.textContent = (text || 'Paused') + (lastOk ? ' - showing data from ' + fmtTime(lastOk / 1000) : ' - no data yet'); markStale(true); setToggle(); }
    async function run() {
      const res = await fetchAll();
      if (ctx.stale()) return;
      const refused = res.find((x) => x.status !== 200);
      if (refused) { refusal(refused); return; }
      clear(notice);
      paint(res);
      lastOk = Date.now();
      markStale(false);
      const st = res.map((x) => x.data && x.data.server_time).find((t) => typeof t === 'number');
      status.textContent = 'Live - updated ' + fmtTime(st || Date.now() / 1000) + (st ? ' (server clock)' : '');
    }
    function start() { if (stop) stop(); clear(notice); stop = ctx.every(run, ms); setToggle(); run(); }
    function refusal(x) {
      pause('Paused');
      const e = explain(x);
      const canReset = state.session && state.session.device && state.session.device.kind === 'browser' && state.session.simulation_enabled;
      clear(notice).append(alertBox(x.data && x.data.error === 'step_up_required' ? 'warn' : 'bad', 'Live refresh paused: ' + e.title, e.text, { detail: e.detail, actions: [
        h('button', { class: 'btn small', type: 'button', text: 'Resume live refresh', onclick: async () => {
          if (x.data && x.data.error === 'step_up_required') { const pin = await askPin(x.data.message, false); if (!pin) return; state.pin = pin; }
          start();
        } }),
        canReset ? h('button', { class: 'btn small', type: 'button', text: 'Reset simulated signals', onclick: async () => { await resetSimulation(); if (!ctx.stale()) start(); } }) : null
      ] }));
    }
    start();
    return { control: h('div', { class: 'live-ctl' }, status, toggle), notice, refresh: run, restart: start };
  }
  function stat(label, n, kind) { return h('div', { class: 'stat ' + (kind || '') }, h('div', { class: 'n', text: n == null ? '-' : String(n) }), h('div', { class: 'l', text: label })); }
  // A session the server still lists as ACTIVE but that nobody has used for longer than the idle timeout: it ends on its next use.
  function isIdle(s) {
    const pol = state.session && state.session.policy && state.session.policy.session;
    const limit = (pol && pol.idle_timeout_seconds) || 900;
    return s.status === 'ACTIVE' && s.last_seen > 0 && Date.now() / 1000 - s.last_seen > limit;
  }
  function dayLabel(ts) { const d = new Date(ts * 1000), n = new Date(); return d.toDateString() === n.toDateString() ? '' : d.toLocaleDateString([], { day: 'numeric', month: 'short' }); }

  function eventTable(events, id) {
    const cols = [{ label: 'Time', cell: 'nowrap-cell' }, { label: 'Event', cell: 'ev-col' }, { label: 'User' }, { label: 'Decision' }, { label: 'Details', cell: 'wrap' }];
    const dt = dataTable(cols, { id, label: 'Security events', cls: 'events' });
    events.forEach((e) => {
      const risk = e.risk_delta || e.session_risk != null
        ? 'Request risk ' + (e.risk_score == null ? '-' : e.risk_score) + (e.risk_delta ? ', session +' + e.risk_delta : '') + (e.session_risk != null ? ' (session risk ' + e.session_risk + ')' : '') : '';
      dt.body.append(tableRow(cols, [
        h('span', {}, h('strong', { text: fmtTime(e.ts) }), dayLabel(e.ts) ? h('span', { class: 'sub', text: dayLabel(e.ts) }) : null),
        EVENT_LABEL[e.type] || e.type,
        e.username ? h('span', {}, e.username, e.role ? h('span', { class: 'sub', text: ROLE[e.role] || e.role }) : null) : '-',
        e.decision ? decisionBadge(e.decision) : '-',
        h('span', {}, e.method ? h('span', { class: 'sub mono req', text: e.method + ' ' + e.path.replace(/\//g, '/​') }) : null, scrub(e.reason), risk ? h('span', { class: 'sub', text: risk }) : null, e.details ? h('details', { class: 'small' }, h('summary', { text: 'Contributing signals' }), h('span', { class: 'small', text: scrub(e.details) })) : null)
      ], { 'data-event': e.event_id }));
    });
    return dt.wrap;
  }

  // ---- overview: counters, risk alerts and the latest security events
  VIEWS.overview = function viewOverview(root, ctx) {
    const stats = h('div', { class: 'stat-grid', id: 'admin-stats' });
    const alertsBody = h('div', { id: 'risk-alerts' });
    const eventsBody = h('div', { id: 'recent-events' });
    const thr0 = () => (state.session && state.session.session && state.session.session.revoke_threshold) || 60;
    function paint([sm, ss, ev, dv, us, gr]) {
      const d = sm.data;
      const sessList = ss.data.sessions || [];
      const inUse = sessList.length < 100 ? sessList.filter((s) => s.status === 'ACTIVE' && !isIdle(s)).length : d.active_sessions;
      clear(stats).append(stat('Active sessions', inUse, 'ok'), stat('Revoked sessions', d.revoked_sessions, d.revoked_sessions ? 'bad' : ''), stat('Denials, last hour', d.denials_last_hour, d.denials_last_hour ? 'warn' : ''), stat('Step-ups, last hour', d.step_ups_last_hour),
        stat('Revocations, total', d.revocations_total, d.revocations_total ? 'bad' : ''), stat('Locked accounts', d.locked_users, d.locked_users ? 'warn' : ''), stat('Emergency access active', d.active_break_glass, d.active_break_glass ? 'warn' : ''), stat('Registered devices', d.devices));
      const alerts = [];
      (us.data.users || []).filter((u) => u.locked_until * 1000 > Date.now()).forEach((u) => alerts.push({ kind: 'bad', ic: 'lock', text: 'Account locked: ' + u.username, sub: 'Until ' + fmtTime(u.locked_until) + (u.lock_reason ? ' - ' + scrub(u.lock_reason) : '') }));
      (gr.data.grants || []).filter((g) => g.status === 'ACTIVE' && g.expires_ts * 1000 > Date.now()).forEach((g) => alerts.push({ kind: 'warn', ic: 'alert', text: 'Emergency access active: ' + g.username + ' on patient ' + g.patient_id, sub: 'Ends ' + fmtTime(g.expires_ts) + '. Justification: ' + g.justification }));
      (ss.data.sessions || []).filter((s) => s.status === 'ACTIVE' && !isIdle(s)).forEach((s) => { const i = riskInfo(s.risk_points, thr0()); if (i.pct >= 25) alerts.push({ kind: i.kind, ic: 'activity', text: 'Session risk ' + i.level.toLowerCase() + ': ' + s.username, sub: s.risk_points + ' of ' + thr0() + ' points on ' + s.origin_ip }); });
      const inUseDevices = new Set(sessList.filter((s) => s.status === 'ACTIVE' && !isIdle(s)).map((s) => s.device_id));
      (dv.data.devices || []).forEach((x) => {
        const a = deviceAssessment(x);
        if (a.state === 'verified' || a.state === 'unknown' || a.state === 'simulated') return;      // no problem in the evidence (unknown and simulated are shown on the Devices screen, not raised as alerts)
        if (a.state === 'stale' && !inUseDevices.has(x.device_id)) return;                            // a device that simply stopped reporting is no alert unless someone is signed in on it
        alerts.push({ kind: a.kind === 'bad' ? 'bad' : 'warn', ic: 'laptop', text: deviceName(x.kind, x.device_id, x.hostname) + ': ' + a.label.toLowerCase(), sub: a.why + (inUseDevices.has(x.device_id) ? ' A session is signed in on it.' : '') });
      });
      const hour = Date.now() / 1000 - 3600;
      (ev.data.events || []).filter((e) => e.type === 'SESSION_REVOKED' && e.ts > hour).slice(0, 4).forEach((e) => alerts.push({ kind: 'bad', ic: 'x-circle', text: 'Session revoked: ' + (e.username || 'unknown user'), sub: fmtTime(e.ts) + ' - ' + scrub(e.reason) }));
      (ev.data.events || []).filter((e) => e.type === 'DECISION' && e.ts > hour && /network/i.test((e.code || '') + ' ' + (e.reason || '')) && e.decision && e.decision !== 'ALLOW').slice(0, 3).forEach((e) => alerts.push({ kind: e.decision === 'STEP_UP' ? 'warn' : 'bad', ic: 'wifi', text: 'Network change: ' + (e.username || 'unknown user'), sub: fmtTime(e.ts) + ' - ' + scrub(e.reason) }));
      alerts.sort((a, b) => (a.kind === 'bad' ? 0 : 1) - (b.kind === 'bad' ? 0 : 1));
      clear(alertsBody).append(alerts.length
        ? h('ul', { class: 'alert-list' }, alerts.slice(0, 8).map((a) => h('li', { class: a.kind }, icon(a.ic, 'sm'), h('div', {}, h('strong', { text: a.text }), h('span', { class: 'a-sub', text: a.sub })))))
        : emptyState('shield-check', 'No active risk alerts', 'No locked accounts, elevated sessions, unhealthy devices, network changes or active emergency access in the evidence the server holds.'));
      clear(eventsBody).append(eventTable((ev.data.events || []).slice(0, 12), 'event-table'));
    }
    const live = liveData(ctx, () => Promise.all([adminGet('/admin/summary'), adminGet('/admin/sessions'), adminGet('/admin/events?limit=60'), adminGet('/admin/devices'), adminGet('/admin/users'), adminGet('/admin/grants')]), paint, 6000);
    root.append(live.notice,
      h('p', { class: 'page-intro', id: 'overview-help', text: 'Security operations overview. Every number is read from the server\'s own session, event, account and device records at the time shown below. "Active sessions" counts signed-in sessions that are not idle; "Registered devices" counts every device that has signed in or reported. Alerts are derived from the same records, never from this page.' }),
      stats,
      h('div', { class: 'grid two-one stale-aware' },
        panel('Recent security events', eventsBody, { icon: 'list', flush: true, head: live.control, id: 'panel-events' }),
        panel('Risk alerts', alertsBody, { icon: 'bell', flush: true, id: 'panel-alerts' })));
    eventsBody.append(skeleton(4)); alertsBody.append(skeleton(3));
  };

  // ---- sessions
  VIEWS.sessions = function viewSessions(root, ctx) {
    let filter = 'ACTIVE';
    let cache = null;
    const body = h('div', { id: 'session-body' });
    const cols = [{ label: 'User', cell: 'cell-primary' }, { label: 'Device (evidence)', cell: 'wrap' }, { label: 'Network (evidence)', cell: 'wrap' }, { label: 'Risk' }, { label: 'Status' }, { label: 'Activity / reason', cell: 'wrap' }, { label: 'Action', cell: 'cell-actions' }];
    const seg = h('div', { class: 'seg filters', role: 'radiogroup', 'aria-label': 'Session filter' }, [['ACTIVE', 'Active'], ['REVOKED', 'Revoked'], ['ALL', 'All']].map(([v, label]) =>
      h('label', { class: 'seg-opt' }, h('input', { type: 'radio', name: 'sess-filter', value: v, checked: v === filter, onchange: () => { filter = v; if (cache) paint(cache); } }), h('span', { text: label }))));
    // The network evidence of one session: the address at sign-in, and the address the server saw at the session's latest recorded event
    // (sign-in or a later audited request; the server records no address for unaudited polling), each with its time.
    function networkCell(s) {
      const loop = /^(127\.|::1$|0:0:0:0:0:0:0:1$)/.test(String(s.origin_ip || ''));
      const bits = [h('span', { class: 'mono', text: s.origin_ip || 'unknown' }), h('span', { class: 'sub', text: 'at sign-in ' + fmtTime(s.created_at) })];
      if (s.simulated_ip) bits.push(h('span', { class: 'sub mono', text: 'evaluated as ' + s.simulated_ip }), badge('Simulated', 'sim'));
      else if (!s.evidence_ip) bits.push(badge('Unknown', 'unknown'), h('span', { class: 'sub', text: 'no address evidence recorded' }));
      else if (String(s.evidence_ip) !== String(s.origin_ip)) bits.push(badge('Changed', 'warn'), h('span', { class: 'sub mono', text: 'now ' + s.evidence_ip + ' at ' + fmtTime(s.evidence_ts) }));
      else if (s.evidence_ts && s.evidence_ts > s.created_at) bits.push(badge(loop ? 'Unchanged (local)' : 'Unchanged', loop ? 'unknown' : 'ok'), h('span', { class: 'sub', text: 'same address at ' + fmtTime(s.evidence_ts) }));
      else bits.push(badge('No later evidence', 'unknown'), h('span', { class: 'sub', text: 'only the sign-in address is recorded' }));
      if (loop) bits.push(h('span', { class: 'sub', text: 'local address: a network change could not be seen' }));
      return h('span', {}, bits);
    }
    function paint(res) {
      cache = res;
      const [ss, dv] = res;
      const devs = {}; (dv.data.devices || []).forEach((x) => { devs[x.device_id] = x; });
      const thr = thr0();
      const mine = state.session && state.session.session && state.session.session.session_id;
      const rows = (ss.data.sessions || []).filter((s) => filter === 'ALL' || (filter === 'ACTIVE' ? s.status === 'ACTIVE' && !isIdle(s) : s.status === 'REVOKED')).slice(0, 60);
      const dt = dataTable(cols, { id: 'session-table', label: 'Sessions' });
      const nowSrv = (typeof ss.data.server_time === 'number' ? ss.data.server_time : Date.now() / 1000);
      rows.forEach((s) => {
        const ri = riskInfo(s.risk_points, thr);
        const idle = isIdle(s);
        const st = idle ? ['Idle', ''] : (SESSION_STATUS[s.status] || [s.status, '']);
        const dv1 = devs[s.device_id];
        const a = dv1 ? deviceAssessment(dv1) : { label: 'Unavailable', kind: 'unknown', why: 'No device record for this session.' };
        dt.body.append(tableRow(cols, [
          h('span', {}, h('span', { class: 'primary', text: s.username }), h('span', { class: 'sub', text: ROLE[s.role] || s.role })),
          h('span', {}, h('span', { class: 'primary', text: dv1 ? deviceName(dv1.kind, dv1.device_id, dv1.hostname) : 'Device ' + fingerprint(s.device_id) }), badge(a.label, a.kind), h('span', { class: 'sub', text: a.why })),
          networkCell(s),
          h('span', { class: 'meter-line' }, meter(ri.pct, ri.kind), h('span', { class: 'small nowrap', text: ri.level + ' (' + s.risk_points + ' of ' + thr + ')' })),
          badge(st[0], st[1]),
          idle ? 'Idle since ' + fmtTime(s.last_seen) + ' - ends on its next use' : s.status === 'ACTIVE' ? 'Started ' + fmtTime(s.created_at) + '; last activity ' + fmtTime(s.last_seen) + ' (' + Math.max(0, Math.round(nowSrv - s.last_seen)) + ' s ago)' : ((s.revoked_by ? s.revoked_by + ': ' : '') + scrub(s.revoke_reason || st[0])),
          s.status === 'ACTIVE' ? (s.session_id === mine ? badge('This session', 'info') : h('button', { class: 'btn small danger', type: 'button', 'aria-label': 'Revoke the session of ' + s.username, text: 'Revoke', onclick: () => revoke(s) })) : null
        ], { 'data-session': s.session_id }));
      });
      clear(body).append(rows.length ? dt.wrap : emptyState('activity', 'No sessions in this view', 'Change the filter to see other sessions.'));
    }
    function thr0() { return (state.session && state.session.session && state.session.session.revoke_threshold) || 60; }
    async function revoke(s) {
      const ok = await openDialog({ title: 'Revoke session', body: [alertBox('warn', 'This signs the user out immediately', null), dl([['User', s.username], ['Role', ROLE[s.role] || s.role], ['Network', s.origin_ip]])], submitLabel: 'Revoke session', submitKind: 'danger' });
      if (!ok || !state.token) return;
      const r = await call('POST', '/admin/sessions/revoke', { session_id: s.session_id, reason: 'revoked by a security administrator' });
      if (!state.token) return;
      if (r.status === 200) { toast('Session of ' + s.username + ' revoked.'); live.refresh(); } else toast(explain(r).title);
    }
    const live = liveData(ctx, () => Promise.all([adminGet('/admin/sessions'), adminGet('/admin/devices')]), paint, 6000);
    root.append(live.notice,
      h('p', { class: 'page-intro', id: 'sessions-help', text: 'One row per sign-in. "Device" is the device the session is bound to and what the server\'s evidence says about it; "Network" is the address the server saw at sign-in and at the session\'s latest recorded event, each with its time; "Risk" is the penalty points this session has collected against the revoke limit. Unknown means the server has no evidence, not that something is fine.' }),
      panel('Sessions', body, { icon: 'activity', flush: true, head: h('div', { class: 'head-tools' }, seg, live.control), id: 'panel-sessions' }));
    body.append(skeleton(4));
  };

  // ---- devices and posture
  VIEWS.devices = function viewDevices(root, ctx) {
    const body = h('div', { class: 'grid two', id: 'device-grid' });
    function paint([dv, ss]) {
      clear(body);
      const sessionsOn = {};      // device id -> usernames of the sessions signed in (and not idle) on it right now
      (ss.data.sessions || []).filter((s) => s.status === 'ACTIVE' && !isIdle(s)).forEach((s) => { (sessionsOn[s.device_id] = sessionsOn[s.device_id] || []).push(s.username); });
      const order = { unhealthy: 0, stale: 1, unavailable: 2, simulated: 3, unknown: 4, verified: 5 };
      const list = (dv.data.devices || []).slice().sort((a, b) => order[deviceAssessment(a).state] - order[deviceAssessment(b).state]);
      if (!list.length) { body.append(emptyState('laptop', 'No devices registered', 'Devices appear here once they have signed in or reported posture.')); return; }
      list.forEach((d) => {
        const demo = d.agent_simulated;
        const st = deviceAssessment(d);
        const sigs = h('ul', { class: 'signals' }, (d.signals || []).map((sg) => {
          const s = String(sg.source || ''), v = String(sg.value || '');
          const k = /^SIMULATED/i.test(s) || /--fake/i.test(s) || v.toUpperCase() === 'SIMULATED' || (demo && (sg.name === 'firewall' || sg.name === 'antivirus')) ? 'sim' : /^measured/i.test(s) ? 'measured' : 'reported';
          return h('li', {}, h('span', { class: 's-name', text: sg.name.charAt(0).toUpperCase() + sg.name.slice(1) }), h('span', { class: 's-value' + (/^(off|none|disabled|outdated|inactive|invalid)$/i.test(v) || (/^false$/i.test(v) && /secure context|online/i.test(sg.name)) ? ' neg' : ''), text: v }),
            k === 'sim' ? badge('Simulated', 'sim') : k === 'measured' ? badge('Measured', 'measured') : badge('Self-reported', 'reported'));
        }));
        const fresh = typeof st.age === 'number' && typeof st.limit === 'number' ? (st.age <= st.limit ? 'fresh' : 'stale') : 'unknown';
        const users = sessionsOn[d.device_id];
        body.append(panel(deviceName(d.kind, d.device_id, d.hostname), [
          h('div', { class: 'status-line' }, badge(st.label, st.kind), badge(d.kind === 'agent' ? 'Signed agent' : 'Browser', d.kind === 'agent' ? 'measured' : 'reported')),
          h('p', { class: 'small', text: st.why }),
          demo ? alertBox('warn', 'Agent in demonstration mode', 'This agent reports simulated firewall and antivirus values.') : null,
          d.block_reason && st.state !== 'stale' ? alertBox('bad', 'Blocked', d.block_reason) : null,
          dl([
            ['Evidence source', st.source],
            ['Last report', typeof st.age === 'number' ? st.age + ' s ago - ' + fresh + (typeof st.limit === 'number' ? ' (the server trusts a report for ' + st.limit + ' s)' : '') : 'none'],
            ['Platform', d.os || '-'],
            ['Posture score', String(d.score) + (d.kind === 'agent' ? '' : ' (a browser always carries a base score: it cannot be measured)')],
            ['Signed in now', users ? users.join(', ') : 'nobody'],
            ['Not applicable', st.notApplicable]
          ]),
          sigs
        ], { icon: d.kind === 'agent' ? 'laptop' : 'monitor', class: 'device-card' }));
      });
    }
    const live = liveData(ctx, () => Promise.all([adminGet('/admin/devices'), adminGet('/admin/sessions')]), paint, 8000);
    root.append(live.notice,
      h('div', { class: 'toolbar-plain' }, h('p', { class: 'page-intro', id: 'devices-help', text: 'What the server\'s evidence says about every registered device. Verified = measured by the signed laptop agent and fresh. Unhealthy = the evidence shows a problem. Stale = the last report is older than the server trusts. Unknown = nothing verifiable: a browser can only report about itself, so it can never be Verified. Simulated = a demonstration value, not a measurement.' }), live.control),
      body);
    body.append(skeleton(3));
  };

  // ---- access decisions and audit log
  function eventsView(kind) {
    return function view(root, ctx) {
      let filter = kind === 'decisions' ? 'ALL' : 'ALL';
      const body = h('div', { id: kind + '-body' });
      const decisionQuery = { ALL: 'type=DECISION', ALLOW: 'type=DECISION&decision=ALLOW', STEP_UP: 'type=DECISION&decision=STEP_UP', DENY: 'type=DECISION&decision=DENY', REVOKE: 'type=SESSION_REVOKED', NETWORK: 'type=DECISION' };
      const query = () => (kind === 'decisions' ? decisionQuery[filter] : (filter === 'ALL' ? '' : 'type=' + filter));
      let tools;
      if (kind === 'decisions') {
        tools = h('div', { class: 'seg filters', role: 'radiogroup', 'aria-label': 'Decision filter' }, [['ALL', 'All'], ['ALLOW', 'Allowed'], ['STEP_UP', 'Step-up'], ['DENY', 'Denied'], ['REVOKE', 'Revoked'], ['NETWORK', 'Network changes']].map(([v, label]) =>
          h('label', { class: 'seg-opt' }, h('input', { type: 'radio', name: 'dec-filter', value: v, checked: v === filter, onchange: () => { filter = v; live.again(); } }), h('span', { text: label }))));
      } else {
        tools = h('select', { class: 'input', id: 'audit-type', 'aria-label': 'Event type', onchange: (ev) => { filter = ev.target.value; live.again(); } },
          h('option', { value: 'ALL', text: 'All events' }), Object.keys(EVENT_LABEL).map((k) => h('option', { value: k, text: EVENT_LABEL[k] })));
      }
      const live = liveData(ctx, () => Promise.all([adminGet('/admin/events?limit=200' + (query() ? '&' + query() : ''))]), ([ev]) => {
        let rows = ev.data.events || [];
        if (kind === 'decisions' && filter === 'NETWORK') rows = rows.filter((e) => /network/i.test((e.code || '') + ' ' + (e.reason || '')));      // the server has no network-change filter: the latest 200 decisions are filtered here
        clear(body).append(rows.length ? eventTable(rows, kind + '-table') : emptyState('list', 'No events match', 'Nothing has been recorded for this filter yet.'));
      }, 6000);
      live.again = () => { clear(body).append(skeleton(4)); live.restart(); };
      root.append(live.notice, h('p', { class: 'page-intro', text: kind === 'decisions'
        ? 'Every decision the policy engine made about a patient-data request, step-up or revocation, with the reason and the effect on session risk.'
        : 'The complete security audit trail: sign-ins, decisions, revocations, lockouts, emergency access, policy changes and administrator actions.' }),
      panel(kind === 'decisions' ? 'Access decisions' : 'Audit log', body, { icon: kind === 'decisions' ? 'shield-check' : 'list', flush: true, head: h('div', { class: 'head-tools' }, tools, live.control), id: 'panel-' + kind }));
      body.append(skeleton(4));
    };
  }
  VIEWS.decisions = eventsView('decisions');
  VIEWS.audit = eventsView('audit');

  // ---- users and emergency access
  VIEWS.users = function viewUsers(root, ctx) {
    const uBody = h('div', { id: 'user-body' });
    const gBody = h('div', { id: 'grant-body' });
    const uCols = [{ label: 'Account', cell: 'cell-primary' }, { label: 'Role' }, { label: 'Ward' }, { label: 'State' }, { label: 'Action', cell: 'cell-actions' }];
    const gCols = [{ label: 'Requested', cell: 'cell-primary' }, { label: 'Doctor' }, { label: 'Patient' }, { label: 'Status' }, { label: 'Justification', cell: 'wrap' }, { label: 'Action', cell: 'cell-actions' }];
    function paint([us, gr]) {
      const ut = dataTable(uCols, { id: 'user-table', label: 'Accounts' });
      (us.data.users || []).forEach((u) => {
        const locked = u.locked_until * 1000 > Date.now();
        ut.body.append(tableRow(uCols, [
          h('span', {}, h('span', { class: 'primary', text: u.display_name }), h('span', { class: 'sub', text: u.username })),
          ROLE[u.role] || u.role, u.ward || '-',
          h('span', {}, locked ? badge('Locked until ' + fmtTime(u.locked_until), 'bad') : badge('Active', 'ok'), locked && u.lock_reason ? h('span', { class: 'sub', text: scrub(u.lock_reason) }) : (u.failed_logins ? h('span', { class: 'sub', text: u.failed_logins + ' failed sign-in(s)' }) : null)),
          locked || u.failed_logins ? h('button', { class: 'btn small', type: 'button', 'aria-label': 'Unlock ' + u.username, text: 'Unlock', onclick: async () => {
            const r = await call('POST', '/admin/unlock', { username: u.username });
            if (state.token) toast(r.status === 200 ? u.username + ' unlocked (recorded in the audit log).' : explain(r).title);
          } }) : null
        ], { 'data-user': u.username }));
      });
      clear(uBody).append(ut.wrap);
      const gt = dataTable(gCols, { id: 'grant-table', label: 'Emergency access grants' });
      const grants = gr.data.grants || [];
      grants.forEach((g) => {
        const active = g.status === 'ACTIVE' && g.expires_ts * 1000 > Date.now();
        const label = active ? ['Active', 'warn'] : g.status === 'REVOKED' ? ['Revoked', ''] : ['Ended', ''];
        gt.body.append(tableRow(gCols, [
          h('span', {}, fmtTime(g.created_ts), h('span', { class: 'sub', text: dayLabel(g.created_ts) })),
          g.username, 'Patient ' + g.patient_id,
          h('span', {}, badge(label[0], label[1]), active ? h('span', { class: 'sub', text: 'ends ' + fmtTime(g.expires_ts) }) : null),
          g.justification,
          active ? h('button', { class: 'btn small danger', type: 'button', 'aria-label': 'Revoke emergency access for ' + g.username, text: 'Revoke', onclick: async () => {
            const r = await call('POST', '/admin/grants/revoke', { grant_id: g.grant_id });
            if (state.token) toast(r.status === 200 ? 'Emergency access revoked.' : explain(r).title);
          } }) : null
        ], { 'data-grant': g.grant_id }));
      });
      clear(gBody).append(grants.length ? gt.wrap : emptyState('shield-check', 'No emergency access requests', 'Doctors\' emergency (break-glass) requests appear here with their justification.'));
    }
    const live = liveData(ctx, () => Promise.all([adminGet('/admin/users'), adminGet('/admin/grants')]), paint, 8000);
    root.append(live.notice,
      h('div', { class: 'stack' },
        panel('Accounts', uBody, { icon: 'user', flush: true, head: live.control, id: 'panel-users' }),
        panel('Emergency access requests', gBody, { icon: 'alert', flush: true, id: 'panel-grants' })));
    uBody.append(skeleton(3)); gBody.append(skeleton(3));
  };

  // ---- policy (the only place where the whole risk policy is shown)
  const POLICY_GROUPS = { bands: 'Decision thresholds', session: 'Sessions and lockout', tokens: 'Access tokens', penalties: 'Session risk penalties', device: 'Device posture', network: 'Network change', behavior: 'Request bursts', break_glass: 'Emergency access', login: 'Sign-in protection', admin: 'Administration', simulation: 'Evaluation tools' };
  const POLICY_META = {
    'bands.allow_below': ['Allow below request risk', 'Requests scoring under this value are allowed.'],
    'bands.step_up_below': ['Step-up below request risk', 'From the allow limit up to this value a step-up PIN is required; above it the request is denied.'],
    'session.revoke_threshold': ['Revoke at session risk', 'Accumulated penalty points that end the session.'],
    'session.lockout_minutes': ['Account lockout (minutes)', 'How long an account stays locked after a risk revocation.'],
    'session.idle_timeout_seconds': ['Idle timeout (seconds)', 'A session without activity for this long ends.'],
    'session.absolute_timeout_seconds': ['Maximum session length (seconds)', 'No session lasts longer than this.'],
    'tokens.ttl_seconds': ['Access token lifetime (seconds)', 'Pages renew their token automatically before it expires.'],
    'tokens.renew_grace_seconds': ['Renewal grace (seconds)', 'An expired token may still be renewed for this long (a phone waking up).'],
    'device.laptop_stale_seconds': ['Laptop agent silence limit (seconds)', 'A laptop whose agent has been silent longer than this is blocked.'],
    'device.phone_stale_seconds': ['Browser silence limit (seconds)', 'A browser that has not reported for this long is blocked.'],
    'device.firewall_off_score': ['Firewall off (measured)', 'Risk added when the signed agent reports the firewall off.'],
    'device.antivirus_off_score': ['No antivirus registered (measured)', 'Risk added when the agent finds no registered security product.'],
    'device.browser_base_score': ['Browser base risk', 'A browser only self-reports, so it never scores zero.'],
    'device.screen_lock_off_score': ['Screen lock off (simulated)', 'Risk added by the simulated screen-lock switch.'],
    'device.os_outdated_score': ['OS not current (simulated)', 'Risk added by the simulated OS patch switch.'],
    'device.protection_off_score': ['Protection off (simulated)', 'Risk added by the simulated device protection switch.'],
    'device.on_blocked': ['When a device is blocked', 'DENY keeps the session and lets it recover; REVOKE ends it.'],
    'network.same_subnet_score': ['Same-subnet change: risk', 'Risk added when the address changes inside the same /24.'],
    'network.same_subnet_action': ['Same-subnet change: action', 'ALLOW, STEP_UP, DENY or REVOKE.'],
    'network.different_subnet_score': ['Different-subnet change: risk', 'Risk added when the session moves to another subnet.'],
    'network.different_subnet_action': ['Different-subnet change: action', 'ALLOW, STEP_UP, DENY or REVOKE.'],
    'network.rebind_after_step_up': ['Adopt new network after PIN', 'After a verified PIN the session takes the new network as its baseline.'],
    'penalties.role_denied': ['Role not permitted', 'Points added to the session risk when a request is refused because of the user\'s role.'],
    'penalties.not_assigned': ['Patient not assigned', 'Added when a doctor asks for a patient who is not assigned and has no emergency access.'],
    'penalties.ward_denied': ['Patient on another ward', 'Added when a nurse asks for a patient of another ward.'],
    'penalties.unknown_endpoint': ['Unsupported request', 'Added for a request the server does not offer.'],
    'penalties.bad_request': ['Malformed request', 'Added when the request body is not valid.'],
    'penalties.bad_step_up_pin': ['Wrong step-up PIN', 'Added for every wrong PIN, so a PIN cannot be guessed for free.'],
    'penalties.posture_blocked': ['Device blocked by posture', 'Added when a request is refused because the device does not meet the policy.'],
    'penalties.network_denied': ['Network change denied', 'Added when a request is refused because the network changed.'],
    'penalties.risk_too_high': ['Request risk too high', 'Added when the combined request risk is above the deny limit.'],
    'penalties.not_found': ['Unknown patient', 'Added when a request names a patient that does not exist.'],
    'penalties.break_glass_used': ['Emergency access used', 'Added each time a doctor obtains emergency access.'],
    'penalties.burst': ['Request burst', 'Added to requests that arrive in a burst.'],
    'behavior.burst_window_seconds': ['Burst window (seconds)', 'Length of the window used to count requests.'],
    'behavior.burst_limit': ['Requests per window', 'More requests than this in one window add burst risk.'],
    'behavior.burst_score': ['Burst risk', 'Risk added to requests during a burst.'],
    'break_glass.enabled': ['Emergency access enabled', 'Doctors may request time-limited access to unassigned patients.'],
    'break_glass.duration_seconds': ['Emergency access duration (seconds)', 'How long a grant lasts.'],
    'break_glass.min_justification_chars': ['Minimum justification length', 'Characters the doctor must write.'],
    'break_glass.max_grants_per_session': ['Grants per sign-in', 'Maximum emergency grants in one session.'],
    'login.max_failures': ['Failed sign-ins before lockout', 'Wrong passwords within the window that lock the account.'],
    'login.window_seconds': ['Failed sign-in window (seconds)', 'Period over which failures are counted.'],
    'login.lockout_minutes': ['Sign-in lockout (minutes)', 'How long the account is locked after too many failures.'],
    'admin.require_managed_device': ['Administration only from the registered laptop', 'When on, administrative functions are refused from phones and browsers.'],
    'simulation.enabled': ['Evaluation tools enabled', 'Demonstration only. On: a user who opens the portal in evaluation mode sees the risk, device and network details of their own session and can use the simulated network and posture switches. Off: the server sends those details to no role except the security administrator, refuses the simulation requests, and gives plain denial messages without scores. Recommended off outside a demonstration.']
  };
  VIEWS.policy = function viewPolicy(root, ctx) {
    const note = h('div', { id: 'policy-note', 'aria-live': 'polite' });
    const out = h('div', { class: 'grid two', id: 'policy-groups' });
    root.append(h('p', { class: 'page-intro', text: 'Every change is validated by the server, applied immediately and written to the audit log with your name and the old and new value.' }), note, out);
    out.append(h('div', { class: 'panel' }, h('div', { class: 'panel-body' }, skeleton(5))));
    (async () => {
      const r = await call('GET', '/admin/policy', null, { noPrompt: false });
      if (ctx.stale()) return;
      clear(out);
      if (r.status !== 200) { out.append(h('div', { class: 'panel' }, h('div', { class: 'panel-body' }, errorAlert(r)))); return; }
      paintPolicy(r.data.policy);
    })();
    function paintPolicy(policy) {
    const leaves = (obj, prefix) => Object.keys(obj).flatMap((k) => (obj[k] !== null && typeof obj[k] === 'object') ? leaves(obj[k], prefix + k + '.') : [[prefix + k, obj[k]]]);
    const groups = {};
    leaves(policy, '').forEach(([path, value]) => { const g = path.split('.')[0]; (groups[g] = groups[g] || []).push([path, value]); });
    Object.keys(POLICY_GROUPS).filter((g) => groups[g]).forEach((g) => {
      out.append(panel(POLICY_GROUPS[g], groups[g].map(([path, value]) => {
        const meta = POLICY_META[path] || [path.split('.').slice(1).join(' ').replace(/_/g, ' '), ''];
        const id = 'pol-' + path.replace(/\./g, '-');
        let ctl;
        if (typeof value === 'boolean') ctl = h('select', { class: 'input', id }, h('option', { value: 'true', text: 'On', selected: value }), h('option', { value: 'false', text: 'Off', selected: !value }));
        else if (typeof value === 'string') ctl = h('select', { class: 'input', id }, ['ALLOW', 'STEP_UP', 'DENY', 'REVOKE'].map((o) => h('option', { value: o, text: o, selected: o === value })));
        else ctl = h('input', { class: 'input', id, type: 'number', inputmode: 'numeric', min: '0', value: String(value) });
        return h('div', { class: 'policy-row', 'data-path': path },
          h('label', { class: 'p-name', for: id }, meta[0], meta[1] ? h('span', { class: 'p-help', text: meta[1] }) : null),
          h('div', { class: 'p-ctl' }, ctl, h('button', { class: 'btn small', type: 'button', 'aria-label': 'Apply ' + meta[0], text: 'Apply', onclick: async () => {
            const v = typeof value === 'boolean' ? ctl.value === 'true' : typeof value === 'string' ? ctl.value : Number(ctl.value);
            const x = await call('POST', '/admin/policy/set', { path, value: v });
            if (!state.token) return;
            clear(note).append(x.status === 200 ? alertBox('ok', 'Policy updated', meta[0] + ' is now ' + (typeof v === 'boolean' ? (v ? 'On' : 'Off') : v) + '. The change is active and recorded in the audit log.') : errorAlert(x));
            if (x.status === 200) refreshSession();
          } })));
      }), { class: 'policy-card', id: 'policy-' + g }));
    });
    }
  };

  // ================================================================ boot
  window.addEventListener('online', () => setOnline(true));
  window.addEventListener('offline', () => setOnline(false));
  window.addEventListener('hashchange', () => { if (state.token) render(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeNav(true); });
  if (window.matchMedia) {
    const wide = window.matchMedia('(min-width: 1024px)');
    const onWide = (e) => { if (e.matches) closeNav(false); };
    if (wide.addEventListener) wide.addEventListener('change', onWide);
  }
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') resume(); });
  window.addEventListener('pageshow', (e) => { if (e.persisted) { if (state.token) resume(); else renderLogin(); } });
  // The token lives in memory only, so once this page is gone the session could never be used again: close it on the server too (best effort).
  window.addEventListener('pagehide', (e) => {
    if (e.persisted || !state.token) return;
    try { fetch('/ctl/logout', { method: 'POST', keepalive: true, cache: 'no-store', credentials: 'omit', headers: { Authorization: 'Bearer ' + state.token, 'X-Device-Id': state.deviceId || '' } }); } catch (err) { /* nothing more can be done while unloading */ }
  });
  window.addEventListener('beforeinstallprompt', (e) => { e.preventDefault(); state.installPrompt = e; const b = $('install-btn'); if (b) b.classList.remove('hidden'); });

  if ('serviceWorker' in navigator && window.isSecureContext) {
    navigator.serviceWorker.register('/sw.js').catch(() => { /* the portal works without it; only the offline page is missing */ });
  }
  renderLogin();
})();
