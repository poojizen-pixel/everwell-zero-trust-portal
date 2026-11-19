// Role-specific interfaces in real Chrome (headless desktop, throw-away profile, one isolated browser context per page so every page is its own device).
// Proves, through the rendered pages and the requests they make:
//   - the doctor, nurse and receptionist workspaces carry no security monitoring (no status chips, risk, posture, network, policy or event wording,
//     no technical detail or reference codes, no security screens or controls) in any state: list, chart, refusal, emergency dialog, step-up dialog,
//     account menu, session ended;
//   - the security administrator keeps the monitoring screens, with the time, the source and the age of every piece of evidence, and the exact
//     vocabulary verified / unhealthy / stale / unknown / simulated / unavailable (an unknown or stale device is never shown as healthy);
//   - routes of other roles fall back to the role's own first screen and no clinical page ever calls an administration endpoint;
//   - a desktop browser is never called a phone; evaluation mode exists only when asked for and only while the administrator allows it;
//   - session notices (idle, maximum length) and the end-of-session screens (revoked, expired) are plain and true.
// Environment: ZT_TEST_CHROME, ZT_TEST_BASE (loopback edge), ZT_TEST_PROFILE, ZT_ROLE_CREDS, ZT_ROLE_PINS (JSON, never printed).
// Output: one line "RESULT_JSON:[...]" with {id,title,expected,actual,ok}.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const env = process.env;
const base = env.ZT_TEST_BASE;
const creds = JSON.parse(env.ZT_ROLE_CREDS || '{}');
const pins = JSON.parse(env.ZT_ROLE_PINS || '{}');
const results = [];
const rec = (id, title, expected, actual, ok) => { results.push({ id, title, expected, actual: String(actual), ok: ok === true }); console.error(`${ok === true ? 'PASS' : 'FAIL'} ${id} ${title}${ok === true ? '' : ' -> ' + actual}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 15000, step = 150) { const end = Date.now() + ms; while (Date.now() < end) { try { const v = await fn(); if (v) return v; } catch (e) { /* retry */ } await sleep(step); } return null; }
let chrome = null;
process.on('exit', () => { try { chrome && chrome.kill(); } catch (e) { /* gone */ } });

// ------------------------------------------------------------------------------------------------------------------------------------ API helpers
async function apiLogin(user, device, label = 'Desktop browser') {
  const r = await fetch(base + '/ctl/login', { signal: AbortSignal.timeout(30000), method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Device-Id': device },
    body: JSON.stringify({ username: user, password: creds[user], device_kind: 'browser', device_label: label, platform: 'Windows', signals: { secure_context: true, online: true, visible: true, standalone: false, connection: '4g' } }) });
  const j = await r.json().catch(() => ({}));
  return { status: r.status, token: j.token, device, user, json: j, lastBeat: Date.now(), issued: Date.now() };
}
// access tokens live about 90 s: an API session of this script renews its token before it is old (the pages do the same on their own)
async function renewIfOld(s) {
  if (!s.issued || Date.now() - s.issued < 50000) return;
  const r = await fetch(base + '/ctl/renew', { signal: AbortSignal.timeout(30000), method: 'POST', headers: { 'X-Device-Id': s.device, Authorization: 'Bearer ' + s.token } });
  const j = await r.json().catch(() => ({}));
  if (r.status === 200 && j.token) { s.token = j.token; s.issued = Date.now(); }
}
async function apiCall(s, method, p, body, extra = {}) {
  if (p !== '/ctl/renew') await renewIfOld(s);
  if (s.user && Date.now() - s.lastBeat > 25000 && p !== '/ctl/heartbeat') await apiCall(s, 'POST', '/ctl/heartbeat', { signals: { secure_context: true, online: true, visible: true, standalone: false, connection: '4g' } });
  const headers = { 'X-Device-Id': s.device, Authorization: 'Bearer ' + s.token, ...extra };
  if (body != null) headers['Content-Type'] = 'application/json';
  const r = await fetch(base + p, { signal: AbortSignal.timeout(30000), method, headers, body: body == null ? undefined : JSON.stringify(body) });
  const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch (e) { /* not JSON */ }
  if (p === '/ctl/heartbeat') s.lastBeat = Date.now();
  return { status: r.status, json, text };
}
const pin = (user) => ({ 'X-StepUp-Pin': pins[user] });
async function setPolicy(adm, key, value) { return apiCall(adm, 'POST', '/admin/policy/set', { path: key, value }, pin('sec_dan')); }
let adm = null;
async function freshAdmin(tag) { adm = await apiLogin('sec_dan', 'RU-API-ADMIN-' + tag + '-' + Date.now().toString(36)); if (!adm.token) throw new Error('administrator API sign-in failed: HTTP ' + adm.status); return adm; }

// ------------------------------------------------------------------------------------------------------------------------------------ what a clinical page must never contain
const SOC_TEXT = [
  ['risk', /\brisk\b/i], ['score', /\bscore\b/i], ['session status', /session (active|confirmed|unconfirmed)/i], ['network status', /network (unchanged|changed|:)/i],
  ['posture', /\bposture\b|\bhealthy\b|\bdegraded\b|\bunverified\b/i], ['evidence labels', /\b(self-reported|measured|simulated)\b/i], ['technical detail', /technical detail/i],
  ['reference code', /reference:/i], ['threshold or penalty', /threshold|step-up band|penalt/i], ['points', /\b\d+ (of \d+ )?points?\b/i], ['ip address', /\b\d{1,3}(\.\d{1,3}){3}\b/],
  ['raw device id', /\b(DEV|WEB|PHONE)-[A-Za-z0-9]{3,}/], ['device telemetry', /heartbeat|firewall|antivirus|posture agent/i], ['evaluation or demonstration', /evaluation|demonstration tools|session & access/i],
  ['decision feed', /decision log|policy decision|security events?/i]
];
const ACCOUNT_TEXT = SOC_TEXT.filter(([n]) => !['session status', 'security events?'].includes(n) && n !== 'decision feed');
let clinicalValues = [];     // the synthetic clinical texts of the demonstration patients: removed before a clinical screen is scanned for security wording (a care note may say "risk")
function scan(list, text) { const t = clinicalValues.reduce((a, s) => (s ? a.split(s).join(' ') : a), text); return list.filter(([, re]) => re.test(t)).map(([n]) => n); }
// the short fingerprint the page shows instead of a device identifier (same function as the page's)
function fingerprint(id) { let x = 0x811c9dc5; const s = String(id || ''); for (let i = 0; i < s.length; i++) { x ^= s.charCodeAt(i); x = Math.imul(x, 16777619) >>> 0; } return x.toString(16).toUpperCase().padStart(8, '0').slice(0, 6); }
const SNAP = `(() => {
  const vis = (e) => { const r = e.getBoundingClientRect(); const s = getComputedStyle(e); return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none'; };
  const label = (e) => (e.getAttribute('aria-label') || e.textContent || e.value || e.placeholder || e.id || '').replace(/\\s+/g, ' ').trim();
  return { title: document.title, hash: location.hash, text: document.body.innerText,
    controls: [...document.querySelectorAll('button, a[href], [role=button], input:not([type=hidden]), select, textarea')].filter(vis).map(label),
    nav: [...document.querySelectorAll('.nav-link')].map((a) => (a.querySelector('span') || a).textContent.trim()),
    chips: [...document.querySelectorAll('#chip-session, #chip-net, #chip-device, #chip-risk, .status-chips > *')].filter(vis).length,
    pageTitle: (document.getElementById('page-title') || {}).textContent || '', eyebrow: (document.querySelector('.topbar-eyebrow') || {}).textContent || '' };
})()`;

async function main() {
  const profile = env.ZT_TEST_PROFILE;
  fs.rmSync(profile, { recursive: true, force: true });
  fs.mkdirSync(profile, { recursive: true });
  chrome = spawn(env.ZT_TEST_CHROME, ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check',
    '--disable-extensions', '--disable-background-networking', '--disable-sync', '--mute-audio', 'about:blank'], { stdio: 'ignore' });
  const portFile = path.join(profile, 'DevToolsActivePort');
  const ap = await until(() => fs.existsSync(portFile) && fs.readFileSync(portFile, 'utf8').split('\n').length >= 2 && fs.readFileSync(portFile, 'utf8'), 20000);
  if (!ap) throw new Error('Chrome did not start');
  const [port, wsPath] = ap.split('\n');
  const ws = new WebSocket(`ws://127.0.0.1:${port}${wsPath}`);
  await new Promise((res, rej) => { ws.addEventListener('open', res); ws.addEventListener('error', rej); });
  let nextId = 0; const pending = new Map(); const events = [];
  ws.addEventListener('message', (ev) => { const m = JSON.parse(ev.data); if (m.id && pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); m.error ? p.rej(new Error(m.error.message)) : p.res(m.result); } else if (m.method) events.push(m); });
  // every CDP command has a time limit: a command that never answers must fail the run loudly (naming the command), never hang it
  const send = (method, params = {}, sessionId) => new Promise((res, rej) => { const id = ++nextId; const timer = setTimeout(() => { pending.delete(id); rej(new Error('CDP command did not answer within 60 s: ' + method + (params && params.expression ? ' ' + String(params.expression).slice(0, 80) : ''))); }, 60000); pending.set(id, { res: (v) => { clearTimeout(timer); res(v); }, rej: (e) => { clearTimeout(timer); rej(e); } }); ws.send(JSON.stringify({ id, method, params, sessionId })); });
  const PHONE_UA = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36';
  const TABLET_UA = 'Mozilla/5.0 (Linux; Android 14; SM-X710) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';

  // one isolated browser context per page: its own storage, so its own device id (pages never share a device)
  async function openPage(o = {}) {
    const { width = 1280, height = 900, mobile = false, ua = null } = o;
    const { browserContextId } = await send('Target.createBrowserContext');
    const { targetId } = await send('Target.createTarget', { url: 'about:blank', browserContextId });
    const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
    const cmd = (m, p) => send(m, p, sessionId);
    for (const d of ['Page', 'Runtime', 'Network']) await cmd(d + '.enable');
    await cmd('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: mobile ? 2 : 1, mobile });
    if (ua) await cmd('Emulation.setUserAgentOverride', { userAgent: ua });
    if (mobile) await cmd('Emulation.setTouchEmulationEnabled', { enabled: true, maxTouchPoints: 5 });
    const js = async (expression) => { const r = await cmd('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }); if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception ? r.exceptionDetails.exception.description : r.exceptionDetails.text); return r.result.value; };
    const go = async (url) => { const mark = events.length; await cmd('Page.navigate', { url }); await until(() => events.slice(mark).some((e) => e.sessionId === sessionId && e.method === 'Page.loadEventFired'), 15000); };
    const reqs = () => events.filter((e) => e.sessionId === sessionId && e.method === 'Network.requestWillBeSent').map((e) => { try { return e.params.request.method + ' ' + new URL(e.params.request.url).pathname; } catch (x) { return ''; } });
    const close = async () => { try { await send('Target.closeTarget', { targetId }); await send('Target.disposeBrowserContext', { browserContextId }); } catch (e) { /* gone */ } };
    return { cmd, js, go, reqs, close };
  }
  const settle = async (pg, ms = 1200) => { await sleep(ms); await until(() => pg.js("!document.querySelector('.skeleton')"), 8000); };
  const snap = (pg) => pg.js(SNAP);
  async function signIn(pg, user, o = {}) {
    await pg.go(base + '/' + (o.evaluation ? '?evaluation=1' : ''));
    if (!(await until(() => pg.js("!!document.querySelector('form input[type=password]')"), 15000))) throw new Error('the sign-in form did not appear');
    await pg.js(`(() => { document.querySelector('#u').value = ${JSON.stringify(user)}; document.querySelector('#p').value = ${JSON.stringify(creds[user])}; document.querySelector('form').requestSubmit(); })()`);
    if (!(await until(() => pg.js("!!document.querySelector('.topbar')"), 15000))) throw new Error('sign-in failed for ' + user);
    await settle(pg, 1200);
  }
  const route = async (pg, hash, ms = 1300) => { await pg.js(`location.hash = ${JSON.stringify(hash)}`); await settle(pg, ms); };
  // what the administrator's page shows right now (used only to explain a failure: the state of the screen, never a credential or a patient value)
  const adminPageState = async () => {
    try {
      const late = await until(() => adminPg.js("document.querySelectorAll('.device-card').length"), 10000);
      const s = await adminPg.js(`(() => ({ hash: location.hash, visible: document.visibilityState, title: (document.getElementById('page-title') || {}).textContent, skeletons: document.querySelectorAll('.skeleton').length, gridChildren: (document.getElementById('device-grid') || { children: [] }).children.length, cards: document.querySelectorAll('.device-card').length, alerts: [...document.querySelectorAll('.alert')].filter((a) => a.offsetParent !== null).map((a) => a.textContent.replace(/\\s+/g, ' ').trim().slice(0, 100)), main: (document.getElementById('main') || { innerText: '' }).innerText.replace(/\\s+/g, ' ').slice(0, 200) }))()`);
      return 'cards appeared within 10 s more: ' + (late ? 'yes (' + late + ')' : 'no') + '; page: ' + JSON.stringify(s);
    } catch (e) { return 'page state unavailable: ' + (e && e.message); }
  };
  const dialogOpen = (pg, ms = 8000) => until(() => pg.js("!!document.querySelector('dialog[open]')"), ms);
  const closeDialog = async (pg) => { await pg.js("(() => { const d = document.querySelector('dialog[open]'); if (d) d.close(); })()"); await sleep(300); };
  const clickButton = (pg, text) => pg.js(`(() => { const b = [...document.querySelectorAll('button')].find((x) => x.textContent.trim() === ${JSON.stringify(text)}); if (b) { b.click(); return true; } return false; })()`);
  const deviceOf = (pg) => pg.js("localStorage.getItem('zt_device_id')");
  const allowedCtl = (r) => /^(POST \/ctl\/(login|renew|heartbeat|logout|break-glass)|GET \/ctl\/(session|agents))$/.test(r);

  await freshAdmin('main');
  // the patients' names and clinical values, as the services hold them (read through the permitted roles), to prove the administrator's screens carry none
  const recepApi = await apiLogin('front_carol', 'RU-API-RECEP');
  const docApi = await apiLogin('dr_alice', 'RU-API-DOC');
  const names = ((await apiCall(recepApi, 'GET', '/api/patients/list')).json || {}).patients || [];
  const clinicalStrings = [];
  for (const id of [101, 102]) { const r = (await apiCall(docApi, 'GET', `/api/patients/${id}/records`, null, pin('dr_alice'))).json || {}; for (const k of ['diagnosis', 'medication', 'care_notes']) if (r[k]) clinicalStrings.push(r[k]); }
  const patientNames = names.map((p) => p.name).filter(Boolean);
  clinicalValues = clinicalStrings.slice();

  // ---------------------------------------------------------------- RU1-RU3 (+ RU12): the three clinical workspaces in every state
  const WORK = {
    dr_alice: { id: 'RU1', role: 'Doctor', nav: ['My patients'], restricted: 103, deny: /Revoke|Unlock|Reschedule|Save appointment|Pause|Resume|Apply and|Reset simulated|Send 5|Check access|access-control test|Save policy|Users & access|Audit log/i, want: ['Export clinical summary', 'Open'] },
    nurse_bob: { id: 'RU2', role: 'Nurse', nav: ['Ward patients'], restricted: 102, deny: /Revoke|Unlock|Reschedule|Save appointment|Pause|Resume|Apply and|Reset simulated|Send 5|Check access|access-control test|Save policy|Export|Request emergency access/i, want: ['Open'] },
    front_carol: { id: 'RU3', role: 'Receptionist', nav: ['Patient registry', 'Appointments'], restricted: null, deny: /Revoke|Unlock|Pause|Resume|Apply and|Reset simulated|Send 5|Check access|access-control test|Save policy|Export|emergency/i, want: ['Reschedule'] }
  };
  const accountTexts = {};
  for (const [user, w] of Object.entries(WORK)) {
    const problems = []; const shots = {};
    let pg;
    try {
      pg = await openPage();
      await signIn(pg, user);
      shots.home = await snap(pg);
      await route(pg, '#/patients/101', 2200); shots.chart = await snap(pg);
      if (user === 'front_carol') {
        await route(pg, '#/appointments', 1800); shots.appointments = await snap(pg);
        const opened = await pg.js(`(() => { const b = document.querySelector('button[aria-label^="Reschedule appointment"]'); if (b) { b.click(); return true; } return false; })()`);
        if (opened && await dialogOpen(pg)) { shots.reschedule = await snap(pg); await closeDialog(pg); } else problems.push('the reschedule dialog did not open');
      }
      if (w.restricted) {
        await route(pg, '#/patients/' + w.restricted, 2200); shots.restricted = await snap(pg);
        if (user === 'dr_alice') {
          if (await pg.js("!!document.getElementById('emergency-btn')")) { await pg.js("document.getElementById('emergency-btn').click()"); if (await dialogOpen(pg)) { shots.emergency = await snap(pg); await closeDialog(pg); } else problems.push('the emergency dialog did not open'); }
          else problems.push('no emergency access offered for the unassigned patient');
        }
      }
      await route(pg, '#/patients', 1200);
      await pg.js("document.getElementById('account-btn').click()");
      if (await dialogOpen(pg)) { shots.account = await snap(pg); await closeDialog(pg); } else problems.push('the account menu did not open');
      for (const [name, s] of Object.entries(shots)) {
        const hits = scan(name === 'account' ? ACCOUNT_TEXT : SOC_TEXT, s.text);
        if (hits.length) problems.push(`${name}: security wording [${hits.join(', ')}]`);
        if (s.chips > 0 && name !== 'account') problems.push(`${name}: ${s.chips} status chip(s) shown`);
        const bad = s.controls.filter((c) => w.deny.test(c));
        if (bad.length) problems.push(`${name}: controls this role must not have: ${bad.join(' | ')}`);
        if (JSON.stringify(s.nav) !== JSON.stringify(w.nav)) problems.push(`${name}: navigation ${JSON.stringify(s.nav)}`);
        if (s.eyebrow !== 'Everwell Hospital') problems.push(`${name}: eyebrow "${s.eyebrow}"`);
      }
      accountTexts[user] = (shots.account || {}).text || '';
      const wants = (shots.chart || {}).controls || [];
      const missing = w.want.filter((x) => !(wants.concat((shots.home || {}).controls || [], (shots.appointments || {}).controls || [])).some((c) => c === x || c.startsWith(x)));
      if (missing.length) problems.push('expected controls missing: ' + missing.join(', '));
      const calls = pg.reqs();
      const bad = calls.filter((r) => /\/admin\/|\/ctl\/(policy|simulate)/.test(r) || (/\/ctl\//.test(r) && !allowedCtl(r)));
      if (bad.length) problems.push('requests this workspace must not make: ' + [...new Set(bad)].join(', '));
      if (user === 'nurse_bob' && /diagnosis/i.test(shots.chart.text)) problems.push('the nurse chart shows a diagnosis');
      if (user === 'front_carol' && /diagnosis|medication|care notes/i.test(shots.chart.text)) problems.push('the receptionist chart shows clinical headings');
      if (user === 'dr_alice' && !/Diagnosis/.test(shots.chart.text)) problems.push('the doctor chart lacks the diagnosis');
      rec(w.id, `${w.role} workspace (list, chart${user === 'front_carol' ? ', appointments, reschedule dialog' : ', refusal for a patient outside the list'}${user === 'dr_alice' ? ', emergency dialog' : ''}, account menu): ${w.nav.join(' and ')} only, no status chips, no risk, posture, network, policy, event or reference wording, none of the controls of other roles, no request to an administration endpoint`,
        'no security monitoring and no foreign control in any state', `${Object.keys(shots).length} states checked; problems: [${problems.slice(0, 6).join('; ')}]`, problems.length === 0 && Object.keys(shots).length >= 4);
    } catch (e) { rec(w.id, `${w.role} workspace checks ran`, 'no exception', e && e.message || e, false); }
    if (pg) { try { await pg.js("document.getElementById('signout-btn') && document.getElementById('signout-btn').click()"); } catch (e) { /* gone */ } await pg.close(); }
  }

  // ---------------------------------------------------------------- RU4: plain words in the states that need the user: refusal, step-up, session ended
  {
    const problems = []; let pg;
    try {
      pg = await openPage();
      await signIn(pg, 'dr_alice');
      await route(pg, '#/patients/103', 2200);
      const refusal = await snap(pg);
      if (!/Patient not on your list/.test(refusal.text) || /not_assigned|Technical detail|Reference|risk|403/i.test(refusal.text)) problems.push('refusal text: ' + refusal.text.replace(/\s+/g, ' ').slice(0, 160));
      await route(pg, '#/patients/101', 2200);
      await pg.js("document.getElementById('export-btn').click()");
      if (await dialogOpen(pg)) {
        const d = await snap(pg);
        if (!/Verification required/.test(d.text) || !/Enter your step-up PIN/.test(d.text) || scan(SOC_TEXT, d.text).length) problems.push('step-up dialog text: ' + d.text.replace(/\s+/g, ' ').slice(0, 160));
        await pg.js(`(() => { document.getElementById('pin-input').value = ${JSON.stringify(pins.dr_alice)}; document.getElementById('pin-input').form.requestSubmit(); })()`);
        if (!(await until(() => pg.js("(document.querySelector('dialog[open]') || {}).innerText && document.querySelector('dialog[open]').innerText.includes('Clinical summary export')"), 10000))) problems.push('the export did not open after the PIN');
        await closeDialog(pg);
      } else problems.push('no step-up dialog for the export');
      rec('RU4', 'Plain language where the user must act: a patient outside the list says "Patient not on your list" (no code, no technical detail), the step-up dialog asks for the PIN without policy wording and the export then opens', 'plain text, PIN accepted', `problems: [${problems.join('; ')}]`, problems.length === 0);
    } catch (e) { rec('RU4', 'Plain-language states ran', 'no exception', e && e.message || e, false); }
    if (pg) await pg.close();
  }

  // ---------------------------------------------------------------- the security administrator's console
  let adminPg;
  {
    const problems = []; const seen = {};
    try {
      adminPg = await openPage();
      await signIn(adminPg, 'sec_dan');
      const navWant = ['Overview', 'Sessions', 'Devices & posture', 'Access decisions', 'Audit log', 'Users & access', 'Policy', 'My session'];
      const home = await snap(adminPg);
      if (JSON.stringify(home.nav) !== JSON.stringify(navWant)) problems.push('navigation ' + JSON.stringify(home.nav));
      if (!/Security operations/.test(home.eyebrow)) problems.push('eyebrow "' + home.eyebrow + '"');
      const screens = [['overview', ['Active sessions', 'Risk alerts', 'Recent security events', 'server clock']], ['sessions', ['Device (evidence)', 'Network (evidence)', 'One row per sign-in', 'at sign-in']],
        ['devices', ['Verified = measured', 'Last report', 'Evidence source', 'Not applicable']], ['decisions', ['Network changes', 'Access decisions']], ['audit', ['Audit log']],
        ['users', ['Accounts', 'Emergency access requests']], ['policy', ['Evaluation tools', 'Decision thresholds']], ['session', ['Your session', 'Your device', 'Your network', 'Evidence source', 'Confirmed by the server']]];
      for (const [id, needs] of screens) {
        await route(adminPg, '#/' + id, 2600);
        const s = await snap(adminPg); seen[id] = s;
        const missing = needs.filter((n) => !s.text.toLowerCase().includes(n.toLowerCase()));
        if (missing.length) problems.push(`${id}: missing [${missing.join(', ')}]`);
        if (s.chips > 0) problems.push(`${id}: status chips shown`);
        if (['overview', 'sessions', 'devices', 'decisions', 'audit', 'users'].includes(id) && !/Live - updated \d\d:\d\d:\d\d/.test(s.text)) problems.push(`${id}: no live-update time`);
        if (['overview', 'sessions', 'devices'].includes(id) && !/server clock/.test(s.text)) problems.push(`${id}: update time is not the server's`);
      }
      rec('RU5', 'Security administrator console keeps its monitoring: eight screens (overview, sessions, devices, decisions, audit, users, policy, own session), each saying what it measures and showing when the data was read (server clock), the evidence columns, the device evidence vocabulary and the network-change filter', 'all 8 screens with their evidence', `problems: [${problems.join('; ')}]`, problems.length === 0);
      const idxProblems = [];
      for (const id of ['overview', 'sessions', 'devices', 'decisions', 'audit', 'users', 'policy', 'session']) { const s = seen[id]; const hm = /\bhealthy\b/i.exec(s.text); if (hm) idxProblems.push(id + ': the word "healthy" is shown: ...' + s.text.slice(Math.max(0, hm.index - 60), hm.index + 40).replace(/\s+/g, ' ') + '...'); }
      const bad2 = ['Phone/browser', 'This phone'].filter((x) => Object.values(seen).some((s) => s.text.includes(x)));
      if (bad2.length) idxProblems.push('wording: ' + bad2.join(', '));
      rec('RU6', 'The console shows no status pills of the administrator\'s own session (a chip about one\'s own risk next to other users\' alerts reads as system status) and never uses the word "healthy" or "Phone/browser"', 'no chips, no "healthy", no "Phone/browser"', `problems: [${idxProblems.join('; ')}]`, idxProblems.length === 0);
    } catch (e) { rec('RU5', 'Administrator console checks ran', 'no exception', e && e.message || e, false); }
  }

  // ---------------------------------------------------------------- RU16: "Check access now" on the administrator's own session asks for something that role may do
  {
    const problems = [];
    try {
      await route(adminPg, '#/session', 2500);
      const dev = await deviceOf(adminPg);
      const mine = async () => (((await apiCall(adm, 'GET', '/admin/sessions')).json || {}).sessions || []).find((s) => s.device_id === dev && s.username === 'sec_dan' && s.status === 'ACTIVE');
      const before = await mine();
      let lastCard = '';
      for (let i = 0; i < 6; i++) {            // six clicks: the earlier version was refused by design every time (15 points each) and revoked the session after four
        await adminPg.js("(() => { const s = document.getElementById('probe-result'); while (s && s.firstChild) s.removeChild(s.firstChild); document.getElementById('check-access').click(); })()");
        lastCard = await until(() => adminPg.js("(document.querySelector('#probe-result .result-card') || {}).innerText || ''"), 12000) || '';
        if (!/Access allowed/.test(lastCard)) { problems.push(`click ${i + 1}: ${lastCard.replace(/\s+/g, ' ').slice(0, 120)}`); break; }
        await sleep(400);
      }
      const after = await mine();
      if (!before || !after) problems.push('the administrator session is not listed as active afterwards');
      else if (after.risk_points !== before.risk_points) problems.push(`session risk changed from ${before.risk_points} to ${after.risk_points}`);
      rec('RU16', 'On the administrator\'s own-session screen, "Check access now" requests something the role may do (the administration summary): six clicks in a row are all "Access allowed", add nothing to the session risk and leave the session active (the earlier button asked for the patient list, which that role may never have, and ended the session after four clicks)', 'six allowed checks, risk unchanged, session active', `problems: [${problems.join('; ')}]; last card: ${lastCard.replace(/\s+/g, ' ').slice(0, 80)}`, problems.length === 0);
    } catch (e) { rec('RU16', 'The administrator access check ran', 'no exception', e && e.message || e, false); }
  }

  // ---------------------------------------------------------------- RU7: other roles' routes lead nowhere
  {
    const problems = []; let count = 0;
    const foreign = ['#/overview', '#/sessions', '#/devices', '#/decisions', '#/audit', '#/users', '#/policy', '#/session', '#/demo', '#/appointments'];
    for (const [user, w] of Object.entries(WORK)) {
      let pg;
      try {
        pg = await openPage(); await signIn(pg, user);
        for (const hsh of foreign) {
          if (user === 'front_carol' && hsh === '#/appointments') continue;
          await route(pg, hsh, 900); count++;
          const s = await snap(pg);
          if (!w.nav.includes(s.pageTitle)) problems.push(`${user} ${hsh}: shows "${s.pageTitle}"`);
          if (w.deny.test(s.controls.join(' | '))) problems.push(`${user} ${hsh}: foreign control`);
        }
        const bad = pg.reqs().filter((r) => /\/admin\/|\/ctl\/(policy|simulate)/.test(r));
        if (bad.length) problems.push(`${user}: requests ${[...new Set(bad)].join(', ')}`);
      } catch (e) { problems.push(`${user}: ${e && e.message}`); }
      if (pg) { try { await pg.js("document.getElementById('signout-btn') && document.getElementById('signout-btn').click()"); } catch (e) { /* gone */ } await pg.close(); }
    }
    for (const hsh of ['#/patients', '#/appointments', '#/demo']) {
      await route(adminPg, hsh, 900); count++;
      const s = await snap(adminPg);
      if (['My patients', 'Ward patients', 'Patient registry', 'Appointments', 'Demonstration tools'].includes(s.pageTitle) || /Assigned patients|Patient ID|Reschedule/.test(s.text)) problems.push(`security_admin ${hsh}: shows "${s.pageTitle}"`);
    }
    rec('RU7', 'Routes of other roles lead nowhere: every security route typed into a doctor, nurse or receptionist page, and every clinical route typed into the administrator\'s, falls back to the role\'s own first screen with none of the foreign controls, and the clinical pages make no request to an administration endpoint', 'own screens only', `${count} routes tried; problems: [${problems.slice(0, 6).join('; ')}]`, problems.length === 0 && count >= 30);
  }

  // ---------------------------------------------------------------- RU8: device labels (desktop, phone and tablet user agents, separate devices)
  let phonePg, tabletPg, deskPg;
  {
    const problems = [];
    try {
      const login = await (async () => { const p = await openPage(); await p.go(base + '/'); await until(() => p.js("!!document.querySelector('form input[type=password]')"), 15000); const t = await p.js("document.body.innerText"); await p.close(); return t; })();
      if (!/This browser/.test(login) || /phone/i.test(login)) problems.push('sign-in screen device wording: ' + login.replace(/\s+/g, ' ').slice(0, 120));
      deskPg = await openPage(); await signIn(deskPg, 'dr_alice');
      phonePg = await openPage({ width: 360, height: 740, mobile: true, ua: PHONE_UA }); await signIn(phonePg, 'nurse_bob');
      tabletPg = await openPage({ width: 820, height: 1180, mobile: true, ua: TABLET_UA }); await signIn(tabletPg, 'front_carol');
      const devRes = await apiCall(adm, 'GET', '/admin/devices'); const devs = devRes.json || {};
      if (!devs.devices) problems.push('device list unavailable: HTTP ' + devRes.status + ' ' + (devs.error || ''));
      const labelOf = async (pg) => { const id = await deviceOf(pg); const d = (devs.devices || []).find((x) => x.device_id === id); return d ? `${d.kind}/${d.hostname}` : 'missing:' + id; };
      const got = { desktop: await labelOf(deskPg), phone: await labelOf(phonePg), tablet: await labelOf(tabletPg) };
      if (got.desktop !== 'browser/Desktop browser') problems.push('desktop browser is recorded as ' + got.desktop);
      if (got.phone !== 'browser/Phone browser') problems.push('phone user agent is recorded as ' + got.phone);
      if (got.tablet !== 'browser/Tablet browser') problems.push('tablet user agent is recorded as ' + got.tablet);
      await route(adminPg, '#/devices', 3000);
      const titles = await adminPg.js("[...document.querySelectorAll('.device-card .panel-head h2')].map((h) => h.textContent.trim())");
      if (!titles.length) problems.push('the device screen shows no cards at all; ' + await adminPageState());
      for (const want of ['Desktop browser', 'Phone browser', 'Tablet browser']) if (!titles.some((t) => t.startsWith(want))) problems.push(`the device screen lacks a "${want}" card (${titles.length} cards)`);
      if (titles.some((t) => /phone\/browser|^device /i.test(t))) problems.push('ambiguous device title: ' + titles.join(' | '));
      const evalPhone = await snap(phonePg);
      if (/phone/i.test(evalPhone.text) && !/Phone browser/.test(evalPhone.text)) problems.push('the phone page mentions a phone in an unexpected way');
      rec('RU8', 'Device labels do not misrepresent the device: the sign-in screen offers "This browser" (never "phone"), a desktop browser is recorded and listed as "Desktop browser", a phone user agent as "Phone browser", a tablet user agent as "Tablet browser" (server-side labels), and the device screen titles every browser card that way', 'Desktop / Phone / Tablet browser, never "Phone/browser"', `problems: [${problems.join('; ')}]; recorded: ${JSON.stringify(got)}`, problems.length === 0);
    } catch (e) { rec('RU8', 'Device label checks ran', 'no exception', e && e.message || e, false); }
  }

  // ---------------------------------------------------------------- RU9 / RU10: evidence states (unknown, stale, verified) and network honesty on the administrator's screens
  {
    const problems = [];
    try {
      // a browser device that signed in through the API and never reports again becomes stale; one second page keeps reporting (heartbeat every 10 s)
      const deskId = await deviceOf(deskPg);
      await freshAdmin('stale');
      await setPolicy(adm, 'device.phone_stale_seconds', 15);
      await apiCall(adm, 'POST', '/ctl/heartbeat', { signals: { secure_context: true, online: true, visible: true, standalone: false, connection: '4g' } });
      const quiet = await apiLogin('nurse_bob', 'RU-STALE-DEVICE-1', 'Tablet browser');
      await sleep(18000);
      await apiCall(adm, 'POST', '/ctl/heartbeat', { signals: { secure_context: true, online: true, visible: true, standalone: false, connection: '4g' } });
      await route(adminPg, '#/devices', 3000);
      const cards = await adminPg.js(`[...document.querySelectorAll('.device-card')].map((c) => ({ title: (c.querySelector('.panel-head h2') || {}).textContent.trim(), badges: [...c.querySelectorAll('.status-line .badge')].map((b) => b.textContent.trim()), text: c.innerText }))`);
      const stale = cards.filter((c) => c.title === 'Tablet browser ' + fingerprint('RU-STALE-DEVICE-1') && c.badges.includes('Stale'));
      if (!cards.length) problems.push('the device screen shows no cards at all; ' + await adminPageState());
      if (!stale.length) problems.push('no stale card for the device that stopped reporting (' + cards.length + ' cards)');
      else if (!/last report is \d+ s old/.test(stale[0].text) || /Verified|Unknown/.test(stale[0].badges.join(' '))) problems.push('the stale card does not state its age: ' + stale[0].text.replace(/\s+/g, ' ').slice(0, 140));
      const verifiedBrowsers = cards.filter((c) => !/^Registered laptop/.test(c.title) && c.badges.includes('Verified'));
      if (verifiedBrowsers.length) problems.push('a browser is shown as Verified: ' + verifiedBrowsers.map((c) => c.title).join(', '));
      const deskCard = cards.filter((c) => c.title === 'Desktop browser ' + fingerprint(deskId));
      if (deskCard.length !== 1 || !deskCard[0].badges.includes('Unknown') || !/Self-reported only/.test(deskCard[0].text)) problems.push('a fresh browser is not shown as Unknown / self-reported only: ' + deskCard.map((c) => c.badges.join('/')).join(' | '));
      if (cards.some((c) => /healthy/i.test(c.text) || c.badges.some((b) => /^healthy$/i.test(b)))) problems.push('the word healthy appears on a device card');
      await freshAdmin('stale2');
      await setPolicy(adm, 'device.phone_stale_seconds', 90);
      await apiCall(quiet, 'POST', '/ctl/logout', null);
      rec('RU9', 'Unknown and stale evidence is never shown as healthy: a browser that reports normally is "Unknown" (self-reported only), a device that stopped reporting is "Stale" with the age of its last report, a browser is never "Verified", and the word "healthy" appears on no device card', 'Unknown / Stale with age; Verified only for the signed agent', `problems: [${problems.join('; ')}]; cards: ${cards.map((c) => c.title + ':' + c.badges.join('/')).join(' | ')}`, problems.length === 0);
    } catch (e) { rec('RU9', 'Evidence state checks ran', 'no exception', e && e.message || e, false); try { await freshAdmin('stale-restore'); await setPolicy(adm, 'device.phone_stale_seconds', 90); } catch (x) { /* the runner restores it too */ } }
    const problems2 = [];
    try {
      await route(adminPg, '#/sessions', 3000);
      const rows = await adminPg.js(`[...document.querySelectorAll('#session-table tbody tr')].map((r) => r.innerText.replace(/\\s+/g, ' '))`);
      const loopRows = rows.filter((r) => /127\.0\.0\.1|::1/.test(r));
      if (!rows.length) problems2.push('no session rows');
      for (const r of loopRows) { if (!/local address: a network change could not be seen/.test(r)) problems2.push('a loopback session without the local-address note: ' + r.slice(0, 120)); if (/\bUnchanged\b(?! \(local\))/.test(r)) problems2.push('plain "Unchanged" for a loopback session: ' + r.slice(0, 120)); }
      if (rows.some((r) => !/at sign-in \d\d:\d\d:\d\d/.test(r))) problems2.push('a session row without the sign-in time');
      rec('RU10', 'Network evidence is honest: every session row shows the address at sign-in with its time, and a session whose address is local (the demonstration runs on one machine) says that a network change could not be seen instead of claiming "unchanged"', 'time and local-address note on every row', `${rows.length} rows; problems: [${problems2.slice(0, 4).join('; ')}]`, problems2.length === 0 && rows.length > 0);
    } catch (e) { rec('RU10', 'Network evidence checks ran', 'no exception', e && e.message || e, false); }
  }

  // ---------------------------------------------------------------- RU11: evaluation mode exists only when asked for and only while the administrator allows it
  {
    const problems = []; let pg, pgA, pgR;
    try {
      pg = await openPage(); await signIn(pg, 'dr_alice', { evaluation: true });
      const ev = await snap(pg);
      const pill = await pg.js("(document.getElementById('eval-pill') || {}).textContent || ''");
      const chipsText = await pg.js("['chip-session','chip-net','chip-device','chip-risk'].map((id) => (document.getElementById(id) || {}).textContent || '').join(' | ')");
      if (pill !== 'Evaluation mode') problems.push('no evaluation pill: "' + pill + '"');
      if (!ev.nav.includes('My session') || !ev.nav.includes('Demonstration tools')) problems.push('evaluation navigation: ' + JSON.stringify(ev.nav));
      if (!/Desktop browser - Unknown/.test(chipsText) || /healthy/i.test(chipsText) || !/Session confirmed \d\d:\d\d:\d\d/.test(chipsText) || !/Network: Unchanged \(local address\)/.test(chipsText) || !/Session risk: (Low|Elevated|High)/.test(chipsText)) problems.push('evaluation chips: ' + chipsText);
      await route(pg, '#/session', 2500);
      const sv = await snap(pg);
      for (const need of ['Your device', 'Unknown', 'Self-reported only', 'Evidence source', 'Not applicable to this device', 'Your network']) if (!sv.text.includes(need)) problems.push('evaluation session screen lacks "' + need + '"');
      pgR = await openPage(); await signIn(pgR, 'front_carol', { evaluation: true });
      const evR = await snap(pgR); if (!evR.nav.includes('Demonstration tools') || evR.chips < 1) problems.push('receptionist evaluation mode incomplete');
      pgA = await openPage(); await signIn(pgA, 'sec_dan', { evaluation: true });
      const evA = await snap(pgA); if (evA.nav.some((n) => /Demonstration|Evaluation/i.test(n)) || evA.chips > 0 || /Evaluation mode/.test(evA.text)) problems.push('the administrator got evaluation mode');
      // the administrator switches the evaluation tools off: the open evaluation page loses them at its next session check, and a new page never gets them
      await freshAdmin('eval'); const off = await setPolicy(adm, 'simulation.enabled', false);
      if (off.status !== 200) problems.push('could not switch the evaluation tools off: HTTP ' + off.status);
      await pg.js("document.getElementById('account-btn').click()"); await dialogOpen(pg); await closeDialog(pg); await sleep(800);
      const after = await snap(pg);
      if (after.nav.some((n) => /Demonstration|My session/.test(n)) || after.chips > 0) problems.push('the open evaluation page kept its evaluation entries: ' + JSON.stringify(after.nav) + ' chips ' + after.chips);
      const pg2 = await openPage(); await signIn(pg2, 'dr_alice', { evaluation: true });
      await route(pg2, '#/demo', 900); const e2 = await snap(pg2);
      if (e2.nav.length !== 1 || e2.pageTitle !== 'My patients' || e2.chips > 0) problems.push('with the tools off, ?evaluation=1 still changes the page: ' + JSON.stringify(e2.nav) + ' "' + e2.pageTitle + '"');
      const docNow = await apiLogin('dr_alice', 'RU-API-DOC-SIM-' + Date.now().toString(36));          // a fresh session: the one made at the start is long past its token and device freshness
      const sim = await apiCall(docNow, 'POST', '/ctl/simulate', { kind: 'network', ip: 'reset' });
      if (!(sim.status === 403 && sim.json && sim.json.error === 'simulation_disabled')) problems.push('/ctl/simulate with the tools off: HTTP ' + sim.status);
      await pg2.close();
      await freshAdmin('eval2'); await setPolicy(adm, 'simulation.enabled', true);
      rec('RU11', 'Evaluation mode exists only when asked for (?evaluation=1) and only while the administrator allows it: the chips then name what they refer to with the time the server confirmed it ("Desktop browser - Unknown", "Network: Unchanged (local address)", "Session confirmed hh:mm:ss"), the administrator never gets it, switching the tools off removes it from an open page, and the server refuses the simulation requests', 'off by default, on request, off again on policy', `problems: [${problems.join('; ')}]`, problems.length === 0);
    } catch (e) { rec('RU11', 'Evaluation mode checks ran', 'no exception', e && e.message || e, false); try { await freshAdmin('eval-restore'); await setPolicy(adm, 'simulation.enabled', true); } catch (x) { /* the runner restores it too */ } }
    for (const p of [pg, pgA, pgR]) if (p) { try { await p.js("document.getElementById('signout-btn') && document.getElementById('signout-btn').click()"); } catch (e) { /* gone */ } await p.close(); }
  }

  // ---------------------------------------------------------------- RU15: the administrator's screens carry no patient data; the administrator's direct calls are refused
  {
    const problems = [];
    try {
      for (const id of ['overview', 'sessions', 'devices', 'decisions', 'audit', 'users', 'policy', 'session']) {
        await route(adminPg, '#/' + id, 1800);
        const s = await snap(adminPg);
        const leaked = patientNames.concat(clinicalStrings).filter((x) => x && s.text.includes(x));
        if (leaked.length) problems.push(`${id}: shows ${leaked.length} patient value(s)`);
      }
      const calls = [['GET', '/api/patients/list'], ['GET', '/api/patients/101/summary'], ['GET', '/api/patients/101/records'], ['POST', '/api/patients/101/export-pdf'], ['POST', '/api/patients/101/appointment', {}], ['POST', '/ctl/break-glass', { patient_id: 101, justification: 'The administrator tries emergency access: synthetic data, long enough.' }]];
      const out = [];
      for (const [m, p, b] of calls) { const one = await apiLogin('sec_dan', 'RU-API-ADMIN-clin-' + out.length + '-' + Date.now().toString(36)); const r = await apiCall(one, m, p, b || null, pin('sec_dan')); out.push(`${m} ${p} -> ${r.status} ${r.json && r.json.error}`); if (!(r.status === 403 && r.json && r.json.error === 'role_denied')) problems.push('not refused: ' + out[out.length - 1]); }
      rec('RU15', 'The security administrator\'s access to security events does not imply access to clinical data: none of the eight console screens shows a patient name or clinical value, and the administrator\'s own direct calls for the patient list, summary, record, export, appointment and emergency access are all refused (role_denied)', 'no patient data on any screen; 6 refusals', `problems: [${problems.join('; ')}]; ${out.join('; ')}`, problems.length === 0);
    } catch (e) { rec('RU15', 'Administrator separation checks ran', 'no exception', e && e.message || e, false); }
  }

  // ---------------------------------------------------------------- RU12: the account menu (compact account and session details)
  {
    const problems = [];
    for (const [user, w] of Object.entries(WORK)) {
      const t = accountTexts[user] || '';
      const needs = ['Account', 'Signed in as', 'Role', 'Signed in at', 'Automatic sign-out', 'Longest session', 'Sign out'];
      const missing = needs.filter((n) => !t.includes(n));
      if (missing.length) problems.push(`${user}: account menu lacks ${missing.join(', ')}`);
      if (!t.includes(w.role)) problems.push(`${user}: role missing`);
      if (user === 'nurse_bob' && !/Ward A/.test(t)) problems.push('the nurse\'s ward is missing');
    }
    rec('RU12', 'The compact account menu (the avatar in the top bar) holds the account and session details a clinical user may need: name, role (and ward), when they signed in, the automatic sign-out and the longest session limit, the server\'s confirmation of the session, and Sign out; nothing about risk, devices or networks', 'details present, no security wording', `problems: [${problems.join('; ')}]`, problems.length === 0);
  }

  // ---------------------------------------------------------------- RU13 / RU14: session notices and the end of the session (revoked, expired idle, maximum length)
  {
    const problems = []; let pgN, pgI, pgM, pgV;
    try {
      // revocation by the administrator: the open page shows plain words by itself
      pgV = await openPage(); await signIn(pgV, 'nurse_bob');
      const dev = await deviceOf(pgV);
      await freshAdmin('revoke');
      const sl = ((await apiCall(adm, 'GET', '/admin/sessions')).json || {}).sessions || [];
      const mine = sl.find((s) => s.device_id === dev && s.status === 'ACTIVE');
      if (!mine) problems.push('the nurse page has no active session on the server');
      else {
        const rv = await apiCall(adm, 'POST', '/admin/sessions/revoke', { session_id: mine.session_id, reason: 'role UX check' }, pin('sec_dan'));
        if (rv.status !== 200) problems.push('revoke HTTP ' + rv.status);
        if (!(await until(() => pgV.js("!!document.getElementById('signin-again')"), 25000))) problems.push('the page did not switch to the session-ended screen');
        else {
          const s = await snap(pgV);
          if (!/Session ended/.test(s.title) || !/Your session was ended for security reasons/.test(s.text) || /Decision|Reference|risk|points|threshold|role UX check|revoked by/i.test(s.text)) problems.push('revoked screen: ' + s.text.replace(/\s+/g, ' ').slice(0, 200));
        }
      }
      // idle expiry: 8 s without a protected request ends the session; the 10 s heartbeat notices
      await freshAdmin('idle'); await setPolicy(adm, 'session.idle_timeout_seconds', 8);
      pgI = await openPage(); await signIn(pgI, 'dr_alice');
      await sleep(3000);
      if (!(await until(() => pgI.js("!!document.getElementById('signin-again')"), 30000))) problems.push('the idle session did not end on the screen');
      else { const s = await snap(pgI); if (!/Session expired/.test(s.text) || !/after a period without activity/.test(s.text) || /\b\d+ (seconds|s)\b|risk|points|threshold|Reference/i.test(s.text)) problems.push('expired screen: ' + s.text.replace(/\s+/g, ' ').slice(0, 200)); }
      await freshAdmin('idle2'); await setPolicy(adm, 'session.idle_timeout_seconds', 125);
      // a session about to be signed out for inactivity is told so, and "Stay signed in" is a real activity
      pgN = await openPage(); await signIn(pgN, 'front_carol');
      const idleShown = await until(() => pgN.js("!!document.getElementById('idle-notice')"), 20000);
      if (!idleShown) problems.push('no idle notice appeared'); else {
        const t = await pgN.js("document.getElementById('idle-notice').innerText");
        if (!/You will be signed out soon/.test(t) || !/Because of inactivity your session ends at \d\d:\d\d:\d\d/.test(t) || !/Stay signed in/.test(t)) problems.push('idle notice text: ' + t.replace(/\s+/g, ' '));
        await pgN.js("document.getElementById('stay-signed-in').click()");
        if (!(await until(() => pgN.js("!document.getElementById('idle-notice')"), 8000))) problems.push('"Stay signed in" did not clear the notice');
      }
      await freshAdmin('idle3'); await setPolicy(adm, 'session.idle_timeout_seconds', 900);
      // the longest session: announced when five minutes are left, and enforced by the server
      await setPolicy(adm, 'session.absolute_timeout_seconds', 60);
      pgM = await openPage(); await signIn(pgM, 'nurse_bob');
      const maxShown = await until(() => pgM.js("!!document.getElementById('max-notice')"), 8000);
      if (!maxShown) problems.push('no maximum-length notice'); else { const t = await pgM.js("document.getElementById('max-notice').innerText"); if (!/Maximum session length/.test(t) || !/ends at /.test(t)) problems.push('maximum-length notice text: ' + t.replace(/\s+/g, ' ')); }
      if (!(await until(() => pgM.js("!!document.getElementById('signin-again')"), 90000))) problems.push('the session did not end at its maximum length');
      else { const s = await snap(pgM); if (!/Session expired/.test(s.text) || !/reached its maximum length/.test(s.text) || /risk|points|Reference/i.test(s.text)) problems.push('maximum-length screen: ' + s.text.replace(/\s+/g, ' ').slice(0, 200)); }
      await freshAdmin('abs'); await setPolicy(adm, 'session.absolute_timeout_seconds', 28800);
      rec('RU13', 'Minimal, actionable session feedback: shortly before the idle sign-out the page says when the session ends and offers "Stay signed in" (which really counts as activity), and shortly before the longest session ends it says so; both limits come from the server', 'notices appear, plain, and clear', `problems: [${problems.filter((p) => /notice|Stay|maximum-length notice/i.test(p)).join('; ')}]`, !problems.some((p) => /notice|Stay|maximum-length notice/i.test(p)));
      rec('RU14', 'The end of a session is shown in plain, true words: revoked by an administrator ("Your session was ended for security reasons"), idle expiry ("Session expired", after a period without activity) and the longest session ("reached its maximum length"), none with a decision, a reference code, risk points or limits', 'three plain screens', `problems: [${problems.filter((p) => !/notice|Stay|maximum-length notice/i.test(p)).join('; ')}]`, !problems.some((p) => !/notice|Stay|maximum-length notice/i.test(p)));
    } catch (e) {
      rec('RU13', 'Session notice checks ran', 'no exception', e && e.message || e, false);
      try { await freshAdmin('restore'); await setPolicy(adm, 'session.idle_timeout_seconds', 900); await setPolicy(adm, 'session.absolute_timeout_seconds', 28800); } catch (x) { /* the runner restores them too */ }
    }
    for (const p of [pgN, pgI, pgM, pgV]) if (p) await p.close();
  }

  for (const p of [deskPg, phonePg, tabletPg, adminPg]) if (p) { try { await p.js("document.getElementById('signout-btn') && document.getElementById('signout-btn').click()"); } catch (e) { /* gone */ } await p.close(); }
  ws.close();
}

main().catch((e) => rec('RU0', 'The role-interface checks ran to the end', 'no exception', e && e.stack || e, false)).finally(() => {
  try { chrome && chrome.kill(); } catch (e) { /* gone */ }
  setTimeout(() => { process.stdout.write('RESULT_JSON:' + JSON.stringify(results) + '\n'); process.exit(0); }, 800);
});
