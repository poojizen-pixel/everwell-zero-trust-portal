// End-to-end scenarios driven through the REAL screens in headless desktop Chrome (throw-away profile), each one compared with what the server recorded:
//   U1 posture change on a phone-sized screen -> the screen shows the decision the server actually took (step-up, then denied), and the audit log agrees
//   U2 simulated network change -> step-up decision, PIN, allowed, network baseline updated
//   U3 repeated forbidden requests -> risk rises on screen, the server revokes the session and locks the account, the old session is dead, sign-in is refused
//   U4 a security administrator revokes a live session -> that user's screen shows "Session ended" without any click
//   U5 emergency access -> scoped to one patient, read-only, countdown, ends by itself, the record is refused again afterwards
//   U6 receptionist reschedules an appointment through the screen -> stored by the server, audited; a past date is refused and shown
//   U3b the administrator unlocks the locked account from the Users screen; U7 export identifiers are masked until the doctor asks to see them
//   U8 administrator screens: filters, device provenance badges and names; U9 a policy change asks for the PIN and is audited
// Environment: ZT_TEST_CHROME, ZT_TEST_BASE (loopback edge), ZT_TEST_PROFILE, ZT_ROLE_CREDS, ZT_ROLE_PINS (JSON maps, never printed), ZT_BG_SECONDS (emergency duration set by the runner).
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const env = process.env;
const base = env.ZT_TEST_BASE;
const creds = JSON.parse(env.ZT_ROLE_CREDS || '{}');
const pins = JSON.parse(env.ZT_ROLE_PINS || '{}');
const bgSeconds = Number(env.ZT_BG_SECONDS || 8);
const results = [];
const rec = (id, title, expected, actual, ok) => { results.push({ id, title, expected, actual: String(actual), ok: ok === true }); console.error(`${ok === true ? 'PASS' : 'FAIL'} ${id} ${title}${ok === true ? '' : ' -> ' + actual}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 15000, step = 150) { const end = Date.now() + ms; while (Date.now() < end) { try { const v = await fn(); if (v) return v; } catch (e) { /* retry */ } await sleep(step); } return null; }
let chrome = null;
process.on('exit', () => { try { chrome && chrome.kill(); } catch (e) { /* gone */ } });

// ---- the same server, asked directly (to compare with what the screens showed): a browser-kind device per call site
async function apiLogin(user, device) {
  const r = await fetch(base + '/ctl/login', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Device-Id': device }, body: JSON.stringify({ username: user, password: creds[user], device_kind: 'browser', device_label: 'ui scenario check', platform: 'Windows', signals: { secure_context: true, standalone: false, online: true, visible: true, connection: '4g' } }) });
  const j = await r.json().catch(() => ({}));
  return { status: r.status, token: j.token, device, json: j };
}
async function apiCall(s, method, p, body, extra = {}) {
  const headers = { 'X-Device-Id': s.device, Authorization: 'Bearer ' + s.token, ...extra };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const r = await fetch(base + p, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const t = await r.text(); let j = null; try { j = JSON.parse(t); } catch (e) { /* not json */ }
  return { status: r.status, json: j, text: t };
}

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
  const send = (method, params = {}, sessionId) => new Promise((res, rej) => { const id = ++nextId; pending.set(id, { res, rej }); ws.send(JSON.stringify({ id, method, params, sessionId })); });

  async function openPage(width, height, mobile) {
    const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
    const cmd = (m, p) => send(m, p, sessionId);
    for (const d of ['Page', 'Runtime']) await cmd(d + '.enable');
    await cmd('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: mobile ? 2 : 1, mobile });
    if (mobile) await cmd('Emulation.setTouchEmulationEnabled', { enabled: true, maxTouchPoints: 5 });
    const js = async (expression) => { const r = await cmd('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }); if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception ? r.exceptionDetails.exception.description : r.exceptionDetails.text); return r.result.value; };
    const go = async (url) => { const mark = events.length; await cmd('Page.navigate', { url }); await until(() => events.slice(mark).some((e) => e.sessionId === sessionId && e.method === 'Page.loadEventFired'), 15000); };
    return { targetId, sessionId, cmd, js, go };
  }
  const click = (pg, sel, textMatch) => pg.js(`(() => { const els = [...document.querySelectorAll(${JSON.stringify(sel)})]; const e = ${textMatch ? `els.find((x) => (x.innerText || '').trim().startsWith(${JSON.stringify(textMatch)}))` : 'els[0]'}; if (!e) return false; e.click(); return true; })()`);
  const text = (pg, sel) => pg.js(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); return e ? (e.innerText || e.textContent || '').replace(/\\s+/g, ' ').trim() : null; })()`);
  const settle = async (pg, ms = 1200) => { await sleep(ms); await until(() => pg.js("!document.querySelector('.skeleton')"), 8000); };
  async function signIn(pg, user, mode, evaluation) {
    await pg.go(base + '/' + (evaluation ? '?evaluation=1' : ''));
    await until(() => pg.js("!!document.querySelector('form input[type=password]')"), 15000);
    if (mode === 'laptop') await pg.js("document.querySelector('input[name=mode][value=laptop]').click()");
    await pg.js(`(() => { document.querySelector('#u').value = ${JSON.stringify(user)}; document.querySelector('#p').value = ${JSON.stringify(creds[user])}; document.querySelector('form').requestSubmit(); })()`);
    const ok = await until(() => pg.js("!!document.querySelector('.topbar')"), 15000);
    await settle(pg, 1500);
    return !!ok;
  }
  const answerPin = async (pg, user, wait = 4000) => {
    if (!(await until(() => pg.js("!!document.querySelector('#pin-input')"), wait))) return false;
    await pg.js(`(() => { const i = document.querySelector('#pin-input'); i.value = ${JSON.stringify(pins[user] || '')}; i.closest('form').requestSubmit(); })()`);
    await sleep(1200);
    return true;
  };
  const signOut = async (pg) => { await pg.js("document.getElementById('signout-btn') && document.getElementById('signout-btn').click()"); await sleep(500); };
  const nowTs = () => Math.floor(Date.now() / 1000);

  // an administrator session through the API, to read the audit log and clean up afterwards
  const admin = await apiLogin('sec_dan', 'UI-SCENARIO-ADMIN');
  const events_ = async (query) => (await apiCall(admin, 'GET', '/admin/events?' + query)).json.events || [];
  const unlock = (u) => apiCall(admin, 'POST', '/admin/unlock', { username: u }, { 'X-StepUp-Pin': pins.sec_dan });

  // ---------------------------------------------------------------- U1 / U2: posture and network change on a phone-sized screen
  const t0 = nowTs();
  let pg = await openPage(360, 740, true);
  if (!(await signIn(pg, 'dr_alice', 'browser', true))) throw new Error('doctor sign-in failed');          // evaluation mode: the demonstration tools and the status chips exist only there
  await pg.js("location.hash = '#/demo'"); await settle(pg, 1500);
  await click(pg, '#sim-screen_lock');                                  // screen lock off (simulated)
  await click(pg, '#apply-posture');
  await until(() => pg.js("!!document.querySelector('#posture-result .result-card')"), 12000);
  const u1a = await text(pg, '#posture-result .result-card');
  const chip1 = await pg.js("document.getElementById('chip-device').textContent.trim()");
  await click(pg, '#sim-os_current');                                   // OS patches off as well: the combined risk crosses the deny limit
  await click(pg, '#apply-posture');
  await until(() => pg.js("(document.querySelector('#posture-result .result-card h3') || {}).textContent === 'Access denied'"), 12000);
  const u1b = await text(pg, '#posture-result .result-card');
  await click(pg, '#reset-sim');
  await until(() => pg.js("!!document.querySelector('#posture-result .result-card.ok')"), 12000);
  const u1c = await text(pg, '#posture-result .result-card');
  const chip3 = await pg.js("document.getElementById('chip-device').textContent.trim()");
  const serverDecisions = (await events_('limit=200&type=DECISION')).filter((e) => e.username === 'dr_alice' && e.path === '/api/patients/list' && e.ts >= t0).map((e) => e.decision + ':' + e.code);
  const stepIdx = serverDecisions.lastIndexOf('STEP_UP:step_up_required'), denyIdx = serverDecisions.lastIndexOf('DENY:risk_too_high');
  rec('U1', 'Phone-sized screen, simulated posture change: switching the screen lock off shows "Step-up required" and a degraded device, adding an outdated OS shows "Denied" with the risk reason, resetting shows "Allowed" - and the audit log recorded exactly those server decisions',
    'screen (evaluation mode): step-up, then denied (risk), then allowed; device chip "Desktop browser - Unhealthy" then "Desktop browser - Unknown" (never healthy); server audit: STEP_UP then DENY risk_too_high for the doctor\'s request',
    `step-up card: ${/Step-up verification required/.test(u1a || '') && /Step-up required/.test(u1a || '')}; device chip "${chip1}"; denied card: ${/Access denied/.test(u1b || '') && /Denied/.test(u1b || '') && /above the allowed level/i.test(u1b || '')}; reset card allowed: ${/Access allowed/.test(u1c || '')}; chip after reset "${chip3}"; server decisions (oldest last): ${serverDecisions.slice(0, 6).join(', ')}`,
    /Step-up verification required/.test(u1a || '') && /Step-up required/.test(u1a || '') && /Desktop browser - Unhealthy/.test(chip1) && /Access denied/.test(u1b || '') && /Denied/.test(u1b || '') && /above the allowed level/i.test(u1b || '') && /Access allowed/.test(u1c || '') && /Desktop browser - Unknown/.test(chip3) && !/healthy/i.test(chip3.replace(/Unhealthy/i, '')) && stepIdx >= 0 && denyIdx >= 0 && denyIdx < stepIdx);

  const t1 = nowTs();
  await pg.js("(() => { const s = document.querySelector('#sim-network'); s.value = 'other'; s.dispatchEvent(new Event('change')); })()");
  await click(pg, '#apply-network');
  await until(() => pg.js("!!document.querySelector('#network-result .result-card')"), 12000);
  const u2a = await text(pg, '#network-result .result-card');
  const net1 = await pg.js("document.getElementById('chip-net').textContent.trim()");
  await click(pg, '#network-result .result-card button');                 // "Enter PIN and re-evaluate"
  const pinShown = await answerPin(pg, 'dr_alice', 6000);
  await until(() => pg.js("(document.querySelector('#network-result .result-card h3') || {}).textContent === 'Access allowed after step-up verification'"), 12000);
  const u2b = await text(pg, '#network-result .result-card');
  const net2 = await pg.js("document.getElementById('chip-net').textContent.trim()");
  const netDecisions = (await events_('limit=200&type=DECISION')).filter((e) => e.username === 'dr_alice' && e.path === '/api/patients/list' && e.ts >= t1).map((e) => e.decision);
  rec('U2', 'Simulated network change (different subnet): the screen shows "Step-up required" and a changed (simulated) network; after the PIN it shows "Allowed after step-up" and the network baseline is updated; the audit log has the step-up and the allow',
    'step-up card + network changed (simulated); PIN prompt; allowed after step-up; network unchanged again; server: STEP_UP and ALLOW',
    `step-up card: ${/Step-up verification required/.test(u2a || '')}; chip "${net1}"; PIN prompt shown: ${pinShown}; allowed card: ${/Access allowed after step-up verification/.test(u2b || '')}; chip "${net2}"; server decisions: ${netDecisions.join(', ')}`,
    /Step-up verification required/.test(u2a || '') && /Network: Changed \(simulated\)/.test(net1) && pinShown && /Access allowed after step-up verification/.test(u2b || '') && /Network: Unchanged/.test(net2) && netDecisions.includes('STEP_UP') && netDecisions.includes('ALLOW'));
  await pg.js("(() => { const s = document.querySelector('#sim-network'); s.value = 'reset'; s.dispatchEvent(new Event('change')); })()");
  await click(pg, '#apply-network'); await sleep(1500);

  // ---------------------------------------------------------------- U3: risk escalation -> revocation -> lockout
  await pg.js("location.hash = '#/demo'"); await settle(pg, 800);
  const riskBefore = await pg.js("document.getElementById('chip-risk').textContent.trim()");
  const startedAt = nowTs();                    // (evaluation mode: the plain ended screen of the normal workspace is checked in U4 and RU14)
  await click(pg, '#burst-btn');
  const ended = await until(() => pg.js("!!document.querySelector('.ended')"), 40000);
  const endedText = ended ? await text(pg, '.ended') : '';
  const sessionsAfter = (await events_('limit=200&type=SESSION_REVOKED')).filter((e) => e.username === 'dr_alice' && e.ts >= startedAt);
  const lockEvents = (await events_('limit=200&type=LOCKOUT')).filter((e) => e.username === 'dr_alice' && e.ts >= startedAt);
  await click(pg, '#signin-again');
  await until(() => pg.js("!!document.querySelector('form input[type=password]')"), 8000);
  await pg.js(`(() => { document.querySelector('#u').value = 'dr_alice'; document.querySelector('#p').value = ${JSON.stringify(creds.dr_alice)}; document.querySelector('form').requestSubmit(); })()`);
  const lockedMsg = await until(() => pg.js("(document.querySelector('#login-msg .alert') || {}).innerText || ''"), 10000);
  rec('U3', 'Repeated forbidden requests: the risk indicator rises, the server revokes the session and locks the account, the screen shows "Session ended" with the decision and reason, and a new sign-in is refused until an administrator unlocks it',
    'session ended screen (revoked, risk reason, risk High); audit has SESSION_REVOKED and LOCKOUT for the doctor; sign-in blocked with a locked message',
    `risk before: "${riskBefore}"; ended screen: ${!!ended}; text mentions revoked: ${/revoked/i.test(endedText)}, risk threshold: ${/risk threshold/i.test(endedText)}, High: ${/High/.test(endedText)}; audit revoked ${sessionsAfter.length}, lockout ${lockEvents.length}; sign-in message: "${(lockedMsg || '').slice(0, 90)}"`,
    !!ended && /Session ended/.test(endedText) && /revoked/i.test(endedText) && /risk threshold/i.test(endedText) && /High/.test(endedText) && sessionsAfter.length >= 1 && lockEvents.length >= 1 && /locked/i.test(lockedMsg || ''));
  // the administrator unlocks the account from the Users screen (also exercises that control); the API unlock is only the fallback
  const adm3 = await openPage(1280, 900, false);
  let lockShown = '', unlockClicked = false, doctorAfter = null;
  if (await signIn(adm3, 'sec_dan', 'browser')) {
    await adm3.js("location.hash = '#/users'"); await settle(adm3, 2500);
    lockShown = await text(adm3, '#user-table tr[data-user="dr_alice"]');
    unlockClicked = await click(adm3, '#user-table tr[data-user="dr_alice"] button');
    await sleep(1800);
    doctorAfter = await apiLogin('dr_alice', 'UI-SCENARIO-DOCTOR-AFTER');
    if (doctorAfter.token) await apiCall(doctorAfter, 'POST', '/ctl/logout');
    await signOut(adm3);
  }
  await send('Target.closeTarget', { targetId: adm3.targetId });
  if (!doctorAfter || doctorAfter.status !== 200) await unlock('dr_alice');
  rec('U3b', 'The Users screen shows the locked account with the reason and an Unlock button; after Unlock the doctor can sign in again',
    '"Locked until" shown; Unlock clicked; the doctor\'s next sign-in is accepted (200)', `row: "${(lockShown || '').slice(0, 90)}"; unlock clicked: ${unlockClicked}; doctor sign-in after: ${doctorAfter ? doctorAfter.status : 'n/a'}`,
    /Locked until/.test(lockShown || '') && unlockClicked && !!doctorAfter && doctorAfter.status === 200);
  await send('Target.closeTarget', { targetId: pg.targetId });

  // ---------------------------------------------------------------- U4: an administrator revokes a live session; the user's screen follows by itself
  const nurse = await openPage(360, 740, true);
  const adm = await openPage(1280, 900, false);
  if (!(await signIn(nurse, 'nurse_bob', 'browser'))) throw new Error('nurse sign-in failed');         // the normal nursing workspace: it shows no session details, so the session is found through the server
  const nurseDevice = await nurse.js("localStorage.getItem('zt_device_id')");
  const liveSessions = ((await apiCall(admin, 'GET', '/admin/sessions')).json || {}).sessions || [];
  const nurseSession = liveSessions.find((s) => s.username === 'nurse_bob' && s.device_id === nurseDevice && s.status === 'ACTIVE');
  const ref = nurseSession ? nurseSession.session_id : '';
  if (!(await signIn(adm, 'sec_dan', 'browser'))) throw new Error('administrator sign-in failed');
  await adm.js("location.hash = '#/sessions'"); await settle(adm, 2500);
  const found = await until(() => adm.js(`!!document.querySelector('#session-table tr[data-session$="${ref}"] button')`), 12000);
  const revokedAt = nowTs();
  if (found) { await adm.js(`document.querySelector('#session-table tr[data-session$="${ref}"] button').click()`); await sleep(600); await adm.js("document.querySelector('dialog.modal form').requestSubmit()"); }
  const endedByAdmin = await until(() => nurse.js("!!document.querySelector('.ended')"), 35000);
  const nurseEnded = endedByAdmin ? await text(nurse, '.ended') : '';
  const endedTitle = endedByAdmin ? await nurse.js('document.title') : '';
  const endedBar = endedByAdmin ? await text(nurse, '.login-bar') : '';
  const admEvents = (await events_('limit=100&type=SESSION_REVOKED')).filter((e) => e.ts >= revokedAt && /nurse_bob/.test(e.reason || ''));
  rec('U4', 'An administrator revokes a live session from the Sessions screen: the nurse\'s open screen switches to "Session ended" by itself (no click), and the audit log records who revoked it',
    'revoke button found for that session; the nurse screen shows Session ended within the heartbeat interval; SESSION_REVOKED event by sec_dan',
    `session row found: ${!!found}; nurse screen ended: ${!!endedByAdmin}; text: "${nurseEnded.slice(0, 70)}"; title "${endedTitle}"; brand bar "${endedBar.replace(/\s+/g, ' ')}"; audit: ${admEvents.map((e) => e.username + ':' + e.code).join(', ') || 'none'}`,
    !!found && !!endedByAdmin && /Session ended/.test(nurseEnded) && /Your session was ended for security reasons/.test(nurseEnded) && !/Decision|Reference|risk|points/i.test(nurseEnded) && endedTitle === 'Session ended - Everwell Hospital' && /Everwell Hospital/.test(endedBar) && admEvents.length >= 1);
  await signOut(adm);
  await send('Target.closeTarget', { targetId: nurse.targetId });
  await send('Target.closeTarget', { targetId: adm.targetId });

  // ---------------------------------------------------------------- U5: emergency access is scoped and time-limited
  pg = await openPage(1280, 900, false);
  if (!(await signIn(pg, 'dr_alice', 'browser'))) throw new Error('doctor sign-in (U5) failed');
  await pg.js("location.hash = '#/patients/103'"); await settle(pg, 1800);
  const restricted = await text(pg, '#restricted');
  const noClinicalBefore = !/Diagnosis|Medication|Care notes/.test(restricted || '');
  await click(pg, '#emergency-btn'); await sleep(600);
  await pg.js("document.querySelector('dialog.modal form').requestSubmit()");              // empty justification: refused on screen
  await sleep(500);
  const shortMsg = await text(pg, 'dialog.modal .dlg-message');
  const grantsBefore = ((await apiCall(admin, 'GET', '/admin/grants')).json.grants || []).filter((g) => g.username === 'dr_alice' && g.patient_id === 103 && g.status === 'ACTIVE').length;
  await pg.js(`(() => { const t = document.querySelector('#bg-justification'); t.value = 'Unresponsive patient in the emergency department; the treating team needs the record now.'; t.dispatchEvent(new Event('input')); document.querySelector('#bg-confirm').click(); document.querySelector('dialog.modal form').requestSubmit(); })()`);
  await answerPin(pg, 'dr_alice', 6000);
  const bannerOn = await until(() => pg.js("!!document.querySelector('#emergency-banner') && !!document.querySelector('#emergency-left')"), 12000);
  await sleep(500);
  const chart = await text(pg, '#chart-body');
  const left = await text(pg, '#emergency-left');
  const exportOffered = await pg.js("!!document.querySelector('#export-btn')");
  const grantRows = ((await apiCall(admin, 'GET', '/admin/grants')).json.grants || []).filter((g) => g.username === 'dr_alice' && g.patient_id === 103 && g.status === 'ACTIVE');
  // the access ends by itself: the screen drops the record without any request, and the server refuses the record again
  const gone = await until(() => pg.js("!!document.querySelector('#emergency-banner.expired')"), (bgSeconds + 8) * 1000);
  const afterText = await text(pg, '#chart-body');
  await click(pg, '#emergency-banner .btn');                                  // "Request emergency access again" re-opens the chart: the server decides again
  await sleep(2000);
  const refusedAgain = await text(pg, '#restricted');
  rec('U5', 'Emergency access: not offered clinical data before the request; a short justification is refused on screen; the granted chart is marked read-only with a countdown and no export; it ends by itself after the approved time and the server refuses the record again',
    'no clinical text before; short justification message; banner + countdown + Diagnosis/Medication/Care notes, no export button; one active grant; expired state without clinical text; refusal (not assigned) afterwards',
    `no clinical before: ${noClinicalBefore}; short-justification message: "${(shortMsg || '').slice(0, 50)}"; banner: ${!!bannerOn}; countdown "${left}"; clinical shown: ${/Diagnosis/.test(chart || '') && /Medication/.test(chart || '') && /Care notes/.test(chart || '')}; export offered: ${exportOffered}; active grants ${grantsBefore} -> ${grantRows.length}; expired state: ${!!gone}, clinical text after: ${/Diagnosis|Medication|Care notes/.test(afterText || '')}; after re-check: "${(refusedAgain || '').slice(0, 60)}"`,
    noClinicalBefore && /too short/i.test(shortMsg || '') && !!bannerOn && /^\d\d:\d\d$/.test(left || '') && /Diagnosis/.test(chart || '') && /Medication/.test(chart || '') && /Care notes/.test(chart || '') && !exportOffered && grantsBefore === 0 && grantRows.length === 1 && !!gone && !/Diagnosis|Medication|Care notes/.test(afterText || '') && /not on your list/i.test(refusedAgain || ''));
  await signOut(pg);
  await send('Target.closeTarget', { targetId: pg.targetId });

  // ---------------------------------------------------------------- U6: appointment management through the screen
  pg = await openPage(1280, 900, false);
  if (!(await signIn(pg, 'front_carol', 'browser'))) throw new Error('receptionist sign-in failed');
  const recSession = await apiLogin('front_carol', 'UI-SCENARIO-RECEPTION');
  const pidA = 104;
  const orig = (await apiCall(recSession, 'GET', `/api/patients/${pidA}/summary`)).json.next_appointment;
  await pg.js("location.hash = '#/appointments'"); await settle(pg, 1800);
  const pad = (n) => String(n).padStart(2, '0');
  const future = new Date(Date.now() + 9 * 86400000); const dstr = `${future.getFullYear()}-${pad(future.getMonth() + 1)}-${pad(future.getDate())}`;
  await click(pg, `#appointment-table tbody tr[data-id="${pidA}"] button`); await sleep(700);
  await pg.js("(() => { const d = document.querySelector('#appt-date'); d.removeAttribute('min'); d.value = '2020-01-01'; document.querySelector('#appt-time').value = '09:00'; document.querySelector('dialog.modal form').requestSubmit(); })()");
  await sleep(1500);
  const pastShown = await text(pg, 'dialog.modal .dlg-message');
  const stillOpen = await pg.js("!!document.querySelector('dialog.modal[open]')");
  const afterPast = (await apiCall(recSession, 'GET', `/api/patients/${pidA}/summary`)).json.next_appointment;
  await pg.js(`(() => { document.querySelector('#appt-date').value = ${JSON.stringify(dstr)}; document.querySelector('#appt-time').value = '14:30'; document.querySelector('dialog.modal form').requestSubmit(); })()`);
  await sleep(2000);
  const closed = await pg.js("!document.querySelector('dialog.modal[open]')");
  const rowText = await text(pg, `#appointment-table tbody tr[data-id="${pidA}"]`);
  const stored = (await apiCall(recSession, 'GET', `/api/patients/${pidA}/summary`)).json.next_appointment;
  const audit = (await events_('limit=200&type=DECISION')).filter((e) => e.username === 'front_carol' && e.path === `/api/patients/${pidA}/appointment`);
  const wantStored = `${dstr} 14:30`;
  // put the demonstration data back
  const restoreOk = orig ? (await apiCall(recSession, 'POST', `/api/patients/${pidA}/appointment`, { next_appointment: orig })).status : 'n/a';
  rec('U6', 'Receptionist reschedules an appointment on screen: a past date is refused by the server and the reason is shown in the open dialog (nothing stored); a valid date is stored by the server, shown in the list, and audited',
    'past date: dialog stays open with "Appointment not saved"; stored time unchanged; valid date: dialog closes, list shows the new time, server stores it, audit has ALLOW and DENY-free events for the change',
    `past: message "${(pastShown || '').slice(0, 60)}", dialog open ${stillOpen}, stored unchanged ${afterPast === orig}; valid: closed ${closed}, row "${(rowText || '').slice(0, 60)}", stored "${stored}" (wanted "${wantStored}"); audit allowed events ${audit.filter((e) => e.decision === 'ALLOW').length}; restore ${restoreOk}`,
    /Appointment not saved/.test(pastShown || '') && stillOpen && afterPast === orig && closed && stored === wantStored && audit.filter((e) => e.decision === 'ALLOW').length >= 1);
  await signOut(pg);
  await send('Target.closeTarget', { targetId: pg.targetId });

  // ---------------------------------------------------------------- U7: export shows identifiers masked until the doctor asks to see them
  pg = await openPage(1280, 900, false);
  if (!(await signIn(pg, 'dr_alice', 'browser'))) throw new Error('doctor sign-in (U8) failed');
  await pg.js("location.hash = '#/patients/101'"); await settle(pg, 2000);
  await click(pg, '#export-btn');
  await answerPin(pg, 'dr_alice', 5000);
  const docShown = await until(() => pg.js("!!document.querySelector('dialog.modal .doc')"), 10000);
  const masked0 = await pg.js("[...document.querySelectorAll('dialog.modal .masked')].map((e) => e.textContent)");
  await click(pg, 'dialog.modal .link-btn'); await sleep(300);
  const masked1 = await pg.js("[...document.querySelectorAll('dialog.modal .masked')].map((e) => e.textContent)");
  const toggled = await pg.js("document.querySelector('dialog.modal .link-btn').getAttribute('aria-pressed')");
  await click(pg, 'dialog.modal .link-btn'); await sleep(300);
  const masked2 = await pg.js("[...document.querySelectorAll('dialog.modal .masked')].map((e) => e.textContent)");
  const docNote = await text(pg, 'dialog.modal .doc-note');
  rec('U7', 'Export of an assigned patient (step-up PIN): the document shows the identifiers masked by default, reveals the first one on request and masks it again; it says the identifiers are synthetic',
    'two masked values with bullet characters; after "Show" the first one has none; after "Hide" masked again; synthetic note',
    `document shown: ${!!docShown}; masked at first: ${masked0.map((m) => /•/.test(m)).join(',')}; after Show: ${masked1.map((m) => /•/.test(m)).join(',')} (aria-pressed ${toggled}); after Hide: ${masked2.map((m) => /•/.test(m)).join(',')}; note: "${(docNote || '').slice(0, 50)}"`,
    !!docShown && masked0.length === 2 && masked0.every((m) => /•/.test(m)) && masked1.length === 2 && !/•/.test(masked1[0]) && /•/.test(masked1[1]) && toggled === 'true' && masked2.every((m) => /•/.test(m)) && /synthetic/i.test(docNote || ''));
  await pg.js("document.querySelectorAll('dialog.modal[open]').forEach((d) => d.close())");
  await signOut(pg);
  await send('Target.closeTarget', { targetId: pg.targetId });

  // ---------------------------------------------------------------- U8/U9: administrator screens: filters, device provenance, policy change with PIN
  pg = await openPage(1280, 900, false);
  if (!(await signIn(pg, 'sec_dan', 'browser'))) throw new Error('administrator sign-in (U9) failed');
  const polStart = nowTs();
  await pg.js("location.hash = '#/sessions'"); await settle(pg, 2200);
  await pg.js("document.querySelector('input[name=\"sess-filter\"][value=\"REVOKED\"]').click()"); await sleep(600);
  const revokedRows = await pg.js("[...document.querySelectorAll('#session-table tbody tr')].map((r) => r.innerText.replace(/\\s+/g, ' '))");
  await pg.js("location.hash = '#/decisions'"); await settle(pg, 2200);
  await pg.js("document.querySelector('input[name=\"dec-filter\"][value=\"DENY\"]').click()"); await sleep(2500);
  const deniedRows = await pg.js("[...document.querySelectorAll('#decisions-table tbody tr')].map((r) => r.innerText.replace(/\\s+/g, ' '))");
  await pg.js("location.hash = '#/audit'"); await settle(pg, 2200);
  await pg.js("(() => { const s = document.querySelector('#audit-type'); s.value = 'LOGOUT'; s.dispatchEvent(new Event('change')); })()"); await sleep(2500);
  const logoutRows = await pg.js("[...document.querySelectorAll('#audit-table tbody tr')].map((r) => r.innerText.replace(/\\s+/g, ' '))");
  await pg.js("location.hash = '#/devices'"); await settle(pg, 2500);
  const devBadges = await pg.js("[...new Set([...document.querySelectorAll('#device-grid .badge')].map((b) => b.textContent.trim()))]");
  const devNames = await pg.js("[...document.querySelectorAll('#device-grid .panel-head h2')].map((h) => h.textContent.trim())");
  rec('U8', 'Administrator screens: the Sessions filter shows only revoked sessions, the decisions filter only denials, the audit filter only sign-outs; the device screen shows measured, self-reported and simulated signals and names devices without a computer name',
    'revoked rows >= 1 and all "Revoked"; denied rows >= 1 and all "Denied"; sign-out rows >= 1 and all "Sign-out"; badges Measured + Self-reported + Simulated; device names "Registered laptop NNNNNN" / "Desktop|Phone|Tablet browser NNNNNN"',
    `revoked rows ${revokedRows.length} (all revoked: ${revokedRows.every((r) => /Revoked/.test(r))}); denied rows ${deniedRows.length} (all denied: ${deniedRows.every((r) => /Denied/.test(r))}); sign-out rows ${logoutRows.length} (all: ${logoutRows.every((r) => /Sign-out/.test(r))}); badges: ${devBadges.join('/')}; names: ${devNames.slice(0, 3).join(' | ')}`,
    revokedRows.length >= 1 && revokedRows.every((r) => /Revoked/.test(r)) && deniedRows.length >= 1 && deniedRows.every((r) => /Denied/.test(r)) && logoutRows.length >= 1 && logoutRows.every((r) => /Sign-out/.test(r))
      && ['Measured', 'Self-reported', 'Simulated'].every((b) => devBadges.includes(b)) && devNames.length >= 1 && devNames.every((n) => /^(Registered laptop|Desktop browser|Phone browser|Tablet browser|Browser) [0-9A-F]{6}$/.test(n)));
  await pg.js("location.hash = '#/policy'"); await settle(pg, 2200);
  await pg.js("document.querySelector('.policy-row[data-path=\"bands.allow_below\"] button').click()");
  await answerPin(pg, 'sec_dan', 5000);
  await sleep(1200);
  const polNote = await text(pg, '#policy-note');
  const polEvents = (await events_('limit=100&type=POLICY_CHANGE')).filter((e) => e.username === 'sec_dan' && e.ts >= polStart);
  rec('U9', 'Policy screen: applying a value asks for the step-up PIN, confirms "Policy updated" and the change appears in the audit log with the administrator\'s name',
    'PIN prompt answered; "Policy updated"; a POLICY_CHANGE event for sec_dan', `note: "${(polNote || '').slice(0, 60)}"; audit events: ${polEvents.length}`, /Policy updated/.test(polNote || '') && polEvents.length >= 1);
  await signOut(pg);
  await send('Target.closeTarget', { targetId: pg.targetId });
  await apiCall(admin, 'POST', '/ctl/logout');
  ws.close();
}

main().catch((e) => rec('U0', 'The UI scenarios ran to the end', 'no exception', e && e.stack || e, false)).finally(() => {
  try { chrome && chrome.kill(); } catch (e) { /* gone */ }
  setTimeout(() => { process.stdout.write('RESULT_JSON:' + JSON.stringify(results) + '\n'); process.exit(0); }, 800);
});
