// The public sign-in screen and the four role sign-ins as a user sees them, in headless desktop Chrome with a throw-away profile.
// What it proves (rows L1-L9): nothing about accounts, roles or the computer on the public screen; the two device choices, labelled as
// agreed, with an honest posture disclosure; a connection status that never claims HTTPS for an HTTP page (checked on a real HTTP page AND a
// real HTTPS page); all four roles can sign in with both device choices and sign out; a failed sign-in shows only a generic message.
// HTTPS: the edge certificate is trusted for THIS Chrome process only, by its public-key pin (--ignore-certificate-errors-spki-list);
// nothing is installed anywhere and no Windows setting is touched.
// Environment: ZT_TEST_CHROME, ZT_TEST_HTTP, ZT_TEST_HTTPS, ZT_EDGE_CERT, ZT_TEST_PROFILE, ZT_ROLE_CREDS (JSON {"user":"password"}), ZT_COMPUTERNAME.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const env = process.env;
const creds = JSON.parse(env.ZT_ROLE_CREDS || '{}');
const results = [];
const rec = (id, title, expected, actual, ok) => { results.push({ id, title, expected, actual: String(actual), ok: ok === true }); console.error(`${ok === true ? 'PASS' : 'FAIL'} ${id} ${title}${ok === true ? '' : ' -> ' + actual}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 15000, step = 150) { const end = Date.now() + ms; while (Date.now() < end) { try { const v = await fn(); if (v) return v; } catch (e) { /* retry */ } await sleep(step); } return null; }
let chrome = null;
process.on('exit', () => { try { chrome && chrome.kill(); } catch (e) { /* gone */ } });

const ROLES = [
  ['dr_alice', 'Doctor', ['My patients']],
  ['nurse_bob', 'Nurse', ['Ward patients']],
  ['front_carol', 'Receptionist', ['Patient registry', 'Appointments']],
  ['sec_dan', 'Security administrator', ['Overview', 'Sessions', 'Devices & posture', 'Access decisions', 'Audit log', 'Users & access', 'Policy', 'My session']]
];

// facts about the sign-in screen, collected inside the page (works for the old and the new markup)
const LOGIN_FACTS = `(() => {
  const vis = (e) => !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length);
  const radios = [...document.querySelectorAll('input[type=radio][name=mode]')].map((r) => ({ value: r.value, checked: r.checked, disabled: r.disabled, label: ((r.closest('label') || {}).innerText || '').replace(/\\s+/g, ' ').trim() }));
  const conn = document.querySelector('.conn') || [...document.querySelectorAll('.login > p')].pop() || null;
  const hint = document.getElementById('device-hint');
  const group = document.querySelector('[role=radiogroup]');
  return { body: document.body.innerText, radios, connText: conn ? conn.innerText.replace(/\\s+/g, ' ').trim() : '', connClass: conn ? conn.className : '', hintText: hint ? hint.innerText.trim() : '',
           groupName: group ? (group.getAttribute('aria-label') || group.getAttribute('aria-labelledby') || '') : '', protocol: location.protocol, visibleRadios: [...document.querySelectorAll('input[type=radio][name=mode]')].filter((r) => vis(r.closest('label') || r)).length };
})()`;

async function main() {
  const profile = env.ZT_TEST_PROFILE;
  fs.rmSync(profile, { recursive: true, force: true });
  fs.mkdirSync(profile, { recursive: true });
  const cert = new crypto.X509Certificate(fs.readFileSync(env.ZT_EDGE_CERT));
  const spki = crypto.createHash('sha256').update(cert.publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
  chrome = spawn(env.ZT_TEST_CHROME, ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check', '--disable-extensions',
    '--disable-background-networking', '--disable-sync', '--mute-audio', '--window-size=420,900', `--ignore-certificate-errors-spki-list=${spki}`, 'about:blank'], { stdio: 'ignore' });
  const portFile = path.join(profile, 'DevToolsActivePort');
  const ap = await until(() => fs.existsSync(portFile) && fs.readFileSync(portFile, 'utf8').split('\n').length >= 2 && fs.readFileSync(portFile, 'utf8'), 20000);
  if (!ap) throw new Error('Chrome did not start');
  const [port, wsPath] = ap.split('\n');
  const ws = new WebSocket(`ws://127.0.0.1:${port}${wsPath}`);
  await new Promise((res, rej) => { ws.addEventListener('open', res); ws.addEventListener('error', rej); });
  let nextId = 0; const pending = new Map(); const events = [];
  ws.addEventListener('message', (ev) => { const m = JSON.parse(ev.data); if (m.id && pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); m.error ? p.rej(new Error(m.error.message)) : p.res(m.result); } else if (m.method) events.push(m); });
  const send = (method, params = {}, sessionId) => new Promise((res, rej) => { const id = ++nextId; pending.set(id, { res, rej }); ws.send(JSON.stringify({ id, method, params, sessionId })); });
  async function openPage() {
    const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
    const cmd = (m, p) => send(m, p, sessionId);
    for (const d of ['Page', 'Runtime']) await cmd(d + '.enable');
    const js = async (expression) => { const r = await cmd('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }); if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception ? r.exceptionDetails.exception.description : r.exceptionDetails.text); return r.result.value; };
    const go = async (url) => { const mark = events.length; await cmd('Page.navigate', { url }); await until(() => events.slice(mark).some((e) => e.sessionId === sessionId && e.method === 'Page.loadEventFired'), 15000); };
    return { targetId, sessionId, cmd, js, go };
  }
  const formReady = (pg) => until(() => pg.js("!!document.querySelector('form input[type=password]')"), 15000);
  const lower = (s) => String(s).toLowerCase();
  const computer = lower(env.ZT_COMPUTERNAME || '');

  // ---------------------------------------------------------------- the public screen over plain HTTP
  const pg = await openPage();
  await pg.go(env.ZT_TEST_HTTP + '/');
  if (!(await formReady(pg))) throw new Error('the sign-in form did not appear over HTTP');
  await sleep(500);
  const f = await pg.js(LOGIN_FACTS);
  const body = lower(f.body);
  const forbidden = ['demo accounts', 'dr_alice', 'nurse_bob', 'front_carol', 'sec_dan', 'receptionist', 'security administrator', 'doctor', 'nurse', 'presenter', 'password is', 'passwords are'];
  if (computer) forbidden.push(computer);
  const found = forbidden.filter((w) => body.includes(w));
  rec('L1', 'The public sign-in screen shows no demo accounts, user names, role descriptions or computer name', 'none of the listed words appear', `found: [${found.join(', ')}]`, found.length === 0);

  const labels = f.radios.map((r) => r.label);
  rec('L2', 'Device selection is kept, compact and labelled "This browser" and "Registered laptop" (browser preselected, laptop choice available while the agent reports); a desktop browser is never called a phone', 'two radio choices with exactly those labels, an accessible group name, browser checked, laptop enabled, no "phone" on the screen',
    `labels: [${labels.join(' | ')}]; checked: ${f.radios.filter((r) => r.checked).map((r) => r.value).join(',')}; laptop disabled: ${(f.radios.find((r) => r.value === 'laptop') || {}).disabled}; group name: "${f.groupName}"; mentions a phone: ${/phone/.test(body)}`,
    labels.length === 2 && labels[0] === 'This browser' && labels[1] === 'Registered laptop' && f.radios[0].checked && f.radios[1].disabled === false && f.groupName !== '' && !/phone/.test(body));

  const phoneHint = lower(f.hintText || f.radios[0].label);          // new markup: one hint line; old markup: the description inside the option
  await pg.js("document.querySelector('input[type=radio][name=mode][value=laptop]').click()");
  await sleep(300);
  const f2 = await pg.js(LOGIN_FACTS);
  const laptopHint = lower(f2.hintText || f2.radios[1].label);
  const phoneOk = /self-reported/.test(phoneHint) && /simulated/.test(phoneHint);
  const laptopOk = /measured/.test(laptopHint) && /signed/.test(laptopHint) && /firewall/.test(laptopHint) && /antivirus/.test(laptopHint);
  const phoneNotMeasured = !/measured by the signed/.test(phoneHint.replace(/a browser cannot read them/, ''));
  rec('L3', 'Posture disclosure stays honest: browser = self-reported and simulated; registered laptop = firewall and antivirus measured by the signed agent', 'browser hint says self-reported and simulated (not measured); laptop hint says measured, signed agent, firewall, antivirus',
    `phone hint ok: ${phoneOk && phoneNotMeasured}; laptop hint ok: ${laptopOk}; laptop checked after click: ${f2.radios.find((r) => r.value === 'laptop').checked}`, phoneOk && phoneNotMeasured && laptopOk && f2.radios.find((r) => r.value === 'laptop').checked);

  const httpOk = f.protocol === 'http:' && !/^secure connection \(https\)/i.test(f.connText) && /not encrypted/i.test(f.connText) && !/127\.0\.0\.1|localhost|:\d{4}/.test(f.connText);
  rec('L4', 'Connection status on a page served over HTTP never claims HTTPS and shows no host or port', 'protocol http:, text says not encrypted, no "Secure connection (HTTPS)", no 127.0.0.1 or port', `protocol ${f.protocol}; status text: "${f.connText}"`, httpOk);

  // ---------------------------------------------------------------- the same screen over real HTTPS (key pinned for this browser process only)
  const pgs = await openPage();
  await pgs.go(env.ZT_TEST_HTTPS + '/');
  const httpsForm = await formReady(pgs);
  const hf = httpsForm ? await pgs.js(LOGIN_FACTS) : null;
  const httpsOk = !!hf && hf.protocol === 'https:' && /^secure connection \(https\)$/i.test(hf.connText) && !/127\.0\.0\.1|localhost|:\d{4}/.test(hf.connText);
  rec('L5', 'Connection status on a page served over HTTPS says "Secure connection (HTTPS)" without host or port', 'protocol https:, exactly that text', hf ? `protocol ${hf.protocol}; status text: "${hf.connText}"` : 'the HTTPS page did not load', httpsOk);

  // ---------------------------------------------------------------- the four role sign-ins, with both device choices
  async function signIn(page, base, user, mode, evaluation) {
    await page.go(base + '/' + (evaluation ? '?evaluation=1' : ''));
    if (!(await formReady(page))) return { ok: false, why: 'no form' };
    if (mode === 'laptop') await page.js("document.querySelector('input[type=radio][name=mode][value=laptop]').click()");
    await page.js(`(() => { document.querySelector('#u').value = ${JSON.stringify(user)}; document.querySelector('#p').value = ${JSON.stringify(creds[user])}; document.querySelector('form').requestSubmit(); })()`);
    const shell = await until(() => page.js("!!document.querySelector('.topbar')"), 15000);
    if (!shell) { const msg = await page.js("(document.querySelector('#login-msg') || {}).innerText || ''"); return { ok: false, why: 'no shell; message: ' + msg }; }
    await sleep(900);
    // textContent, not innerText: at this window width the navigation is a closed drawer and some chips are hidden by the responsive layout
    const chips = await page.js("[...document.querySelectorAll('#user-role, #chip-device')].map((e) => e.textContent.trim())");
    const tabs = await page.js("[...document.querySelectorAll('.nav-link')].map((e) => e.querySelector('span').textContent.trim())");
    return { ok: true, chips, tabs };
  }
  async function signOut(page) {
    await page.js("document.getElementById('signout-btn').click()");
    const back = await formReady(page);
    const notice = await page.js("(document.querySelector('.alert.info') || {}).innerText || ''");
    const emptied = back ? await page.js("document.querySelector('#u').value === '' && document.querySelector('#p').value === ''") : false;
    return { back: !!back, notice, emptied };
  }
  for (const mode of ['browser', 'laptop']) {
    const problems = [];
    const wantDevice = mode === 'laptop' ? 'Registered laptop' : 'Desktop browser';
    for (const [user, roleLabel, tabs] of ROLES) {
      const w = await openPage();
      const r = await signIn(w, env.ZT_TEST_HTTP, user, mode);
      if (!r.ok) { problems.push(`${user}: ${r.why}`); await send('Target.closeTarget', { targetId: w.targetId }); continue; }
      const chipText = r.chips.join(' | ');
      if (!chipText.includes(roleLabel)) problems.push(`${user}: role "${chipText}"`);
      if (JSON.stringify(r.tabs) !== JSON.stringify(tabs)) problems.push(`${user}: navigation [${r.tabs.join(', ')}]`);
      if (user !== 'sec_dan' && (await w.js("document.querySelectorAll('.status-chips > *').length"))) problems.push(`${user}: status chips are shown in the normal workspace`);
      if (user !== 'sec_dan' && computer) { const shown = lower(await w.js("document.getElementById('app').innerText")); if (shown.includes(computer)) problems.push(`${user}: the computer name is visible on screen`); }
      // which device did the sign-in choice bind the session to? The administrator's own-session screen says so; a clinical user sees it only in evaluation mode
      let devW = w;
      if (user !== 'sec_dan') { const o0 = await signOut(w); if (!o0.back) problems.push(`${user}: sign-out before the device check`); await send('Target.closeTarget', { targetId: w.targetId }); devW = await openPage(); const r2 = await signIn(devW, env.ZT_TEST_HTTP, user, mode, true); if (!r2.ok) { problems.push(`${user}: evaluation sign-in ${r2.why}`); await send('Target.closeTarget', { targetId: devW.targetId }); continue; } }
      await devW.js("location.hash = '#/session'"); await sleep(1500);
      const devLabel = await until(() => devW.js("(document.querySelector('#panel-device .status-line strong') || {}).textContent || ''"), 8000);
      if (devLabel !== wantDevice) problems.push(`${user}: the session is bound to "${devLabel}" (expected "${wantDevice}")`);
      const o = await signOut(devW);
      if (!o.back || !/signed out/i.test(o.notice) || !o.emptied) problems.push(`${user}: sign-out screen (back ${o.back}, notice "${o.notice}", fields emptied ${o.emptied})`);
      await send('Target.closeTarget', { targetId: devW.targetId });
    }
    rec(mode === 'browser' ? 'L6' : 'L7', mode === 'browser' ? 'All four roles sign in with "This browser", get their own navigation and role (no status chips in a clinical workspace), the session is bound to the desktop browser (own-session screen), and they can sign out' : 'All four roles sign in with "Registered laptop" (signed agent), get their own navigation and role, the session is bound to the registered laptop, they can sign out, and the computer name appears on no clinical screen',
      'doctor, nurse, receptionist, security administrator: shell with the right role and navigation, the right device, no chips for clinical roles; sign-out returns to an empty sign-in form', `problems: [${problems.join('; ')}]`, problems.length === 0);
  }

  // ---------------------------------------------------------------- a failed sign-in shows only a generic message
  const bad = await openPage();
  await bad.go(env.ZT_TEST_HTTP + '/');
  await formReady(bad);
  await bad.js(`(() => { document.querySelector('#u').value = 'dr_alice'; document.querySelector('#p').value = 'not-the-password-0'; document.querySelector('form').requestSubmit(); })()`);
  const err = await until(() => bad.js("(document.querySelector('#login-msg .alert') || {}).innerText || ''"), 10000);
  const stillLogin = await bad.js("!!document.querySelector('form input[type=password]') && !document.querySelector('.topbar')");
  const emptyPw = await bad.js("document.querySelector('#p').value === ''");
  rec('L8', 'A failed sign-in shows one generic message (no hint which part was wrong), clears the password and leaves the sign-in screen in place', 'banner "Invalid username or password.", still on the sign-in screen, password empty', `message: "${err}"; still on sign-in: ${stillLogin}; password cleared: ${emptyPw}`, /^Invalid username or password\.?$/i.test(err || '') && stillLogin && emptyPw);

  // ---------------------------------------------------------------- one role over HTTPS end to end
  const hs = await openPage();
  const hr = await signIn(hs, env.ZT_TEST_HTTPS, 'dr_alice', 'browser');
  const hpat = hr.ok ? await until(() => hs.js("document.querySelectorAll('#patient-table tbody tr[data-id]').length || null"), 15000) : null;
  rec('L9', 'Signing in over the HTTPS edge works end to end with the new screen (doctor sees the two assigned patients)', 'shell with the Doctor role and 2 listed patients', hr.ok ? `chips: ${hr.chips.join(' | ')}; patients listed: ${hpat}` : hr.why, hr.ok && hr.chips.join(' | ').includes('Doctor') && hpat === 2);
  ws.close();
}

main().catch((e) => rec('L0', 'The sign-in screen check ran to the end', 'no exception', e && e.stack || e, false)).finally(() => {
  try { chrome && chrome.kill(); } catch (e) { /* gone */ }
  setTimeout(() => { process.stdout.write('RESULT_JSON:' + JSON.stringify(results) + '\n'); process.exit(0); }, 800);
});
