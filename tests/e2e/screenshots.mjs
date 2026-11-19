// Screenshots of the real portal in headless desktop Chrome (throw-away profile): the sign-in screen and each role's screens at a desktop size and at a
// phone-sized viewport (360 x 740 CSS pixels, device pixel ratio 2, touch + mobile emulation). This is an EMULATED phone viewport in desktop Chrome:
// it shows the layout, it is NOT a test on a real phone.
// Environment: ZT_TEST_CHROME, ZT_TEST_BASE (loopback edge), ZT_TEST_PROFILE, ZT_ROLE_CREDS (JSON {"username":"password",...}, never printed),
//              ZT_SHOT_DIR (output folder), ZT_SHOT_SET ("core" = the deliverable set, "all" = every screen of every role).
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const env = process.env;
const base = env.ZT_TEST_BASE;
const creds = JSON.parse(env.ZT_ROLE_CREDS || '{}');
const pins = JSON.parse(env.ZT_ROLE_PINS || '{}');
const outDir = env.ZT_SHOT_DIR;
const set = env.ZT_SHOT_SET || 'core';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 15000, step = 150) { const end = Date.now() + ms; while (Date.now() < end) { try { const v = await fn(); if (v) return v; } catch (e) { /* retry */ } await sleep(step); } return null; }
let chrome = null;
process.on('exit', () => { try { chrome && chrome.kill(); } catch (e) { /* gone */ } });
const written = [];

const DESKTOP = { name: 'desktop', width: 1440, height: 900, dpr: 1, mobile: false, full: false };
const PHONE = { name: 'phone', width: 360, height: 740, dpr: 2, mobile: true, full: true };

async function main() {
  fs.mkdirSync(outDir, { recursive: true });
  const profile = env.ZT_TEST_PROFILE;
  fs.rmSync(profile, { recursive: true, force: true });
  fs.mkdirSync(profile, { recursive: true });
  chrome = spawn(env.ZT_TEST_CHROME, ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check',
    '--disable-extensions', '--disable-background-networking', '--disable-sync', '--mute-audio', '--hide-scrollbars', 'about:blank'], { stdio: 'ignore' });
  const portFile = path.join(profile, 'DevToolsActivePort');
  const ap = await until(() => fs.existsSync(portFile) && fs.readFileSync(portFile, 'utf8').split('\n').length >= 2 && fs.readFileSync(portFile, 'utf8'), 20000);
  if (!ap) throw new Error('Chrome did not start');
  const [port, wsPath] = ap.split('\n');
  const ws = new WebSocket(`ws://127.0.0.1:${port}${wsPath}`);
  await new Promise((res, rej) => { ws.addEventListener('open', res); ws.addEventListener('error', rej); });
  let nextId = 0; const pending = new Map(); const events = [];
  ws.addEventListener('message', (ev) => { const m = JSON.parse(ev.data); if (m.id && pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); m.error ? p.rej(new Error(m.error.message)) : p.res(m.result); } else if (m.method) events.push(m); });
  const send = (method, params = {}, sessionId) => new Promise((res, rej) => { const id = ++nextId; pending.set(id, { res, rej }); ws.send(JSON.stringify({ id, method, params, sessionId })); });

  async function openPage(vp) {
    const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
    const cmd = (m, p) => send(m, p, sessionId);
    for (const d of ['Page', 'Runtime']) await cmd(d + '.enable');
    await cmd('Emulation.setDeviceMetricsOverride', { width: vp.width, height: vp.height, deviceScaleFactor: vp.dpr, mobile: vp.mobile });
    if (vp.mobile) await cmd('Emulation.setTouchEmulationEnabled', { enabled: true, maxTouchPoints: 5 });
    const js = async (expression) => { const r = await cmd('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }); if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception ? r.exceptionDetails.exception.description : r.exceptionDetails.text); return r.result.value; };
    const go = async (url) => { const mark = events.length; await cmd('Page.navigate', { url }); await until(() => events.slice(mark).some((e) => e.sessionId === sessionId && e.method === 'Page.loadEventFired'), 15000); };
    const shot = async (name, o) => {
      await sleep(500);
      let params = { format: 'png' };
      if (vp.full || (o && o.full)) {
        const m = await cmd('Page.getLayoutMetrics');
        const w = Math.ceil(m.cssContentSize.width), hgt = Math.min(Math.ceil(m.cssContentSize.height), 2600);
        params = { format: 'png', captureBeyondViewport: true, clip: { x: 0, y: 0, width: w, height: hgt, scale: 1 } };
      }
      const r = await cmd('Page.captureScreenshot', params);
      const file = path.join(outDir, `${name}-${vp.name}.png`);
      fs.writeFileSync(file, Buffer.from(r.data, 'base64'));
      written.push(file);
    };
    return { targetId, sessionId, cmd, js, go, shot };
  }

  const click = (pg, sel, textMatch) => pg.js(`(() => { const els = [...document.querySelectorAll(${JSON.stringify(sel)})]; const e = ${textMatch ? `els.find((x) => (x.innerText || '').trim().startsWith(${JSON.stringify(textMatch)}))` : 'els[0]'}; if (!e) return false; e.click(); return true; })()`);
  const settle = async (pg, ms = 1200) => { await sleep(ms); await until(() => pg.js("!document.querySelector('.skeleton')"), 8000); };
  async function signIn(pg, user, evaluation) {
    await pg.go(base + '/' + (evaluation ? '?evaluation=1' : ''));
    await until(() => pg.js("!!document.querySelector('form input[type=password]')"), 15000);
    await pg.js(`(() => { document.querySelector('#u').value = ${JSON.stringify(user)}; document.querySelector('#p').value = ${JSON.stringify(creds[user])}; document.querySelector('form').requestSubmit(); })()`);
    const ok = await until(() => pg.js("!!document.querySelector('.topbar')"), 15000);
    if (!ok) throw new Error('sign-in failed for ' + user);
    await settle(pg, 1500);
  }
  const route = async (pg, hash, ms) => { await pg.js(`location.hash = ${JSON.stringify(hash)}`); await settle(pg, ms || 1500); };
  // answers a step-up PIN prompt when the server asks for one (the PIN comes from the environment and is never printed)
  const answerPin = async (pg, user) => {
    if (!(await until(() => pg.js("!!document.querySelector('#pin-input')"), 3000))) return false;
    await pg.js(`(() => { const i = document.querySelector('#pin-input'); i.value = ${JSON.stringify(pins[user] || '')}; i.closest('form').requestSubmit(); })()`);
    await sleep(1200);
    return true;
  };
  const signOut = async (pg) => { await pg.js("document.querySelector('#nav-toggle') && getComputedStyle(document.querySelector('#nav-toggle')).display !== 'none' && document.querySelector('#nav-toggle').click()"); await sleep(300); await click(pg, '#signout-btn'); await sleep(800); };

  for (const vp of [DESKTOP, PHONE]) {
    // sign-in screen
    let pg = await openPage(vp);
    await pg.go(base + '/');
    await until(() => pg.js("!!document.querySelector('form input[type=password]')"), 15000);
    await sleep(600);
    await pg.shot('login');
    await send('Target.closeTarget', { targetId: pg.targetId });

    // doctor
    if (creds.dr_alice) {
      pg = await openPage(vp);
      await signIn(pg, 'dr_alice');
      if (vp.name === 'desktop') { await route(pg, '#/patients/101', 2000); await pg.shot('doctor-dashboard'); }
      else { await pg.shot('doctor-dashboard'); await route(pg, '#/patients/101', 2000); await pg.shot('doctor-patient-chart'); }
      // emergency access: an unassigned patient, then a justified, time-limited request
      await route(pg, '#/patients/103', 1500);
      if (set === 'all' || vp.name) await pg.shot('doctor-access-restricted');
      if (await click(pg, '#emergency-btn')) {
        await sleep(600);
        await pg.shot('doctor-emergency-dialog');
        await pg.js(`(() => { const t = document.querySelector('#bg-justification'); t.value = 'Unresponsive patient brought to the emergency department; treating team needs the record now.'; t.dispatchEvent(new Event('input')); document.querySelector('#bg-confirm').click(); document.querySelector('dialog.modal form').requestSubmit(); })()`);
        await answerPin(pg, 'dr_alice');
        await settle(pg, 2500);
        await pg.shot('doctor-emergency-access');
      }
      // the compact account menu (who is signed in, when the session ends, sign out): the only session detail in a clinical workspace
      await route(pg, '#/patients/101', 1500);
      if (await click(pg, '#account-btn')) { await until(() => pg.js("!!document.querySelector('dialog[open]')"), 6000); await sleep(500); await pg.shot('doctor-account-menu'); await pg.js("document.querySelector('dialog.modal[open]') && document.querySelector('dialog.modal[open]').close()"); await sleep(300); }
      await signOut(pg);
      await send('Target.closeTarget', { targetId: pg.targetId });

      // EVALUATION MODE (page opened with ?evaluation=1, evaluation tools enabled by the administrator): the user's own session, device and network
      // evidence and the simulation controls, each simulated change followed by the server's real decision. Not part of the normal workspace.
      pg = await openPage(vp);
      await signIn(pg, 'dr_alice', true);
      await route(pg, '#/session', 1500);
      await pg.shot('evaluation-doctor-session');
      await route(pg, '#/demo', 1200);
      if (await pg.js("(() => { const s = document.querySelector('#sim-screen_lock'); if (!s || s.disabled) return false; s.click(); document.querySelector('#apply-posture').click(); return true; })()")) {
        await until(() => pg.js("!!document.querySelector('#posture-result .result-card')"), 10000);
        await sleep(500);
        await pg.shot('evaluation-doctor-demo-posture-change', { full: true });
        await click(pg, '#reset-sim');
        await until(() => pg.js("!!document.querySelector('#posture-result .result-card.ok')"), 10000);
        await sleep(400);
        await pg.js("(() => { const s = document.querySelector('#sim-network'); s.value = 'other'; s.dispatchEvent(new Event('change')); document.querySelector('#apply-network').click(); })()");
        await until(() => pg.js("!!document.querySelector('#network-result .result-card')"), 10000);
        await sleep(500);
        await pg.shot('evaluation-doctor-demo-network-change', { full: true });
        await pg.js("(() => { const s = document.querySelector('#sim-network'); s.value = 'reset'; s.dispatchEvent(new Event('change')); document.querySelector('#apply-network').click(); })()");
        await sleep(1500);
      }
      await pg.js('window.scrollTo(0, 0)');
      await pg.shot('evaluation-doctor-demo-tools');
      await signOut(pg);
      await send('Target.closeTarget', { targetId: pg.targetId });
    }

    // nurse
    if (creds.nurse_bob) {
      pg = await openPage(vp);
      await signIn(pg, 'nurse_bob');
      if (vp.name === 'desktop') { await route(pg, '#/patients/101', 2000); await pg.shot('nurse-dashboard'); }
      else { await pg.shot('nurse-dashboard'); await route(pg, '#/patients/101', 2000); await pg.shot('nurse-patient-chart'); }
      await route(pg, '#/patients/102', 1500);
      await pg.shot('nurse-other-ward-refused');
      await signOut(pg);
      await send('Target.closeTarget', { targetId: pg.targetId });
    }

    // receptionist
    if (creds.front_carol) {
      pg = await openPage(vp);
      await signIn(pg, 'front_carol');
      if (vp.name === 'desktop') { await route(pg, '#/patients/101', 2000); await pg.shot('receptionist-dashboard'); }
      else { await pg.shot('receptionist-dashboard'); await route(pg, '#/patients/101', 2000); await pg.shot('receptionist-patient'); }
      await route(pg, '#/appointments', 1500);
      await pg.shot('receptionist-appointments');
      if (await click(pg, '#appointment-table tbody button')) { await sleep(600); await pg.shot('receptionist-reschedule-dialog'); await pg.js("document.querySelector('dialog.modal') && document.querySelector('dialog.modal').close()"); }
      await signOut(pg);
      await send('Target.closeTarget', { targetId: pg.targetId });
    }

    // security administrator
    if (creds.sec_dan) {
      pg = await openPage(vp);
      await signIn(pg, 'sec_dan');
      await settle(pg, 2500);
      await pg.shot('admin-overview');
      if (set === 'all' || vp.name === 'desktop') {
        for (const [r, n] of [['#/sessions', 'admin-sessions'], ['#/devices', 'admin-devices'], ['#/decisions', 'admin-decisions'], ['#/audit', 'admin-audit'], ['#/users', 'admin-users'], ['#/policy', 'admin-policy'], ['#/session', 'admin-session']]) { await route(pg, r, 2200); await pg.shot(n); }
      }
      await signOut(pg);
      await send('Target.closeTarget', { targetId: pg.targetId });
    }
  }
  ws.close();
  return written;
}

main().then((w) => { process.stdout.write('RESULT_JSON:' + JSON.stringify({ files: w }) + '\n'); }).catch((e) => { process.stdout.write('RESULT_JSON:' + JSON.stringify({ error: String(e && e.stack || e), files: written }) + '\n'); }).finally(() => { try { chrome && chrome.kill(); } catch (e) { /* gone */ } setTimeout(() => process.exit(0), 600); });
