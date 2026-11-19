// What each role ACTUALLY SEES: signs in as every demo role in headless desktop Chrome (throw-away profile), visits every screen of the navigation and the
// patient views, and records the rendered headings, buttons, inputs, table headers, labels and badges, plus every request the page made and the keys of
// every JSON response. Read-only with respect to the system: it only uses the portal like a user does (denials it provokes are scored by the server).
// Environment: ZT_TEST_CHROME, ZT_TEST_BASE (loopback edge), ZT_TEST_PROFILE, ZT_ROLE_CREDS (JSON {"username":"password",...}, never printed).
// Output: one line "RESULT_JSON:{...}" on stdout.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const env = process.env;
const base = env.ZT_TEST_BASE;
const creds = JSON.parse(env.ZT_ROLE_CREDS || '{}');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 15000, step = 150) { const end = Date.now() + ms; while (Date.now() < end) { try { const v = await fn(); if (v) return v; } catch (e) { /* retry */ } await sleep(step); } return null; }

let chrome = null;
process.on('exit', () => { try { chrome && chrome.kill(); } catch (e) { /* gone */ } });

const INV = (scopeExpr) => `(() => {
  const vis = (e) => !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length) && getComputedStyle(e).visibility !== 'hidden';
  const text = (e) => (e.innerText || e.textContent || '').replace(/\\s+/g, ' ').trim();
  const q = (sel, root) => [...(root || document).querySelectorAll(sel)].filter(vis);
  const scope = ${scopeExpr};
  return {
    headings: q('h1, h2, h3', scope).map(text),
    buttons: q('button', scope).map((b) => text(b) + (b.disabled ? ' [disabled]' : '')),
    inputs: q('input, select, textarea', scope).map((i) => (i.getAttribute('aria-label') || i.placeholder || i.id || i.type) + ' (' + i.type + (i.disabled ? ', disabled' : '') + ')'),
    tableHeaders: q('th', scope).map(text),
    kvLabels: q('dl.kv dt', scope).map(text),
    stats: q('.stat .l', scope).map(text),
    badges: q('.badge', scope).map(text),
    banners: q('.alert', scope).map(text),
    listItems: q('#patient-table tbody tr, #appointment-table tbody tr', scope).map(text),
    banner: q('#patient-banner', scope).map(text),
    sampleText: text(scope).slice(0, 900),
    fullText: text(scope).slice(0, 9000)
  };
})()`;
const INVENTORY = INV("document.querySelector('dialog.modal[open]') || document.getElementById('main') || document.getElementById('app')");
const DETAIL = INV("document.getElementById('detail')");

const flat = (o, prefix = '', out = new Set()) => {
  if (Array.isArray(o)) { if (o.length === 0) out.add(prefix + '[]'); for (const x of o) { if (x && typeof x === 'object') flat(x, prefix + '[]', out); else out.add(prefix + '[]'); } }
  else if (o && typeof o === 'object') { for (const [k, v] of Object.entries(o)) { const p = prefix ? prefix + '.' + k : k; if (v && typeof v === 'object') flat(v, p, out); else out.add(p); } }
  return out;
};

async function main() {
  const profile = env.ZT_TEST_PROFILE;
  fs.rmSync(profile, { recursive: true, force: true });
  fs.mkdirSync(profile, { recursive: true });
  chrome = spawn(env.ZT_TEST_CHROME, ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check',
    '--disable-extensions', '--disable-background-networking', '--disable-sync', '--mute-audio', '--window-size=1280,900', 'about:blank'], { stdio: 'ignore' });
  const portFile = path.join(profile, 'DevToolsActivePort');
  const ap = await until(() => fs.existsSync(portFile) && fs.readFileSync(portFile, 'utf8').split('\n').length >= 2 && fs.readFileSync(portFile, 'utf8'), 20000);
  if (!ap) throw new Error('Chrome did not start');
  const [port, wsPath] = ap.split('\n');
  const ws = new WebSocket(`ws://127.0.0.1:${port}${wsPath}`);
  await new Promise((res, rej) => { ws.addEventListener('open', res); ws.addEventListener('error', rej); });
  let nextId = 0; const pending = new Map(); const events = [];
  ws.addEventListener('message', (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); m.error ? p.rej(new Error(m.error.message)) : p.res(m.result); } else if (m.method) events.push(m);
  });
  const send = (method, params = {}, sessionId) => new Promise((res, rej) => { const id = ++nextId; pending.set(id, { res, rej }); ws.send(JSON.stringify({ id, method, params, sessionId })); });

  async function openPage() {
    const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
    const cmd = (m, p) => send(m, p, sessionId);
    for (const d of ['Page', 'Runtime', 'Network']) await cmd(d + '.enable');
    await cmd('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
    const js = async (expression) => {
      const r = await cmd('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
      if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception ? r.exceptionDetails.exception.description : r.exceptionDetails.text);
      return r.result.value;
    };
    const go = async (url) => { const mark = events.length; await cmd('Page.navigate', { url }); await until(() => events.slice(mark).some((e) => e.sessionId === sessionId && e.method === 'Page.loadEventFired'), 15000); };
    return { targetId, sessionId, cmd, js, go };
  }
  const click = (pg, sel, textMatch) => pg.js(`(() => { const els = [...document.querySelectorAll(${JSON.stringify(sel)})]; const e = ${textMatch ? `els.find((x) => (x.innerText || x.textContent || '').trim().startsWith(${JSON.stringify(textMatch)}))` : 'els[0]'}; if (!e) return false; e.click(); return true; })()`);
  const settle = async (pg, ms = 1400) => { await sleep(ms); await until(() => pg.js("!document.querySelector('.skeleton')"), 8000); };
  const closeDialogs = (pg) => pg.js("document.querySelectorAll('dialog.modal[open]').forEach((d) => d.close())");

  const result = { roles: {} };
  const order = ['dr_alice', 'nurse_bob', 'front_carol', 'sec_dan'];
  for (const user of order) {
    if (!creds[user]) continue;
    const pg = await openPage();
    const mark = events.length;
    await pg.go(base + '/');
    await until(() => pg.js("!!document.querySelector('form input[type=password]')"), 15000);
    const loginView = await pg.js(INVENTORY);
    await pg.js(`(() => { document.querySelector('#u').value = ${JSON.stringify(user)}; document.querySelector('#p').value = ${JSON.stringify(creds[user])}; document.querySelector('form').requestSubmit(); })()`);
    await until(() => pg.js("!!document.querySelector('.topbar')"), 15000);
    await sleep(1500);
    const role = { loginView, tabs: {}, details: {}, modals: {}, header: await pg.js("[...document.querySelectorAll('#user-name, #user-role, #chip-session, #chip-net, #chip-device, #chip-risk')].map((e) => (e.textContent || '').replace(/\\s+/g, ' ').trim())") };
    const views = await pg.js("[...document.querySelectorAll('.nav-link')].map((a) => a.getAttribute('data-view') + '|' + a.querySelector('span').textContent.trim())");
    for (const v of views) {
      const [id, label] = v.split('|');
      await click(pg, `.nav-link[data-view="${id}"]`);
      await settle(pg, 1800);
      role.tabs[label] = await pg.js(INVENTORY);
      if (id === 'patients') {
        // every patient the list offers (opened like a user does: click the row), plus a few ids the list does not offer (typed into the ID box;
        // the server must refuse these and the page must show why)
        const ids = await pg.js("[...document.querySelectorAll('#patient-table tbody tr[data-id]')].map((r) => r.getAttribute('data-id'))");
        for (const pid of ids) {
          await click(pg, `#patient-table tbody tr[data-id="${pid}"]`);
          await settle(pg, 1600);
          role.details['listed ' + pid] = await pg.js(DETAIL);
        }
        const probeIds = ['102', '103', '104', '105'].filter((x) => !ids.includes(x)).slice(0, 2).concat(user === 'front_carol' ? ['999'] : []);
        for (const pid of probeIds) {
          await pg.js(`(() => { document.querySelector('#lookup-id').value = ${JSON.stringify(pid)}; document.querySelector('#lookup-btn').click(); })()`);
          await settle(pg, 1600);
          role.details['unlisted ' + pid] = await pg.js(DETAIL);
          if (user === 'dr_alice' && pid === probeIds[0]) {
            const opened = await click(pg, '#emergency-btn');
            if (opened) { await sleep(600); role.modals['emergency access dialog'] = await pg.js(INVENTORY); await click(pg, 'dialog.modal button', 'Cancel'); await sleep(300); }
          }
        }
        await pg.js("location.hash = '#/patients'");
        await sleep(300);
      }
      if (id === 'appointments') {
        if (await click(pg, '#appointment-table tbody button')) { await sleep(600); role.modals['reschedule dialog'] = await pg.js(INVENTORY); await closeDialogs(pg); await sleep(300); }
      }
    }
    // requests the page made and the keys of every JSON response it got
    const reqs = new Map();
    for (const e of events.slice(mark)) {
      if (e.sessionId !== pg.sessionId) continue;
      if (e.method === 'Network.requestWillBeSent') reqs.set(e.params.requestId, { method: e.params.request.method, url: e.params.request.url });
      if (e.method === 'Network.responseReceived' && reqs.has(e.params.requestId)) { const r = reqs.get(e.params.requestId); r.status = e.params.response.status; r.mime = e.params.response.mimeType; }
    }
    const summary = new Map();
    for (const [rid, r] of reqs) {
      let u; try { u = new URL(r.url); } catch (e) { continue; }
      if (!/^\/(api|ctl|admin)\//.test(u.pathname)) continue;
      const p = u.pathname.replace(/\/patients\/\d+\//, '/patients/{id}/');
      let keys = [];
      try { const b = await pg.cmd('Network.getResponseBody', { requestId: rid }); keys = [...flat(JSON.parse(b.body))].sort(); } catch (e) { /* no body available */ }
      const k = `${r.method} ${p} -> ${r.status}`;
      if (!summary.has(k)) summary.set(k, { call: k, count: 0, keys: new Set() });
      const s = summary.get(k); s.count++; keys.forEach((x) => s.keys.add(x));
    }
    role.requests = [...summary.values()].map((s) => ({ call: s.call, count: s.count, keys: [...s.keys].sort() })).sort((a, b) => a.call.localeCompare(b.call));
    await click(pg, '#signout-btn');
    await sleep(800);
    await send('Target.closeTarget', { targetId: pg.targetId });
    result.roles[user] = role;
  }
  ws.close();
  return result;
}

main().then((r) => { process.stdout.write('RESULT_JSON:' + JSON.stringify(r) + '\n'); }).catch((e) => { process.stdout.write('RESULT_JSON:' + JSON.stringify({ error: String(e && e.stack || e) }) + '\n'); }).finally(() => { try { chrome && chrome.kill(); } catch (e) { /* gone */ } setTimeout(() => process.exit(0), 600); });
