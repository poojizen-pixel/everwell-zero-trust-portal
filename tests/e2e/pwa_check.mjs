// Browser-level checks of the installable web app, run in the installed desktop Chrome (headless, throw-away profile) over the DevTools protocol.
// No dependencies: only Node built-ins. It starts its OWN throw-away edge on separate ports (so it can stop it to test the offline page) and
// talks to the same PEP/PDP of the disposable run. Nothing here touches a Windows setting or the user's browser profile.
// Environment (set by tests\e2e\run_e2e.ps1 -Groups W): ZT_TEST_CHROME, ZT_TEST_JAVA, ZT_TEST_EDGE_CP, ZT_TEST_BASE, ZT_TEST_PROFILE,
//   ZT_TEST_USER, ZT_TEST_PASS, ZT_TEST_PATIENT_DENIED, and the ZT_EDGE_* variables the edge itself reads.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const env = process.env;
const base = env.ZT_TEST_BASE;
const results = [];
const rec = (id, title, expected, actual, ok) => { results.push({ id, title, expected, actual: String(actual), ok: ok === true }); console.error(`${ok === true ? 'PASS' : 'FAIL'} ${id} ${title}${ok === true ? '' : ' -> ' + actual}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 15000, step = 150) { const end = Date.now() + ms; while (Date.now() < end) { try { const v = await fn(); if (v) return v; } catch (e) { /* retry */ } await sleep(step); } return null; }

let chrome = null, edge = null;
function cleanup() { try { chrome && chrome.kill(); } catch (e) { /* already gone */ } try { edge && edge.kill(); } catch (e) { /* already gone */ } }
process.on('exit', cleanup);

// remembers the bearer token the page sends, so the test can look for it in storage and replay it afterwards
const RECORDER = "window.__tok=[];(()=>{const f=window.fetch;window.fetch=function(u,o){try{const a=o&&o.headers&&o.headers.Authorization;if(a)window.__tok.push(a)}catch(e){}return f.apply(this,arguments)}})();";

async function main() {
  // --- throw-away edge on its own ports
  edge = spawn(env.ZT_TEST_JAVA, ['-cp', env.ZT_TEST_EDGE_CP, 'edge.Main'], { stdio: 'ignore', env });
  const up = await until(async () => (await fetch(base + '/healthz')).ok, 20000);
  if (!up) { rec('W0', 'The test edge starts', 'healthz answers', 'edge did not start', false); return; }

  // --- headless Chrome with a throw-away profile
  const profile = env.ZT_TEST_PROFILE;
  fs.rmSync(profile, { recursive: true, force: true });
  fs.mkdirSync(profile, { recursive: true });
  chrome = spawn(env.ZT_TEST_CHROME, ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check',
    '--disable-extensions', '--disable-background-networking', '--disable-sync', '--mute-audio', 'about:blank'], { stdio: 'ignore' });
  const portFile = path.join(profile, 'DevToolsActivePort');
  const ap = await until(() => fs.existsSync(portFile) && fs.readFileSync(portFile, 'utf8').split('\n').length >= 2 && fs.readFileSync(portFile, 'utf8'), 20000);
  if (!ap) { rec('W0', 'Chrome starts headless', 'DevTools port file appears', 'Chrome did not start', false); return; }
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
    for (const d of ['Page', 'Runtime', 'Log', 'Network']) await cmd(d + '.enable');
    await cmd('Page.addScriptToEvaluateOnNewDocument', { source: RECORDER });
    const js = async (expression) => {
      const r = await cmd('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
      if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception ? r.exceptionDetails.exception.description : r.exceptionDetails.text);
      return r.result.value;
    };
    const go = async (url) => { const mark = events.length; await cmd('Page.navigate', { url }); await until(() => events.slice(mark).some((e) => e.sessionId === sessionId && e.method === 'Page.loadEventFired'), 15000); };
    return { targetId, sessionId, cmd, js, go };
  }

  // --- 1. load, service worker, control
  let pg = await openPage();
  await pg.go(base + '/');
  const login = await until(() => pg.js("!!document.querySelector('form input[type=password]')"), 15000);
  rec('W1', 'The portal shell loads in Chrome and shows the sign-in form', 'sign-in form present', login ? 'present' : 'missing', !!login);
  const swState = await until(() => pg.js("navigator.serviceWorker.getRegistration().then(r => r && r.active ? r.active.state + ' scope=' + r.scope : null)"), 20000);
  rec('W2', 'The service worker registers and becomes active (scope "/")', 'activated, scope ' + base + '/', swState, !!swState && swState.startsWith('activated') && swState.endsWith('scope=' + base + '/'));
  await pg.go(base + '/');
  const controlled = await until(() => pg.js('!!navigator.serviceWorker.controller'), 10000);
  rec('W3', 'After a reload the page is controlled by the service worker', 'controller present', controlled ? 'present' : 'missing', !!controlled);

  // --- 2. installability as judged by Chrome itself
  const inst = await pg.cmd('Page.getInstallabilityErrors');
  const mani = await pg.cmd('Page.getAppManifest');
  rec('W4', "Chrome's own installability check reports no problems and the manifest has no parse errors", 'installabilityErrors [] and manifest errors []',
    `installabilityErrors=${JSON.stringify(inst.installabilityErrors.map((e) => e.errorId))}; manifestErrors=${JSON.stringify((mani.errors || []).map((e) => e.message))}`,
    inst.installabilityErrors.length === 0 && (mani.errors || []).length === 0);

  let manifestData = {};
  try { manifestData = JSON.parse(mani.data || '{}'); } catch (e) { manifestData = {}; }
  rec('W14', "Chrome's own parse of the manifest carries the Everwell install name, the home-screen label and the three icons", 'name "Everwell Health Portal", short_name "Everwell" (at most 12 characters), 3 icons, theme colour #0b2545',
    `name "${manifestData.name}"; short_name "${manifestData.short_name}"; icons ${(manifestData.icons || []).length}; theme ${manifestData.theme_color}`,
    manifestData.name === 'Everwell Health Portal' && manifestData.short_name === 'Everwell' && String(manifestData.short_name).length <= 12 && (manifestData.icons || []).length === 3 && String(manifestData.theme_color).toLowerCase() === '#0b2545');

  // --- 3. a real session in the browser: sign in, assigned patient, unassigned patient
  await pg.js(`(() => { document.querySelector('#u').value = ${JSON.stringify(env.ZT_TEST_USER)}; document.querySelector('#p').value = ${JSON.stringify(env.ZT_TEST_PASS)}; document.querySelector('form').requestSubmit(); })()`);
  const listCount = await until(() => pg.js("document.querySelectorAll('#patient-table tbody tr[data-id]').length || null"), 15000);
  rec('W5', 'Signed in as the doctor in Chrome: exactly the two assigned patients are listed', '2 list entries', listCount, listCount === 2);
  await pg.js("document.querySelector('#patient-table tbody tr[data-id]').click()");
  const detail = await until(() => pg.js("(() => { const d = document.querySelector('#detail'); const t = d ? d.textContent : ''; return /Diagnosis/.test(t) && /Medication/.test(t) && /Care notes/.test(t) ? t.slice(0, 160) : null; })()"), 15000);
  rec('W6', 'An assigned patient opens with summary and clinical record (diagnosis, medication, care notes)', 'detail shows Diagnosis, Medication and Care notes', detail ? 'yes' : 'no', !!detail);
  await pg.js(`(() => { document.querySelector('#lookup-id').value = ${JSON.stringify(env.ZT_TEST_PATIENT_DENIED)}; document.querySelector('#lookup-btn').click(); })()`);
  const refusal = await until(() => pg.js("(document.querySelector('#detail .alert.bad') || {}).textContent || null"), 15000);
  rec('W7', 'An unassigned patient is refused by the server and the page shows the reason in plain words (no code, no technical detail)', 'alert says "not on your list"', refusal, !!refusal && /not on your list/i.test(refusal) && !/technical detail|not_assigned|reference/i.test(refusal));

  // --- 4. nothing protected is stored in the browser
  const tokens = await pg.js('window.__tok');
  const tokenSet = [...new Set(tokens)].map((t) => t.replace(/^Bearer /, ''));
  const stores = await pg.js(`(async () => {
    const out = { local: Object.keys(localStorage), localValues: Object.values(localStorage), session: sessionStorage.length, cookie: document.cookie, idb: (await indexedDB.databases()).map((d) => d.name), caches: [] };
    for (const k of await caches.keys()) { const c = await caches.open(k); const entries = []; for (const req of await c.keys()) { const res = await c.match(req); entries.push({ url: new URL(req.url).pathname, body: (await res.clone().text()).slice(0, 400000) }); } out.caches.push({ name: k, entries }); }
    return out; })()`);
  const cachedPaths = stores.caches.flatMap((c) => c.entries.map((e) => e.url));
  const protectedCached = cachedPaths.filter((p) => /^\/(api|ctl|admin)\//.test(p));
  const tokenInCache = stores.caches.some((c) => c.entries.some((e) => tokenSet.some((t) => t.length > 20 && e.body.includes(t))));
  rec('W8', 'Cache Storage holds only the static shell: no /api, /ctl or /admin response and no token', 'only shell paths; none protected; token not found',
    `${stores.caches.length} cache(s), ${cachedPaths.length} entries: ${cachedPaths.join(' ')}; protected=${protectedCached.length}; token in cache=${tokenInCache}; tokens captured=${tokenSet.length}`,
    cachedPaths.length > 0 && protectedCached.length === 0 && !tokenInCache && tokenSet.length > 0);
  const tokenInStorage = stores.localValues.some((v) => tokenSet.some((t) => t.length > 20 && String(v).includes(t)));
  rec('W9', 'Browser storage holds no token or PIN: localStorage = device id only, no sessionStorage, no cookies, no IndexedDB', 'keys [zt_device_id]; 0; ""; []',
    `local=${JSON.stringify(stores.local)}; session=${stores.session}; cookie="${stores.cookie}"; idb=${JSON.stringify(stores.idb)}; token in localStorage=${tokenInStorage}`,
    JSON.stringify(stores.local) === '["zt_device_id"]' && stores.session === 0 && stores.cookie === '' && stores.idb.length === 0 && !tokenInStorage);
  const cdpCookies = await pg.cmd('Network.getAllCookies');
  rec('W10', 'The browser holds no cookie for the portal at all', '0 cookies', cdpCookies.cookies.length, cdpCookies.cookies.length === 0);

  // --- 5. closing the page ends the session on the server (a navigation may keep the page in the back/forward cache, so the tab is really closed)
  const lastToken = tokenSet[tokenSet.length - 1];
  const devId = await pg.js("localStorage.getItem('zt_device_id')");
  const before = await fetch(base + '/ctl/session', { headers: { Authorization: 'Bearer ' + lastToken, 'X-Device-Id': devId } });
  await send('Target.closeTarget', { targetId: pg.targetId });
  await sleep(1500);
  const after = await fetch(base + '/ctl/session', { headers: { Authorization: 'Bearer ' + lastToken, 'X-Device-Id': devId } });
  const afterBody = await after.json().catch(() => ({}));
  rec('W11', 'Closing the page ends the session on the server: the old token is refused afterwards', 'before 200; after 401 session_ended', `before ${before.status}; after ${after.status} ${afterBody.error || ''}`, before.status === 200 && after.status === 401 && afterBody.error === 'session_ended');

  // --- 6. offline: stop the edge, open the portal again: the service worker answers with the offline page; protected URLs are not answered from cache
  edge.kill();
  await sleep(1500);
  pg = await openPage();
  await pg.go(base + '/');
  const offline = await until(() => pg.js('document.title'), 8000);
  const bodyText = await pg.js('document.body.innerText');
  const apiCached = await pg.js("caches.match('/api/patients/list').then((r) => !!r)");
  let apiFetch = 'resolved';
  try { apiFetch = await pg.js("fetch('/api/patients/list', { cache: 'no-store' }).then(() => 'resolved', () => 'rejected')"); } catch (e) { apiFetch = 'error ' + e.message; }
  rec('W13', 'With the server unreachable, the installed shell shows the offline page (with the Everwell Hospital branding) and no patient data; protected URLs are not answered from cache', 'title "Offline - Everwell Hospital", text "You are offline" and the Everwell names, api not cached, api fetch rejected',
    `title="${offline}"; offline text=${/You are offline/.test(bodyText)}; Everwell names=${/Everwell Hospital/.test(bodyText) && /Everwell Health Portal/.test(bodyText)}; api cached=${apiCached}; api fetch=${apiFetch}`,
    /^Offline/.test(offline || '') && /Everwell Hospital/.test(offline || '') && /You are offline/.test(bodyText) && /Everwell Hospital/.test(bodyText) && /Everwell Health Portal/.test(bodyText) && !apiCached && apiFetch === 'rejected' && !/Grace|Marcus|Kim|Lee/.test(bodyText));

  // --- 7. CSP: no violations anywhere in this flow (both pages)
  const violations = events.filter((e) => (e.method === 'Log.entryAdded' && (e.params.entry.source === 'security' || /Content Security Policy|Refused to/i.test(e.params.entry.text || ''))) || e.method === 'Runtime.exceptionThrown')
    .map((e) => e.method === 'Runtime.exceptionThrown' ? 'exception: ' + (e.params.exceptionDetails.exception ? e.params.exceptionDetails.exception.description : e.params.exceptionDetails.text) : e.params.entry.text);
  rec('W12', 'No Content-Security-Policy violation and no uncaught script error during the whole flow', '0', violations.length + (violations.length ? ': ' + violations.slice(0, 3).join(' | ') : ''), violations.length === 0);
  ws.close();
}

main().catch((e) => rec('W0', 'The browser check ran to the end', 'no exception', e && e.stack || e, false)).finally(() => {
  cleanup();
  setTimeout(() => { process.stdout.write('RESULT_JSON:' + JSON.stringify(results) + '\n'); process.exit(0); }, 800);
});
