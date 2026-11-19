// Branding checks of the RENDERED interface in headless desktop Chrome (throw-away profile): Everwell Hospital / Everwell Health Portal / tagline, the
// generated icons (pixel checks: deep navy, teal ring, white cross), the sign-in page at desktop and phone width, every screen of all four roles
// (browser title, sidebar, top bar), and the offline page. It also proves the old product name is gone from everything a user can see.
// Environment: ZT_TEST_CHROME, ZT_TEST_BASE (loopback edge), ZT_TEST_PROFILE, ZT_ROLE_CREDS (JSON {"username":"password"}, never printed).
// Output: one line "RESULT_JSON:[...]" with {id,title,expected,actual,ok}.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const env = process.env;
const base = env.ZT_TEST_BASE;
const creds = JSON.parse(env.ZT_ROLE_CREDS || '{}');
const results = [];
const rec = (id, title, expected, actual, ok) => { results.push({ id, title, expected, actual: String(actual), ok: ok === true }); console.error(`${ok === true ? 'PASS' : 'FAIL'} ${id} ${title}${ok === true ? '' : ' -> ' + actual}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 15000, step = 150) { const end = Date.now() + ms; while (Date.now() < end) { try { const v = await fn(); if (v) return v; } catch (e) { /* retry */ } await sleep(step); } return null; }
let chrome = null;
process.on('exit', () => { try { chrome && chrome.kill(); } catch (e) { /* gone */ } });

const HOSPITAL = 'Everwell Hospital', PORTAL = 'Everwell Health Portal', TAGLINE = 'Compassionate Care. Trusted Access.';
const OLD = /zero[ -]?trust|ZT Hospital/i;

// pixel analysis of one icon, inside a page of the same origin (no tainted canvas)
const ANALYZE = `(async (src) => {
  const img = await new Promise((res, rej) => { const i = new Image(); i.onload = () => res(i); i.onerror = () => rej(new Error('image did not load: ' + src)); i.src = src + '?brandcheck=' + Date.now(); });
  const W = img.naturalWidth, H = img.naturalHeight;
  const c = document.createElement('canvas'); c.width = W; c.height = H;
  const x = c.getContext('2d', { willReadFrequently: true }); x.drawImage(img, 0, 0);
  const d = x.getImageData(0, 0, W, H).data;
  const near = (r, g, b, t, tol) => Math.abs(r - t[0]) <= tol && Math.abs(g - t[1]) <= tol && Math.abs(b - t[2]) <= tol;
  let teal = 0, white = 0, navy = 0, opaque = 0, outsideSafe = 0;
  const cx = W / 2, cy = H / 2, safe = 0.4 * Math.min(W, H);
  for (let y = 0; y < H; y++) for (let xx = 0; xx < W; xx++) {
    const i = (y * W + xx) * 4; const r = d[i], g = d[i + 1], b = d[i + 2], a = d[i + 3];
    if (a > 200) {
      opaque++;
      if (near(r, g, b, [0x27, 0xb5, 0xa6], 26)) teal++; else if (near(r, g, b, [255, 255, 255], 14)) white++; else if (near(r, g, b, [0x0b, 0x25, 0x45], 16)) navy++;
      const colored = near(r, g, b, [0x27, 0xb5, 0xa6], 40) || near(r, g, b, [255, 255, 255], 20);
      if (colored && Math.hypot(xx - cx, y - cy) > safe) outsideSafe++;
    }
  }
  const px = (xx, y) => { const i = (y * W + xx) * 4; return { r: d[i], g: d[i + 1], b: d[i + 2], a: d[i + 3] }; };
  return { W, H, teal: teal / (W * H), white: white / (W * H), navy: navy / (W * H), opaque: opaque / (W * H), outsideSafe, corner: px(0, 0), edge: px(Math.round(W * 0.08), H >> 1) };
})`;

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
    const js = async (expression) => { const r = await cmd('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }); if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception ? r.exceptionDetails.exception.description : r.exceptionDetails.text); return r.result.value; };
    const go = async (url) => { const mark = events.length; await cmd('Page.navigate', { url }); await until(() => events.slice(mark).some((e) => e.sessionId === sessionId && e.method === 'Page.loadEventFired'), 15000); };
    return { targetId, cmd, js, go };
  }
  const settle = async (pg, ms = 1200) => { await sleep(ms); await until(() => pg.js("!document.querySelector('.skeleton')"), 8000); };

  // ---------------------------------------------------------------- BR3: the generated icons (pixels)
  let pg = await openPage(1280, 800, false);
  await pg.go(base + '/offline.html');
  const icons = {};
  for (const [name, src] of [['icon-192', '/icons/icon-192.png'], ['icon-512', '/icons/icon-512.png'], ['maskable-512', '/icons/icon-maskable-512.png'], ['favicon-32', '/favicon.png']]) icons[name] = await pg.js(`(${ANALYZE})(${JSON.stringify(src)})`);
  const probs = [];
  for (const k of ['icon-192', 'icon-512']) { const a = icons[k]; if (a.corner.a > 60) probs.push(`${k}: corner not transparent`); if (a.navy < 0.35) probs.push(`${k}: navy ${a.navy.toFixed(2)}`); if (a.teal < 0.03) probs.push(`${k}: teal ${a.teal.toFixed(3)}`); if (a.white < 0.02) probs.push(`${k}: white ${a.white.toFixed(3)}`); }
  const m = icons['maskable-512'];
  if (m.opaque < 0.99) probs.push(`maskable: not full bleed (${m.opaque.toFixed(3)})`);
  if (!(m.corner.a > 250 && Math.abs(m.corner.r - 0x0b) < 12 && Math.abs(m.corner.g - 0x25) < 12 && Math.abs(m.corner.b - 0x45) < 12)) probs.push('maskable: corner is not deep navy');
  if (m.teal < 0.02 || m.white < 0.015) probs.push(`maskable: teal ${m.teal.toFixed(3)} white ${m.white.toFixed(3)}`);
  if (m.outsideSafe > 0) probs.push(`maskable: ${m.outsideSafe} symbol pixels outside the safe zone`);
  const f = icons['favicon-32'];
  if (f.W !== 32 || f.teal < 0.05 || f.white < 0.02) probs.push(`favicon: ${f.W}px teal ${f.teal.toFixed(3)} white ${f.white.toFixed(3)}`);
  if (icons['icon-192'].W !== 192 || icons['icon-512'].W !== 512 || m.W !== 512) probs.push('icon sizes differ from the manifest');
  rec('BR3', 'The generated icons carry the new mark: deep navy field, teal ring, white medical cross (pixel check of the 192, 512, maskable 512 and 32 px files; the maskable symbol stays inside the Android safe zone)', 'navy >= 35 %, teal ring and white cross present, transparent corners on "any" icons, full-bleed navy on the maskable icon, nothing outside the safe zone',
    `problems: [${probs.join('; ')}]; 512 icon: navy ${icons['icon-512'].navy.toFixed(2)}, teal ${icons['icon-512'].teal.toFixed(3)}, white ${icons['icon-512'].white.toFixed(3)}`, probs.length === 0);
  await send('Target.closeTarget', { targetId: pg.targetId });

  // ---------------------------------------------------------------- BR4: the sign-in page at desktop and phone width
  const loginProblems = [];
  for (const [w, h, mobile] of [[1280, 800, false], [360, 740, true]]) {
    pg = await openPage(w, h, mobile);
    await pg.go(base + '/');
    await until(() => pg.js("!!document.querySelector('form input[type=password]')"), 15000);
    await sleep(500);
    const f2 = await pg.js(`(async () => {
      const metas = (n) => (document.querySelector('meta[name="' + n + '"]') || {}).content || '';
      const logo = document.querySelector('.login-bar .brand-mark');
      const ok = async (href) => { try { const r = await fetch(href, { cache: 'no-store' }); return r.status === 200; } catch (e) { return false; } };
      return { title: document.title, text: document.body.innerText, html: document.documentElement.outerHTML, app: metas('application-name'), desc: metas('description'), apple: metas('apple-mobile-web-app-title'),
        logoLoaded: !!logo && logo.complete && logo.naturalWidth >= 100, appleOk: await ok((document.querySelector('link[rel="apple-touch-icon"]') || {}).href), iconOk: await ok((document.querySelector('link[rel="icon"]') || {}).href),
        manifestOk: await ok((document.querySelector('link[rel="manifest"]') || {}).href), bar: (document.querySelector('.login-bar') || {}).innerText || '', hscroll: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1 };
    })()`);
    const tag = `${w}px`;
    if (!f2.title.includes(HOSPITAL)) loginProblems.push(`${tag}: title "${f2.title}"`);
    for (const need of [HOSPITAL, PORTAL, TAGLINE]) if (!f2.text.toLowerCase().includes(need.toLowerCase())) loginProblems.push(`${tag}: page text lacks "${need}"`);
    if (!f2.bar.includes(HOSPITAL) || !f2.bar.includes(TAGLINE)) loginProblems.push(`${tag}: login bar "${f2.bar.replace(/\s+/g, ' ')}"`);
    if (OLD.test(f2.title + ' ' + f2.text + ' ' + f2.html + ' ' + f2.desc + ' ' + f2.app)) loginProblems.push(`${tag}: the old product name is still visible`);
    if (f2.app !== PORTAL) loginProblems.push(`${tag}: application-name "${f2.app}"`);
    if (!f2.desc.includes(HOSPITAL)) loginProblems.push(`${tag}: meta description`);
    if (!f2.apple.includes('Everwell')) loginProblems.push(`${tag}: apple-mobile-web-app-title "${f2.apple}"`);
    if (!f2.logoLoaded || !f2.appleOk || !f2.iconOk || !f2.manifestOk) loginProblems.push(`${tag}: logo/icons/manifest not loading (${JSON.stringify({ l: f2.logoLoaded, a: f2.appleOk, i: f2.iconOk, m: f2.manifestOk })})`);
    if (f2.hscroll) loginProblems.push(`${tag}: horizontal scroll`);
    await send('Target.closeTarget', { targetId: pg.targetId });
  }
  rec('BR4', 'Sign-in page (desktop and 360 px phone): "Everwell Hospital" and the tagline in the header bar, "Everwell Health Portal" on the card, browser title, application-name and description metadata, logo and icons load, no old product name anywhere in the page, no horizontal scroll',
    'all present, nothing old', `problems: [${loginProblems.join('; ')}]`, loginProblems.length === 0);

  // ---------------------------------------------------------------- BR5: all four role dashboards and every one of their screens
  const roles = [['dr_alice', 'Doctor'], ['nurse_bob', 'Nurse'], ['front_carol', 'Receptionist'], ['sec_dan', 'Security administrator']];
  const dashProblems = []; let screens = 0;
  for (const [user, roleName] of roles) {
    if (!creds[user]) { dashProblems.push(`${roleName}: no credentials for the check`); continue; }
    pg = await openPage(1280, 900, false);
    await pg.go(base + '/');
    await until(() => pg.js("!!document.querySelector('form input[type=password]')"), 15000);
    await pg.js(`(() => { document.querySelector('#u').value = ${JSON.stringify(user)}; document.querySelector('#p').value = ${JSON.stringify(creds[user])}; document.querySelector('form').requestSubmit(); })()`);
    if (!(await until(() => pg.js("!!document.querySelector('.topbar')"), 15000))) { dashProblems.push(`${roleName}: sign-in failed`); continue; }
    await settle(pg, 1500);
    const views = await pg.js("[...document.querySelectorAll('.nav-link')].map((a) => a.getAttribute('data-view') + '|' + a.querySelector('span').textContent.trim())");
    const frame = async (where, expectTitle) => {
      const s = await pg.js(`(() => ({
        title: document.title,
        side: (document.querySelector('.sidenav-head .brand-name') || {}).textContent || '',
        sideSub: (document.querySelector('.sidenav-head .brand-sub') || {}).textContent || '',
        eyebrow: (document.querySelector('.topbar-eyebrow') || {}).textContent || '',
        logo: (() => { const l = document.querySelector('.sidenav-head .brand-mark'); return !!l && l.complete && l.naturalWidth >= 100; })(),
        html: document.documentElement.outerHTML }))()`);
      screens++;
      if (s.title !== expectTitle) dashProblems.push(`${where}: title "${s.title}"`);
      if (s.side !== HOSPITAL || s.sideSub !== 'Health Portal') dashProblems.push(`${where}: sidebar "${s.side}" / "${s.sideSub}"`);
      if (!(s.eyebrow === HOSPITAL || s.eyebrow === HOSPITAL + ' - Security operations')) dashProblems.push(`${where}: top bar "${s.eyebrow}"`);
      if (!s.logo) dashProblems.push(`${where}: logo not loaded`);
      if (OLD.test(s.html)) dashProblems.push(`${where}: the old product name is in the page`);
    };
    for (const v of views) {
      const [id, label] = v.split('|');
      await pg.js(`location.hash = '#/${id}'`);
      await settle(pg, 1500);
      await frame(`${roleName} > ${label}`, `${label} - ${HOSPITAL}`);
    }
    if (user !== 'sec_dan') {                                    // a patient chart carries the same brand frame
      const first = views[0].split('|')[1];
      await pg.js("location.hash = '#/patients/101'"); await settle(pg, 2000);
      await frame(`${roleName} > patient chart`, `${first} - ${HOSPITAL}`);
    }
    await pg.js("document.getElementById('signout-btn') && document.getElementById('signout-btn').click()"); await sleep(500);
    await send('Target.closeTarget', { targetId: pg.targetId });
  }
  rec('BR5', 'All four role dashboards (Doctor, Nurse, Receptionist, Security administrator) and every screen of each: sidebar "Everwell Hospital / Health Portal" with the logo, top bar "Everwell Hospital", browser title "<screen> - Everwell Hospital", and no trace of the old product name in the page',
    '4 roles, every screen branded', `${screens} screens checked; problems: [${dashProblems.slice(0, 6).join('; ')}]`, dashProblems.length === 0 && screens >= 14);

  // ---------------------------------------------------------------- BR7: the offline page itself, at phone width
  pg = await openPage(360, 740, true);
  await pg.go(base + '/offline.html');
  await sleep(500);
  const o = await pg.js(`(() => { const a = document.querySelector('a.btn'); const r = a ? a.getBoundingClientRect() : null; const logo = document.querySelector('.offline-card img');
    return { title: document.title, text: document.body.innerText, html: document.documentElement.outerHTML, logo: !!logo && logo.complete && logo.naturalWidth >= 100, btn: r ? Math.round(r.height) : 0,
      hscroll: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1 }; })()`);
  const offProblems = [];
  if (!/^Offline/.test(o.title) || !o.title.includes(HOSPITAL)) offProblems.push(`title "${o.title}"`);
  for (const need of [HOSPITAL, PORTAL, TAGLINE, 'You are offline']) if (!o.text.includes(need)) offProblems.push(`text lacks "${need}"`);
  if (OLD.test(o.title + o.html)) offProblems.push('old product name present');
  if (!o.logo) offProblems.push('logo not loaded');
  if (o.btn < 44) offProblems.push(`button height ${o.btn}`);
  if (o.hscroll) offProblems.push('horizontal scroll');
  rec('BR7', 'The offline page (360 px): title "Offline - Everwell Hospital", Everwell Hospital and Everwell Health Portal names, tagline, logo, a 44 px "Try again" button, no horizontal scroll, no old product name',
    'all present', `problems: [${offProblems.join('; ')}]`, offProblems.length === 0);
  await send('Target.closeTarget', { targetId: pg.targetId });
  ws.close();
}

main().catch((e) => rec('BR0', 'The branding checks ran to the end', 'no exception', e && e.stack || e, false)).finally(() => {
  try { chrome && chrome.kill(); } catch (e) { /* gone */ }
  setTimeout(() => { process.stdout.write('RESULT_JSON:' + JSON.stringify(results) + '\n'); process.exit(0); }, 800);
});
