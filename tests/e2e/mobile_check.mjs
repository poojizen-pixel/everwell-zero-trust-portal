// Responsive and mobile-usability checks in headless desktop Chrome (throw-away profile) with phone EMULATION (device metrics + touch + mobile viewport
// behaviour). It proves what the layout does at 360 CSS pixels (and 320, 768, 1280); it is NOT a test on a real phone.
// What is checked, for the sign-in screen and every screen of every role (including the dialogs the roles can open):
//   - no horizontal page scroll and nothing sticking out of the viewport
//   - touch targets of at least 44 x 44 CSS pixels for buttons, links, inputs, switches and summaries (inline text links and the clickable table rows excepted)
//   - form fields use at least 16 px text (a smaller size makes phone browsers zoom the page when a field gets focus)
//   - tables turn into cards on phones and stay tables on desktop
//   - the navigation drawer is accessible: state exposed with aria, focus moves in and back, Escape and the scrim close it, the page behind is inert
// Environment: ZT_TEST_CHROME, ZT_TEST_BASE, ZT_TEST_PROFILE, ZT_ROLE_CREDS, ZT_ROLE_PINS (JSON maps, never printed).
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

// measurements taken inside the page
const MEASURE = `(() => {
  const vw = document.documentElement.clientWidth;
  const visible = (e) => { const r = e.getBoundingClientRect(); const cs = getComputedStyle(e); return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none' && r.bottom > 0 && r.right > 0 && r.left < vw + 5; };
  const label = (e) => (e.tagName.toLowerCase() + (e.id ? '#' + e.id : '') + (typeof e.className === 'string' && e.className ? '.' + e.className.trim().split(/\\s+/).slice(0, 2).join('.') : '') + ' "' + ((e.innerText || e.getAttribute('aria-label') || e.value || '') + '').replace(/\\s+/g, ' ').trim().slice(0, 30) + '"');
  const scrollParent = (e) => { for (let p = e.parentElement; p && p !== document.body; p = p.parentElement) { const o = getComputedStyle(p).overflowX; if (o === 'auto' || o === 'scroll' || o === 'hidden') return true; } return false; };
  const inClosedDialog = (e) => { const d = e.closest('dialog'); return !!d && !d.open; };
  const out = { vw, scrollW: Math.max(document.documentElement.scrollWidth, document.body.scrollWidth), overflow: [], small: [], smallFont: [], rows: [] };
  for (const e of document.querySelectorAll('body *')) {
    if (!visible(e) || inClosedDialog(e)) continue;
    const r = e.getBoundingClientRect();
    if (r.right > vw + 1 && !scrollParent(e) && !e.closest('svg') && e.tagName !== 'BODY') out.overflow.push(label(e) + ' right=' + Math.round(r.right));
  }
  const targets = document.querySelectorAll('button, a[href], input:not([type=hidden]), select, textarea, summary, [role=button]');
  for (const e of targets) {
    if (!visible(e) && !(e.tagName === 'INPUT' && (e.type === 'radio' || e.type === 'checkbox'))) continue;
    if (inClosedDialog(e) || e.classList.contains('skip-link') || e.classList.contains('row-link')) continue;
    if (e.tagName === 'A' && getComputedStyle(e).display === 'inline') continue;                               // inline text link inside a sentence
    let box = e;
    if (e.tagName === 'INPUT' && (e.type === 'radio' || e.type === 'checkbox')) { const l = e.closest('label'); if (!l) continue; box = l; if (!visible(l)) continue; }
    const r = box.getBoundingClientRect();
    if (r.top > window.innerHeight * 4) continue;
    if (r.height < 43.5 || r.width < 43.5) out.small.push(label(e) + ' ' + Math.round(r.width) + 'x' + Math.round(r.height));
  }
  for (const e of document.querySelectorAll('input:not([type=hidden]):not([type=checkbox]):not([type=radio]), select, textarea')) {
    if (!visible(e) || inClosedDialog(e)) continue;
    if (parseFloat(getComputedStyle(e).fontSize) < 15.99) out.smallFont.push(label(e) + ' ' + getComputedStyle(e).fontSize);
  }
  for (const tr of document.querySelectorAll('table.data tbody tr')) { if (visible(tr)) { out.rows.push({ display: getComputedStyle(tr).display, h: Math.round(tr.getBoundingClientRect().height), clickable: tr.hasAttribute('data-id') }); } }
  const th = document.querySelector('table.data thead'); if (th) { const r = th.getBoundingClientRect(); const cs = getComputedStyle(th); out.theadBox = Math.round(r.width) + 'x' + Math.round(r.height) + ' ' + cs.position; }
  return out;
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

  async function openPage(width, height, mobile) {
    const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
    const cmd = (m, p) => send(m, p, sessionId);
    for (const d of ['Page', 'Runtime']) await cmd(d + '.enable');
    await cmd('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: mobile ? 2 : 1, mobile });
    if (mobile) await cmd('Emulation.setTouchEmulationEnabled', { enabled: true, maxTouchPoints: 5 });
    const js = async (expression) => { const r = await cmd('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }); if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception ? r.exceptionDetails.exception.description : r.exceptionDetails.text); return r.result.value; };
    const go = async (url) => { const mark = events.length; await cmd('Page.navigate', { url }); await until(() => events.slice(mark).some((e) => e.sessionId === sessionId && e.method === 'Page.loadEventFired'), 15000); };
    const key = (k) => cmd('Input.dispatchKeyEvent', { type: 'keyDown', key: k, code: k, windowsVirtualKeyCode: k === 'Escape' ? 27 : 0 }).then(() => cmd('Input.dispatchKeyEvent', { type: 'keyUp', key: k, code: k, windowsVirtualKeyCode: k === 'Escape' ? 27 : 0 }));
    const tap = async (x, y) => { await cmd('Input.dispatchMouseEvent', { type: 'mousePressed', x, y, button: 'left', clickCount: 1 }); await cmd('Input.dispatchMouseEvent', { type: 'mouseReleased', x, y, button: 'left', clickCount: 1 }); };
    return { targetId, sessionId, cmd, js, go, key, tap };
  }
  const click = (pg, sel, textMatch) => pg.js(`(() => { const els = [...document.querySelectorAll(${JSON.stringify(sel)})]; const e = ${textMatch ? `els.find((x) => (x.innerText || '').trim().startsWith(${JSON.stringify(textMatch)}))` : 'els[0]'}; if (!e) return false; e.click(); return true; })()`);
  const settle = async (pg, ms = 1200) => { await sleep(ms); await until(() => pg.js("!document.querySelector('.skeleton')"), 8000); };
  async function signIn(pg, user, evaluation) {
    await pg.go(base + '/' + (evaluation ? '?evaluation=1' : ''));
    await until(() => pg.js("!!document.querySelector('form input[type=password]')"), 15000);
    await pg.js(`(() => { document.querySelector('#u').value = ${JSON.stringify(user)}; document.querySelector('#p').value = ${JSON.stringify(creds[user])}; document.querySelector('form').requestSubmit(); })()`);
    const ok = await until(() => pg.js("!!document.querySelector('.topbar')"), 15000);
    await settle(pg, 1500);
    return !!ok;
  }
  const signOut = async (pg) => { await pg.js("document.getElementById('signout-btn') && document.getElementById('signout-btn').click()"); await sleep(600); };
  const summarize = (m) => ({ overflow: m.overflow.slice(0, 4), small: m.small.slice(0, 6), smallFont: m.smallFont.slice(0, 4), hscroll: m.scrollW > m.vw + 1 });

  // ---------------------------------------------------------------- M1: viewport and PWA basics
  let pg = await openPage(360, 740, true);
  await pg.go(base + '/');
  await until(() => pg.js("!!document.querySelector('form input[type=password]')"), 15000);
  const meta = await pg.js("(() => ({ vp: (document.querySelector('meta[name=viewport]') || {}).content || '', theme: (document.querySelector('meta[name=theme-color]') || {}).content || '', manifest: !!document.querySelector('link[rel=manifest]') }))()");
  rec('M1', 'The page declares a mobile viewport that still allows pinch-zoom, a navy theme colour and the web app manifest', 'width=device-width, initial-scale=1, no maximum-scale / user-scalable=no; theme-color #0b2545; manifest link', `viewport "${meta.vp}"; theme "${meta.theme}"; manifest link ${meta.manifest}`,
    /width=device-width/.test(meta.vp) && /initial-scale=1/.test(meta.vp) && !/maximum-scale|user-scalable\s*=\s*(no|0)/i.test(meta.vp) && meta.theme.toLowerCase() === '#0b2545' && meta.manifest);

  // ---------------------------------------------------------------- M2: sign-in screen at 360 and 320
  const loginProblems = [];
  for (const w of [360, 320]) {
    await pg.cmd('Emulation.setDeviceMetricsOverride', { width: w, height: 740, deviceScaleFactor: 2, mobile: true });
    await pg.go(base + '/'); await until(() => pg.js("!!document.querySelector('form input[type=password]')"), 15000); await sleep(500);
    const s = summarize(await pg.js(MEASURE));
    if (s.hscroll) loginProblems.push(`${w}px: horizontal scroll`);
    s.overflow.forEach((o) => loginProblems.push(`${w}px: ${o}`)); s.small.forEach((o) => loginProblems.push(`${w}px small target: ${o}`)); s.smallFont.forEach((o) => loginProblems.push(`${w}px small font: ${o}`));
  }
  rec('M2', 'The sign-in screen fits 360 px and 320 px wide screens: no horizontal scroll, nothing outside the viewport, touch targets of at least 44 px, form text of at least 16 px', 'no problems', `problems: [${loginProblems.join('; ')}]`, loginProblems.length === 0);
  await pg.cmd('Emulation.setDeviceMetricsOverride', { width: 360, height: 740, deviceScaleFactor: 2, mobile: true });
  await send('Target.closeTarget', { targetId: pg.targetId });

  // ---------------------------------------------------------------- M3-M6: every screen of every role at 360 px
  const roles = [['dr_alice', 'doctor', 'M3'], ['nurse_bob', 'nurse', 'M4'], ['front_carol', 'receptionist', 'M5'], ['sec_dan', 'security administrator', 'M6']];
  const targetProblems = []; const fontProblems = []; const cardProblems = []; const drawerProblems = [];
  for (const [user, roleName, rid] of roles) {
    if (!creds[user]) continue;
    pg = await openPage(360, 740, true);
    if (!(await signIn(pg, user))) { rec(rid, `${roleName}: every screen at 360 px`, 'signed in', 'sign-in failed', false); continue; }
    const views = await pg.js("[...document.querySelectorAll('.nav-link')].map((a) => a.getAttribute('data-view') + '|' + a.querySelector('span').textContent.trim())");
    const problems = [];
    const check = async (where) => {
      await sleep(250);
      const s = summarize(await pg.js(MEASURE));
      if (s.hscroll) problems.push(`${where}: horizontal page scroll`);
      s.overflow.forEach((o) => problems.push(`${where}: outside viewport: ${o}`));
      s.small.forEach((o) => targetProblems.push(`${roleName} ${where}: ${o}`));
      s.smallFont.forEach((o) => fontProblems.push(`${roleName} ${where}: ${o}`));
    };
    let screenCount = 0;
    const visit = async (viewList) => {
      for (const v of viewList) {
        const [id, label] = v.split('|');
        screenCount++;
        await pg.js(`location.hash = '#/${id}'`);
        await settle(pg, 1800);
        await check(label);
        if (id === 'patients') {
          const first = await pg.js("(() => { const r = document.querySelector('#patient-table tbody tr[data-id]'); return r ? r.getAttribute('data-id') : null; })()");
          const rowInfo = await pg.js(MEASURE);
          const cardRows = rowInfo.rows.filter((r) => r.display === 'block' || r.display === 'grid');
          if (rowInfo.rows.length && cardRows.length !== rowInfo.rows.length) cardProblems.push(`${roleName}: patient rows not cards (${rowInfo.rows.map((r) => r.display).join(',')})`);
          if (rowInfo.rows.some((r) => r.clickable && r.h < 44)) cardProblems.push(`${roleName}: a patient row is shorter than 44 px`);
          if (first) { await pg.js(`location.hash = '#/patients/${first}'`); await settle(pg, 2200); await check(label + ' > patient chart'); }
          if (roleName === 'doctor') {
            await pg.js("location.hash = '#/patients/103'"); await settle(pg, 1800); await check(label + ' > refused patient');
            if (await click(pg, '#emergency-btn')) { await sleep(700); await check(label + ' > emergency dialog'); await pg.js("document.querySelectorAll('dialog.modal[open]').forEach((d) => d.close())"); }
          }
          if (user !== 'sec_dan') {                                    // the account menu is part of every clinical screen
            if (await click(pg, '#account-btn')) { await until(() => pg.js("!!document.querySelector('dialog[open]')"), 8000); await sleep(400); await check(label + ' > account menu'); await pg.js("document.querySelectorAll('dialog.modal[open]').forEach((d) => d.close())"); }
          }
          await pg.js("location.hash = '#/patients'"); await sleep(300);
        }
        if (id === 'appointments' && await click(pg, '#appointment-table tbody button')) { await sleep(700); await check(label + ' > reschedule dialog'); await pg.js("document.querySelectorAll('dialog.modal[open]').forEach((d) => d.close())"); }
        if (id === 'demo') {
          // the evaluation tools put results on screen: look at the layout with a result card showing
          if (await click(pg, '#apply-network')) { await until(() => pg.js("!!document.querySelector('#network-result .result-card')"), 12000); await sleep(400); await check(label + ' > with a result'); }
          await click(pg, '#reset-sim'); await sleep(800);
          await pg.js("(() => { const s = document.querySelector('#sim-network'); if (s) { s.value = 'reset'; s.dispatchEvent(new Event('change')); document.querySelector('#apply-network').click(); } })()"); await sleep(1500);
        }
      }
    };
    // the shell itself (drawer closed)
    await visit(views);

    // the navigation drawer (once per role: the nav items differ)
    const dr = [];
    const st0 = await pg.js("(() => { const t = document.getElementById('nav-toggle'); const n = document.getElementById('sidenav'); return { toggle: !!t, label: t && t.getAttribute('aria-label'), expanded: t && t.getAttribute('aria-expanded'), controls: t && t.getAttribute('aria-controls'), navVisibility: getComputedStyle(n).visibility, region: n.tagName + ':' + (n.getAttribute('aria-label') || ''), tw: t && Math.round(t.getBoundingClientRect().width), th: t && Math.round(t.getBoundingClientRect().height) }; })()");
    if (!st0.toggle || st0.expanded !== 'false' || st0.controls !== 'sidenav' || st0.navVisibility !== 'hidden') dr.push(`closed state: ${JSON.stringify(st0)}`);
    if (st0.tw < 44 || st0.th < 44) dr.push(`menu button ${st0.tw}x${st0.th}`);
    await click(pg, '#nav-toggle'); await sleep(450);
    const st1 = await pg.js("(() => { const n = document.getElementById('sidenav'); const r = n.getBoundingClientRect(); const links = [...n.querySelectorAll('.nav-link')]; return { open: document.getElementById('shell').dataset.nav, expanded: document.getElementById('nav-toggle').getAttribute('aria-expanded'), vis: getComputedStyle(n).visibility, left: Math.round(r.left), right: Math.round(r.right), focusInside: !!document.activeElement.closest('#sidenav'), inert: document.getElementById('main-col').inert === true, minLink: Math.round(Math.min(...links.map((a) => a.getBoundingClientRect().height))), current: links.filter((a) => a.getAttribute('aria-current') === 'page').length, scrim: !document.querySelector('.scrim').hidden }; })()");
    if (st1.open !== 'open' || st1.expanded !== 'true' || st1.vis !== 'visible' || st1.left < 0 || st1.right > 360) dr.push(`open state: ${JSON.stringify(st1)}`);
    if (!st1.focusInside) dr.push('focus did not move into the drawer');
    if (!st1.inert) dr.push('the page behind the drawer is not inert');
    if (st1.minLink < 44) dr.push(`navigation link height ${st1.minLink}`);
    if (st1.current !== 1) dr.push(`aria-current on ${st1.current} links`);
    await pg.key('Escape'); await sleep(450);
    const st2 = await pg.js("(() => ({ open: document.getElementById('shell').dataset.nav, expanded: document.getElementById('nav-toggle').getAttribute('aria-expanded'), focusOnToggle: document.activeElement === document.getElementById('nav-toggle'), inert: document.getElementById('main-col').inert === true }))()");
    if (st2.open !== 'closed' || st2.expanded !== 'false' || !st2.focusOnToggle || st2.inert) dr.push(`after Escape: ${JSON.stringify(st2)}`);
    await click(pg, '#nav-toggle'); await sleep(450);
    await pg.tap(345, 400); await sleep(450);                        // a tap on the dimmed page next to the drawer
    const st3 = await pg.js("document.getElementById('shell').dataset.nav");
    if (st3 !== 'closed') dr.push(`a tap outside the drawer left it ${st3}`);
    await click(pg, '#nav-toggle'); await sleep(450);
    const before = await pg.js('location.hash');
    const second = await pg.js("(() => { const l = [...document.querySelectorAll('#sidenav .nav-link')].find((a) => a.getAttribute('aria-current') !== 'page'); return l ? l.getAttribute('data-view') : null; })()");
    // a role with one navigation item (doctor, nurse) has no other link to choose: choosing the open screen must still close the drawer
    const chosen = second || await pg.js("document.querySelector('#sidenav .nav-link').getAttribute('data-view')");
    await click(pg, `#sidenav .nav-link[data-view="${chosen}"]`); await sleep(900);
    const st4 = await pg.js("({ open: document.getElementById('shell').dataset.nav, hash: location.hash, title: document.getElementById('page-title').textContent })");
    if (st4.open !== 'closed' || (second && (st4.hash === before || !st4.hash.endsWith(second)))) dr.push(`choosing a link: ${JSON.stringify(st4)} (was ${before})`);
    drawerProblems.push(...dr.map((d) => `${roleName}: ${d}`));
    // evaluation mode (clinical roles): the screens that exist only there are measured too
    if (user !== 'sec_dan') {
      await signOut(pg);
      if (await signIn(pg, user, true)) {
        const evViews = (await pg.js("[...document.querySelectorAll('.nav-link')].map((a) => a.getAttribute('data-view') + '|' + a.querySelector('span').textContent.trim())")).filter((v) => /^(session|demo)\|/.test(v));
        if (evViews.length !== 2) problems.push(`evaluation mode offers ${evViews.length} extra screens`);
        await visit(evViews);
      } else problems.push('evaluation-mode sign-in failed');
    }
    rec(rid, `${roleName[0].toUpperCase() + roleName.slice(1)}: every screen (${screenCount} screens, patient charts, dialogs and the account menu included${user === 'sec_dan' ? '' : '; evaluation mode too'}) fits a 360 px wide phone without horizontal page scroll`, 'no horizontal scroll, nothing outside the viewport', `problems: [${problems.slice(0, 5).join('; ')}]`, problems.length === 0);
    await signOut(pg);
    await send('Target.closeTarget', { targetId: pg.targetId });
  }
  rec('M7', 'Touch targets on every screen, in every dialog and in the drawer are at least 44 x 44 px (buttons, links, inputs, switches, summaries); table rows are tall enough to tap', 'no target smaller than 44 px', `${targetProblems.length} small target(s): [${targetProblems.slice(0, 6).join('; ')}]`, targetProblems.length === 0);
  rec('M8', 'Form fields use at least 16 px text on phones (smaller text makes phone browsers zoom the page when a field is focused)', 'no field under 16 px', `${fontProblems.length}: [${fontProblems.slice(0, 5).join('; ')}]`, fontProblems.length === 0);
  rec('M9', 'Tables turn into readable cards on a phone (header hidden visually, one block per row)', 'patient rows are blocks/grids for every clinical and front-desk role', `problems: [${cardProblems.join('; ')}]`, cardProblems.length === 0);
  rec('M10', 'The navigation drawer is accessible: menu button with aria-expanded/aria-controls, focus moves into the drawer, the page behind is inert, Escape and a tap outside close it, focus returns to the menu button, choosing a link navigates and closes it', 'no problem for any of the four roles', `problems: [${drawerProblems.join('; ')}]`, drawerProblems.length === 0);

  // ---------------------------------------------------------------- M11: tablet and desktop widths
  const widthProblems = [];
  for (const [w, h, mobile] of [[768, 1024, true], [1024, 768, false], [1280, 800, false], [1920, 1080, false]]) {
    for (const evaluation of [false, true]) {
      pg = await openPage(w, h, mobile);
      if (!(await signIn(pg, 'dr_alice', evaluation))) { widthProblems.push(`${w}px: sign-in failed`); continue; }
      for (const hash of evaluation ? ['#/session', '#/demo'] : ['#/patients/101']) {
        await pg.js(`location.hash = '${hash}'`); await settle(pg, 1500);
        const s = summarize(await pg.js(MEASURE));
        if (s.hscroll) widthProblems.push(`${w}px ${hash}: horizontal scroll`);
        s.overflow.forEach((o) => widthProblems.push(`${w}px ${hash}: ${o}`));
      }
      const shell = await pg.js("(() => { const n = document.getElementById('sidenav'); const t = document.getElementById('nav-toggle'); const r = n.getBoundingClientRect(); const chip = document.getElementById('chip-device'); const acc = document.getElementById('account-btn'); return { navVisible: getComputedStyle(n).visibility === 'visible' && r.left >= 0 && r.width > 100, toggleShown: getComputedStyle(t).display !== 'none', chipsShown: !!chip && getComputedStyle(chip).display !== 'none', chipCount: document.querySelectorAll('.status-chips > *').length, accountShown: !!acc && acc.getBoundingClientRect().width >= 44 && acc.getBoundingClientRect().height >= 44 }; })()");
      if (w >= 1024 && (!shell.navVisible || shell.toggleShown)) widthProblems.push(`${w}px: desktop layout wrong ${JSON.stringify(shell)}`);
      if (w >= 1024 && evaluation && !shell.chipsShown) widthProblems.push(`${w}px: evaluation mode lacks its status chips ${JSON.stringify(shell)}`);
      if (!evaluation && shell.chipCount !== 0) widthProblems.push(`${w}px: the normal workspace shows status chips ${JSON.stringify(shell)}`);
      if (!shell.accountShown) widthProblems.push(`${w}px: the account button is missing or smaller than 44 px ${JSON.stringify(shell)}`);
      if (w < 1024 && (shell.navVisible || !shell.toggleShown)) widthProblems.push(`${w}px: drawer layout wrong ${JSON.stringify(shell)}`);
      if (w >= 1024 && !evaluation) { await pg.js("location.hash = '#/patients'"); await settle(pg, 1200); const rows = (await pg.js(MEASURE)).rows; if (rows.length && !rows.every((r) => r.display === 'table-row')) widthProblems.push(`${w}px: tables are not tables (${[...new Set(rows.map((r) => r.display))].join(',')})`); }
      await signOut(pg);
      await send('Target.closeTarget', { targetId: pg.targetId });
    }
  }
  rec('M11', 'Tablet and desktop widths (768, 1024, 1280, 1920 px), normal and evaluation mode: no horizontal scroll; drawer below 1024 px, persistent navigation from 1024 px; no status chips in the normal workspace and the full chips only in evaluation mode; the account button is always at least 44 px; tables are real tables on desktop', 'no problems', `problems: [${widthProblems.slice(0, 6).join('; ')}]`, widthProblems.length === 0);
  ws.close();
}

main().catch((e) => rec('M0', 'The mobile checks ran to the end', 'no exception', e && e.stack || e, false)).finally(() => {
  try { chrome && chrome.kill(); } catch (e) { /* gone */ }
  setTimeout(() => { process.stdout.write('RESULT_JSON:' + JSON.stringify(results) + '\n'); process.exit(0); }, 800);
});
