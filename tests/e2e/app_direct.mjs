// Defence-in-depth test of the PROTECTED APP on its own (no PDP decision, no PEP): the app is called directly with identity claims that carry a
// CORRECT PEP signature (the test knows the run's shared secret, i.e. it plays a PEP that forwards wrong or hostile claims). The app must still
// refuse everything the database says the account may not do, and must refuse requests whose signature, timestamp or path do not match.
// Environment: ZT_APP_URL (https://127.0.0.1:9000), ZT_PEP_APP_SECRET, ZT_APP_CERT (PEM of the app's self-signed certificate, used as the ONLY trust anchor),
//   ZT_USERS (JSON from db_probe users), ZT_BG_SESSION + ZT_BG_PATIENT (a session that holds an active break-glass grant), ZT_CLIN (JSON clinical values).
// Output: "RESULT_JSON:[...]" with {id,title,expected,actual,ok}.
import https from 'node:https';
import fs from 'node:fs';
import crypto from 'node:crypto';

const env = process.env;
const url = new URL(env.ZT_APP_URL);
const pem = fs.readFileSync(env.ZT_APP_CERT);
const secret = env.ZT_PEP_APP_SECRET;
const users = Object.fromEntries(JSON.parse(env.ZT_USERS).map((u) => [u.username, u]));
const clin = JSON.parse(env.ZT_CLIN || '[]');
const results = [];
const rec = (id, title, expected, actual, ok) => results.push({ id, title, expected, actual: String(actual), ok: ok === true });

function call(method, path, claims, opts = {}) {
  const ts = opts.ts ?? Math.floor(Date.now() / 1000);
  const c = claims;
  const signedPath = opts.signedPath ?? path;
  const canonical = [method, signedPath, ts, c.user, c.role, c.ward, c.basis, c.session].join('|');
  let sig = crypto.createHmac('sha256', secret).update(canonical).digest('hex');
  if (opts.badSig) sig = sig.replace(/^./, sig[0] === '0' ? '1' : '0');
  const headers = { 'X-PEP-Timestamp': String(ts), 'X-PEP-Signature': sig, 'X-ZT-User': c.user, 'X-ZT-Role': c.role, 'X-ZT-Ward': c.ward, 'X-ZT-Basis': c.basis, 'X-ZT-Session': c.session };
  for (const h of opts.drop || []) delete headers[h];
  if (opts.unsigned) { delete headers['X-PEP-Signature']; delete headers['X-PEP-Timestamp']; }
  if (opts.body !== undefined) { headers['Content-Type'] = 'application/json'; headers['Content-Length'] = String(Buffer.byteLength(opts.body)); }
  return new Promise((resolve) => {
    const req = https.request({ host: url.hostname, port: url.port, method, path, headers, ca: [pem], checkServerIdentity: () => undefined, timeout: 15000 }, (res) => {
      let body = ''; res.on('data', (d) => { body += d; }); res.on('end', () => { let j = null; try { j = JSON.parse(body); } catch (e) { /* not json */ } resolve({ status: res.statusCode, text: body, json: j }); });
    });
    req.on('error', (e) => resolve({ status: 0, text: String(e), json: null }));
    req.end(opts.body);
  });
}
const claimsOf = (name, over = {}) => ({ user: users[name].user_id, role: users[name].role, ward: users[name].ward || '', basis: 'x', session: 'S-app-direct-test', ...over });
const keysOf = (j) => (j && typeof j === 'object' ? Object.keys(j).sort().join(',') : '');
const leaks = (text) => clin.filter((v) => v && text.includes(v)).length;

async function main() {
  const doc = claimsOf('dr_alice', { basis: 'assigned' }), nur = claimsOf('nurse_bob', { basis: 'ward' }), rec_ = claimsOf('front_carol', { basis: 'front_desk' }), adm = claimsOf('sec_dan', { basis: '' });
  const S = (c, p) => call('GET', p, c);

  // 1. receptionist
  let r1 = await S(rec_, '/api/patients/101/summary'), r2 = await S(rec_, '/api/patients/101/records'), r3 = await call('POST', '/api/patients/101/export-pdf', rec_), r4 = await S(rec_, '/api/patients/list');
  rec('AP1', 'Protected app, receptionist claims: demographics yes; records and export refused at the data layer; no clinical value in any body', 'summary 200 (no clinical fields), records 403, export 403, list 200 with 5 patients, 0 clinical values',
    `summary ${r1.status} [${keysOf(r1.json)}]; records ${r2.status}; export ${r3.status}; list ${r4.status} (${r4.json && r4.json.patients ? r4.json.patients.length : '-'}); clinical values leaked: ${leaks(r1.text + r2.text + r3.text + r4.text)}`,
    r1.status === 200 && !('diagnosis' in (r1.json || {})) && r2.status === 403 && r3.status === 403 && r4.status === 200 && r4.json.patients.length === 5 && leaks(r1.text + r2.text + r3.text + r4.text) === 0);

  // 2. nurse
  r1 = await S(nur, '/api/patients/101/records'); r2 = await S(nur, '/api/patients/102/summary'); r3 = await S(nur, '/api/patients/102/records'); r4 = await call('POST', '/api/patients/101/export-pdf', nur);
  const nl = await S(nur, '/api/patients/list');
  rec('AP2', 'Protected app, nurse (ward A) claims: own-ward record without diagnosis; other ward and export refused at the data layer', 'records 101 200 without diagnosis; 102 summary/records 403; export 403; list = 101,103,105',
    `records101 ${r1.status} [${keysOf(r1.json)}]; 102 summary ${r2.status}, records ${r3.status}; export ${r4.status}; list ${nl.json && nl.json.patients ? nl.json.patients.map((p) => p.patient_id).join(',') : nl.status}`,
    r1.status === 200 && !('diagnosis' in r1.json) && r2.status === 403 && r3.status === 403 && r4.status === 403 && nl.json && nl.json.patients.map((p) => p.patient_id).join(',') === '101,103,105');

  // 3. doctor
  r1 = await S(doc, '/api/patients/101/records'); r2 = await S(doc, '/api/patients/103/records');
  const forgedBasis = await S({ ...doc, basis: 'break_glass' }, '/api/patients/103/records');       // the basis CLAIM must not be believed: the grant table decides
  const dl = await S(doc, '/api/patients/list'); r3 = await call('POST', '/api/patients/103/export-pdf', doc);
  rec('AP3', 'Protected app, doctor claims: assigned record yes; unassigned refused even when the claim says "break_glass" (the grant table decides); list = assigned only', 'records 101 200 with diagnosis; 103 records 403 (also with forged basis); export 103 403; list = 101,102',
    `records101 ${r1.status} (diagnosis present: ${!!(r1.json && r1.json.diagnosis)}); 103 records ${r2.status}; forged basis ${forgedBasis.status}; export103 ${r3.status}; list ${dl.json && dl.json.patients ? dl.json.patients.map((p) => p.patient_id).join(',') : dl.status}`,
    r1.status === 200 && !!r1.json.diagnosis && r2.status === 403 && forgedBasis.status === 403 && r3.status === 403 && dl.json.patients.map((p) => p.patient_id).join(',') === '101,102');

  // 4. security administrator
  const ar = [await S(adm, '/api/patients/list'), await S(adm, '/api/patients/101/summary'), await S(adm, '/api/patients/101/records'), await call('POST', '/api/patients/101/export-pdf', adm)];
  rec('AP4', 'Protected app, security administrator claims: no patient data at all (list, summary, records, export)', 'four refusals, 0 clinical values', `${ar.map((x) => x.status).join(', ')}; clinical values leaked: ${leaks(ar.map((x) => x.text).join(' '))}`,
    ar.every((x) => x.status === 403) && leaks(ar.map((x) => x.text).join(' ')) === 0);

  // 5. signature, timestamp, path and header integrity
  const base = '/api/patients/101/summary';
  const bad = {
    'wrong signature': await call('GET', base, doc, { badSig: true }),
    'no signature': await call('GET', base, doc, { unsigned: true }),
    'stale timestamp (5 min)': await call('GET', base, doc, { ts: Math.floor(Date.now() / 1000) - 300 }),
    'signed for another path': await call('GET', '/api/patients/101/records', doc, { signedPath: base }),
    'identity header removed': await call('GET', base, doc, { drop: ['X-ZT-User'] })
  };
  // role header changed AFTER signing: signed as 'nurse', sent as 'doctor'
  const ts = Math.floor(Date.now() / 1000);
  const canonical = ['GET', base, ts, doc.user, 'nurse', doc.ward, doc.basis, doc.session].join('|');
  const sig = crypto.createHmac('sha256', secret).update(canonical).digest('hex');
  const tampered = await new Promise((resolve) => {
    const req = https.request({ host: url.hostname, port: url.port, method: 'GET', path: base, headers: { 'X-PEP-Timestamp': String(ts), 'X-PEP-Signature': sig, 'X-ZT-User': doc.user, 'X-ZT-Role': 'doctor', 'X-ZT-Ward': doc.ward, 'X-ZT-Basis': doc.basis, 'X-ZT-Session': doc.session }, ca: [pem], checkServerIdentity: () => undefined }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', () => resolve(0)); req.end();
  });
  bad['role changed after signing'] = { status: tampered };
  const notRefused = Object.entries(bad).filter(([, v]) => v.status !== 403).map(([k, v]) => `${k} -> ${v.status}`);
  rec('AP5', 'Protected app: a request whose signature, timestamp, path or identity headers were altered is refused', 'every altered request -> 403', `${Object.keys(bad).length} cases; not refused: [${notRefused.join(', ')}]`, notRefused.length === 0);

  // 6. identity claims that contradict the account (a PEP, or a stolen PEP key, vouching for the wrong role)
  const nurseAsDoctor = await S({ ...claimsOf('nurse_bob', { basis: 'assigned' }), role: 'doctor' }, '/api/patients/101/records');
  const recAsNurse = await S({ ...claimsOf('front_carol', { basis: 'ward' }), role: 'nurse', ward: 'A' }, '/api/patients/101/records');
  const nurseOtherWard = await S({ ...claimsOf('nurse_bob', { basis: 'ward' }), ward: 'B' }, '/api/patients/102/summary');
  rec('AP6', 'Protected app: claims that contradict the account in the database (role or ward) are refused, not believed', 'nurse account claiming role doctor -> 403; receptionist account claiming nurse/ward A -> 403; nurse account claiming ward B -> 403',
    `nurse as doctor ${nurseAsDoctor.status} (diagnosis leaked: ${!!(nurseAsDoctor.json && nurseAsDoctor.json.diagnosis)}); receptionist as nurse ${recAsNurse.status}; nurse claiming ward B ${nurseOtherWard.status}`,
    nurseAsDoctor.status === 403 && recAsNurse.status === 403 && nurseOtherWard.status === 403);

  // 8. appointment management at the data layer (the only write of the portal): receptionist claims only, strict validation, nothing else touched
  {
    const pad = (n) => String(n).padStart(2, '0');
    const stamp = (days, hh) => { const d = new Date(Date.now() + days * 86400000); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${hh}`; };
    const pid = 105;                                   // a ward-A patient; nobody else's test depends on its appointment
    const appt = (c, body, id = pid) => call('POST', `/api/patients/${id}/appointment`, c, { body: typeof body === 'string' ? body : JSON.stringify(body) });
    const before = await S(rec_, `/api/patients/${pid}/summary`);
    const docBefore = await S(doc, '/api/patients/101/records');
    const wanted = stamp(6, '10:00');
    const ok = await appt(rec_, { next_appointment: wanted });
    const after = await S(rec_, `/api/patients/${pid}/summary`);
    const refusedRoles = [['doctor', await appt({ ...doc }, { next_appointment: stamp(7, '10:00') })], ['nurse', await appt(nur, { next_appointment: stamp(7, '10:00') })], ['administrator', await appt(adm, { next_appointment: stamp(7, '10:00') })]];
    const forged = await appt({ ...claimsOf('nurse_bob', { basis: 'front_desk' }), role: 'receptionist' }, { next_appointment: stamp(7, '10:00') });      // a nurse account vouched for as a receptionist
    const afterRefusals = await S(rec_, `/api/patients/${pid}/summary`);
    rec('AP8', 'Protected app, appointment change: only receptionist claims may change the next appointment; doctor, nurse, administrator and a nurse account claiming to be a receptionist are refused at the data layer and nothing is written',
      'receptionist 200 and the summary shows the new time; doctor/nurse/administrator/forged claims 403; the stored time is unchanged by the refusals',
      `receptionist ${ok.status} (new time stored: ${after.json && after.json.next_appointment === wanted}); refused: ${refusedRoles.map(([n, r]) => n + ' ' + r.status).join(', ')}; forged ${forged.status}; unchanged after refusals: ${afterRefusals.json && afterRefusals.json.next_appointment === wanted}`,
      ok.status === 200 && after.json && after.json.next_appointment === wanted && refusedRoles.every(([, r]) => r.status === 403) && forged.status === 403 && afterRefusals.json.next_appointment === wanted);

    const originalValue = before.json && before.json.next_appointment;
    const badBodies = { 'past date': { next_appointment: '2020-01-01 10:00' }, 'more than 12 months': { next_appointment: stamp(400, '10:00') }, 'impossible date': { next_appointment: '2026-13-45 99:99' }, 'wrong format': { next_appointment: 'next tuesday' },
      'ISO with T': { next_appointment: stamp(8, '10:00').replace(' ', 'T') }, 'number': { next_appointment: 20261013 }, 'null': { next_appointment: null }, 'array': { next_appointment: [stamp(8, '10:00')] }, 'missing field': { note: 'x' }, 'empty object': {}, 'not JSON': '{oops', 'oversized body': { next_appointment: 'x'.repeat(5000) } };
    const accepted = [];
    for (const [name, body] of Object.entries(badBodies)) { const r = await appt(rec_, body); if (r.status !== 400 && r.status !== 413) accepted.push(`${name} -> ${r.status}`); }
    const unknown = await appt(rec_, { next_appointment: stamp(8, '10:00') }, 999);
    const afterBad = await S(rec_, `/api/patients/${pid}/summary`);
    rec('AP9', 'Protected app, appointment validation: past dates, dates beyond 12 months, impossible dates, wrong formats and types, missing fields, malformed JSON and oversized bodies are all refused (400) and change nothing; an unknown patient is 404',
      '12 invalid inputs -> 400/413, none stored; patient 999 -> 404', `accepted: [${accepted.join(', ')}]; unknown patient ${unknown.status}; stored time still the valid one: ${afterBad.json && afterBad.json.next_appointment === wanted}`,
      accepted.length === 0 && unknown.status === 404 && afterBad.json && afterBad.json.next_appointment === wanted);

    const restore = originalValue ? await appt(rec_, { next_appointment: originalValue }) : { status: 'skipped' };   // put the demonstration data back (a past original is refused by design: then it stays at the test value)
    const docAfter = await S(doc, '/api/patients/101/records');
    const sumAfter = await S(rec_, `/api/patients/${pid}/summary`);
    const sameOther = before.json && sumAfter.json && ['name', 'dob', 'ward', 'patient_id'].every((k) => before.json[k] === sumAfter.json[k]);
    rec('AP10', 'Protected app, appointment change writes only the appointment: name, date of birth, ward and every clinical value are unchanged, and the response carries no clinical field',
      'identity fields equal before/after; the doctor\'s clinical record of another patient unchanged; the change response has only patient_id, next_appointment, message', `identity unchanged: ${sameOther}; clinical record unchanged: ${JSON.stringify(docBefore.json) === JSON.stringify(docAfter.json)}; response fields: [${keysOf(ok.json)}]; leaks: ${leaks(ok.text)}; restore ${restore.status}`,
      !!sameOther && JSON.stringify(docBefore.json) === JSON.stringify(docAfter.json) && keysOf(ok.json) === 'message,next_appointment,patient_id' && leaks(ok.text) === 0);
  }

  // 7. break-glass at the data layer: only the patient, only the creating session, never export
  if (env.ZT_BG_SESSION && env.ZT_BG_PATIENT) {
    const p = env.ZT_BG_PATIENT; const other = '103';          // a patient this session holds NO grant for
    const same = await S({ ...doc, basis: 'break_glass', session: env.ZT_BG_SESSION }, `/api/patients/${p}/records`);
    const otherPatient = await S({ ...doc, basis: 'break_glass', session: env.ZT_BG_SESSION }, `/api/patients/${other}/records`);
    const exp = await call('POST', `/api/patients/${p}/export-pdf`, { ...doc, basis: 'break_glass', session: env.ZT_BG_SESSION });
    const otherSession = await S({ ...doc, basis: 'break_glass', session: 'S-another-session-of-the-same-doctor' }, `/api/patients/${p}/records`);
    rec('AP7', 'Protected app, emergency access: the granted patient only, in the session that asked for it, and never the export (SSN/billing)', `patient ${p} records 200; patient ${other} 403; export 403; same doctor in another session 403`,
      `granted patient ${same.status}; other patient ${otherPatient.status}; export ${exp.status} (ssn present: ${!!(exp.json && exp.json.ssn)}); other session ${otherSession.status}`,
      same.status === 200 && otherPatient.status === 403 && exp.status === 403 && otherSession.status === 403);
  }
}
main().catch((e) => rec('AP0', 'The direct app test ran to the end', 'no exception', e && e.stack || e, false)).finally(() => { process.stdout.write('RESULT_JSON:' + JSON.stringify(results) + '\n'); });
