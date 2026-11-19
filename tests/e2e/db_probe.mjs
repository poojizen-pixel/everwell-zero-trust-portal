// Read-only look at the disposable run database (never the legacy db\ folder): what the role/permission tables actually contain and which
// clinical values exist, so that tests can scan API responses for them. Uses Node's built-in SQLite in READ-ONLY mode; prints JSON only.
// usage: node db_probe.mjs <path to run\db\zero_trust.db> <permissions|assignments|clinical|users|columns>
import { DatabaseSync } from 'node:sqlite';

const [, , dbPath, mode] = process.argv;
if (!dbPath || !mode) { console.error('usage: node db_probe.mjs <db> <mode>'); process.exit(2); }
if (/[\\/]db[\\/]zero_trust\.db$/i.test(dbPath) && !/zt-demo/i.test(dbPath)) { console.error('refusing: this is not a disposable run database'); process.exit(2); }
const db = new DatabaseSync(dbPath, { readOnly: true });
const all = (sql) => db.prepare(sql).all().map((r) => ({ ...r }));
let out;
switch (mode) {
  case 'permissions':
    out = all(`SELECT rp.role AS role, e.method AS method, e.path AS path, e.sensitivity AS sensitivity FROM role_permissions rp JOIN endpoints e ON e.endpoint_id = rp.endpoint_id ORDER BY rp.role, e.path, e.method`);
    break;
  case 'assignments':
    out = all(`SELECT u.username AS username, u.role AS role, u.ward AS ward, a.patient_id AS patient_id FROM patient_assignments a JOIN users u ON u.user_id = a.user_id ORDER BY u.username, a.patient_id`);
    break;
  case 'clinical':
    // plain-text clinical columns (used only to scan responses for leaks) + whether the identifiers are stored encrypted (never printed)
    out = all(`SELECT patient_id, name, dob, ward, next_appointment, diagnosis, medication, care_notes,
                      length(ssn_encrypted) AS ssn_len, length(billing_encrypted) AS billing_len,
                      substr(ssn_encrypted, 1, 3) = '' AS ssn_blank FROM patients ORDER BY patient_id`);
    break;
  case 'users':
    out = all(`SELECT user_id, username, role, ward, substr(password_hash, 1, instr(password_hash, '$') - 1) AS password_kdf,
                      substr(step_up_pin_hash, 1, instr(step_up_pin_hash, '$') - 1) AS pin_kdf FROM users ORDER BY username`);
    break;
  case 'columns':
    out = {};
    for (const t of ['users', 'patients', 'patient_assignments', 'break_glass_grants', 'sessions', 'security_events']) out[t] = all(`PRAGMA table_info(${t})`).map((c) => c.name);
    break;
  default:
    console.error('unknown mode'); process.exit(2);
}
console.log(JSON.stringify(out));
