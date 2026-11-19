-- Zero Trust Access Simulator - Relational Schema (SQLite)
-- Core state for the Policy Decision Point (PDP): devices, endpoints, policies,
-- sessions, and the risk_events audit log that drives the live SOC dashboard.

PRAGMA foreign_keys = ON;

-- Devices: one row per client machine running the C++ posture agent.
-- Continuously updated by PIP telemetry ingestion every heartbeat (~2s).
CREATE TABLE IF NOT EXISTS devices (
    device_id           TEXT PRIMARY KEY,
    hostname            TEXT NOT NULL,
    os                  TEXT NOT NULL,
    firewall_active     INTEGER NOT NULL DEFAULT 0,   -- boolean 0/1
    antivirus_active    INTEGER NOT NULL DEFAULT 0,   -- boolean 0/1
    last_heartbeat_ts    INTEGER,                      -- unix epoch seconds
    last_signature_valid INTEGER NOT NULL DEFAULT 0,   -- boolean 0/1
    created_at          INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

-- Endpoints: sensitivity classification for each protected route.
-- path is a PATTERN, not a literal route: numeric id segments are '*'
-- (e.g. '/api/patients/*/records' matches '/api/patients/103/records').
-- The PDP normalizes an incoming concrete path to its pattern (regex-replace
-- \d+ segments with '*') before this lookup. Looked up when scoring a
-- request's Data Sensitivity vector.
CREATE TABLE IF NOT EXISTS endpoints (
    endpoint_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    method           TEXT NOT NULL,
    path             TEXT NOT NULL,
    sensitivity      INTEGER NOT NULL,     -- 0-60 per spec
    UNIQUE(method, path)
);

-- Users: identity pillar. Roles gate WHICH endpoints are reachable at all;
-- risk score (device/network/behavior/assignment) then gates HOW that access
-- is served (full / masked / denied) on top of the role gate. Both must agree.
-- step_up_pin_hash backs the concrete second factor for the STEP_UP decision
-- (the PDP prompts for this PIN before issuing an elevated-trust token).
CREATE TABLE IF NOT EXISTS users (
    user_id          TEXT PRIMARY KEY,
    username         TEXT NOT NULL UNIQUE,
    password_hash    TEXT NOT NULL,        -- SHA-256 hex digest
    step_up_pin_hash TEXT NOT NULL,        -- SHA-256 hex digest of the step-up PIN
    role             TEXT NOT NULL CHECK (role IN ('doctor','nurse','receptionist','auditor')),
    created_at       INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

-- Patients: the actual protected data the Protected App serves. SSN and
-- billing are stored encrypted (AES, app-held key - see protected_app) and
-- are only decrypted server-side when the PDP decision is ALLOW; STEP_UP
-- responses get masked values instead of a decrypt attempt.
CREATE TABLE IF NOT EXISTS patients (
    patient_id        INTEGER PRIMARY KEY,
    name              TEXT NOT NULL,
    dob               TEXT NOT NULL,
    diagnosis         TEXT,
    medication        TEXT,
    ssn_encrypted     TEXT,      -- base64 AES ciphertext
    billing_encrypted TEXT,      -- base64 AES ciphertext
    created_at        INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

-- Patient assignments: which doctor/nurse is the assigned caregiver for a
-- patient. NOT a hard access gate - accessing an unassigned patient is
-- allowed (real hospitals need break-glass access for emergencies/coverage)
-- but is fed into the risk score as an "assignment mismatch" vector, so it
-- raises risk and typically forces STEP_UP + a logged reason rather than
-- being silently allowed or silently blocked.
CREATE TABLE IF NOT EXISTS patient_assignments (
    user_id     TEXT NOT NULL REFERENCES users(user_id),
    patient_id  INTEGER NOT NULL REFERENCES patients(patient_id),
    PRIMARY KEY (user_id, patient_id)
);

-- Role permissions: explicit RBAC gate. If no row exists for (role, endpoint),
-- that role cannot reach that endpoint at ANY risk score - least privilege
-- is enforced independently of, and before, the dynamic risk calculation.
CREATE TABLE IF NOT EXISTS role_permissions (
    role         TEXT NOT NULL,
    endpoint_id  INTEGER NOT NULL REFERENCES endpoints(endpoint_id),
    PRIMARY KEY (role, endpoint_id)
);

-- Policies: named risk-threshold bands and the action they map to.
-- Kept as data (not hardcoded if/else) so the ABAC ruleset is auditable/editable.
CREATE TABLE IF NOT EXISTS policies (
    policy_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL UNIQUE,
    min_risk      INTEGER NOT NULL,
    max_risk      INTEGER NOT NULL,        -- exclusive upper bound
    action        TEXT NOT NULL CHECK (action IN ('ALLOW','STEP_UP','DENY')),
    description   TEXT
);

-- Sessions: one row per active device/user session tracked by the PDP.
-- status is checked on EVERY /pdp/evaluate call (not just at token issue),
-- so a SOC operator terminating a session from the dashboard takes effect
-- on the very next request - no waiting for token expiry.
CREATE TABLE IF NOT EXISTS sessions (
    session_id         TEXT PRIMARY KEY,
    device_id          TEXT NOT NULL REFERENCES devices(device_id),
    user_id            TEXT NOT NULL REFERENCES users(user_id),
    origin_ip          TEXT,                 -- IP at login; mid-session change spikes risk
    created_at         INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    last_seen_ts       INTEGER,
    current_risk_score INTEGER NOT NULL DEFAULT 0,
    status             TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','TERMINATED')),
    terminated_by      TEXT,                 -- 'SYSTEM' (auto) or a SOC user_id (manual kill)
    terminated_reason  TEXT
);

-- Risk events: append-only audit log. One row per PDP evaluation.
-- This is the table the live dashboard event stream and the "kill test" read from.
-- device_id deliberately has NO foreign key: this table must be able to log
-- a request that CLAIMS a device_id nobody ever registered (a fabricated
-- id, or a request that arrived before telemetry ever ran) - that is
-- exactly the kind of event a security audit log needs to capture, so a
-- fail-closed DENY can never be blocked from being logged by a constraint
-- on the very data proving something suspicious happened.
CREATE TABLE IF NOT EXISTS risk_events (
    event_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id     TEXT,
    device_id      TEXT,
    endpoint_id    INTEGER REFERENCES endpoints(endpoint_id),
    request_method TEXT NOT NULL,
    request_path   TEXT NOT NULL,
    risk_score     INTEGER NOT NULL,
    decision       TEXT NOT NULL CHECK (decision IN ('ALLOW','STEP_UP','DENY')),
    reason         TEXT NOT NULL,
    ts             INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE INDEX IF NOT EXISTS idx_risk_events_device_ts ON risk_events(device_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_risk_events_session ON risk_events(session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_device ON sessions(device_id);

-- Seed data: endpoint sensitivity map (path = pattern, '*' is a wildcard id segment)
INSERT OR IGNORE INTO endpoints (method, path, sensitivity) VALUES
    ('GET',  '/api/public/info', 0),
    ('GET',  '/api/patients/list', 20),
    ('GET',  '/api/patients/*/records', 40),
    ('POST', '/api/patients/*/export-pdf', 60),
    ('GET',  '/api/audit/events', 10);

-- Seed data: policy thresholds
INSERT OR IGNORE INTO policies (name, min_risk, max_risk, action, description) VALUES
    ('allow_full',   0,  40,  'ALLOW',   'Low combined risk - full access granted'),
    ('step_up_mfa',  40, 70,  'STEP_UP', 'Moderate risk - require step-up verification / mask sensitive fields'),
    ('deny_hard',    70, 1000,'DENY',    'High risk - request denied, security event logged');

-- Seed data: demo users, one per role.
-- Password for all demo accounts: Demo@123 (SHA-256 hex digest, column 3)
-- Step-up PIN for all demo accounts: 2468   (SHA-256 hex digest, column 4)
-- Both hashed with the same scheme the PDP's auth code uses (plain SHA-256 -
-- fine for a demo; a real system would salt + use a slow KDF like bcrypt/argon2).
INSERT OR IGNORE INTO users (user_id, username, password_hash, step_up_pin_hash, role) VALUES
    ('U-DOC-001',  'dr_alice',   'ff96673205dc722320598ebf8f88325b2ac56922d5a2164b5765868274bc0d73', 'a1fb4e703a9ef1fa4936801721ff285a97ac85330856674412e054892afe6972', 'doctor'),
    ('U-NUR-001',  'nurse_bob',  'ff96673205dc722320598ebf8f88325b2ac56922d5a2164b5765868274bc0d73', 'a1fb4e703a9ef1fa4936801721ff285a97ac85330856674412e054892afe6972', 'nurse'),
    ('U-REC-001',  'front_carol','ff96673205dc722320598ebf8f88325b2ac56922d5a2164b5765868274bc0d73', 'a1fb4e703a9ef1fa4936801721ff285a97ac85330856674412e054892afe6972', 'receptionist'),
    ('U-AUD-001',  'audit_dan',  'ff96673205dc722320598ebf8f88325b2ac56922d5a2164b5765868274bc0d73', 'a1fb4e703a9ef1fa4936801721ff285a97ac85330856674412e054892afe6972', 'auditor');

-- Seed data: role -> endpoint access gate (RBAC, independent of risk score)
INSERT OR IGNORE INTO role_permissions (role, endpoint_id)
    SELECT 'doctor', endpoint_id FROM endpoints WHERE path IN
        ('/api/public/info','/api/patients/list','/api/patients/*/records','/api/patients/*/export-pdf');
INSERT OR IGNORE INTO role_permissions (role, endpoint_id)
    SELECT 'nurse', endpoint_id FROM endpoints WHERE path IN
        ('/api/public/info','/api/patients/list','/api/patients/*/records');
INSERT OR IGNORE INTO role_permissions (role, endpoint_id)
    SELECT 'receptionist', endpoint_id FROM endpoints WHERE path IN
        ('/api/public/info','/api/patients/list');
INSERT OR IGNORE INTO role_permissions (role, endpoint_id)
    SELECT 'auditor', endpoint_id FROM endpoints WHERE path IN
        ('/api/public/info','/api/audit/events');

-- NOTE: `patients` and `patient_assignments` are intentionally NOT seeded
-- here. ssn_encrypted/billing_encrypted must be produced with the Protected
-- App's own AES key, so the Protected App seeds demo patient rows itself on
-- first startup (see protected_app's PatientSeeder) rather than this script
-- inserting values it cannot correctly encrypt. Demo dataset it creates:
--   101 Grace Kim     (assigned: dr_alice, nurse_bob)
--   102 Marcus Lee     (assigned: dr_alice)
--   103 Priya Nair      (assigned: nurse_bob only - NOT dr_alice, used to
--                        demo the assignment-mismatch / break-glass risk vector)
--   104 Tom Alvarez    (unassigned to anyone - used for the same demo)
