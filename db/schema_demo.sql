-- Zero Trust Hospital Portal - demo schema (SQLite). Used ONLY for new, disposable databases; db/schema.sql (legacy) is unchanged.
-- The PDP owns users, devices, sessions, policy, grants and security events; the Protected App owns patients and assignments.
-- Both processes use the same file in WAL mode (SQLite handles concurrent readers; each process serialises its own writes).
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    user_id             TEXT PRIMARY KEY,
    username            TEXT NOT NULL UNIQUE,
    display_name        TEXT NOT NULL,
    password_hash       TEXT NOT NULL,         -- pbkdf2-sha256$iterations$salt$hash (salted, slow KDF)
    step_up_pin_hash    TEXT NOT NULL,         -- same format; second factor for STEP_UP decisions
    role                TEXT NOT NULL CHECK (role IN ('doctor','nurse','receptionist','security_admin')),
    ward                TEXT,                  -- nurses: the ward they may access
    locked_until        INTEGER NOT NULL DEFAULT 0,
    lock_reason         TEXT,
    failed_logins       INTEGER NOT NULL DEFAULT 0,
    failed_window_start INTEGER NOT NULL DEFAULT 0,
    created_at          INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

-- kind 'agent'  : laptop running the C++ posture agent; posture is MEASURED by the agent and signed (HMAC) per heartbeat.
-- kind 'browser': phone or any browser; the page reports what a browser can observe (SELF-REPORTED), the rest is SIMULATED.
CREATE TABLE IF NOT EXISTS devices (
    device_id            TEXT PRIMARY KEY,
    kind                 TEXT NOT NULL DEFAULT 'agent' CHECK (kind IN ('agent','browser')),
    hostname             TEXT NOT NULL,
    os                   TEXT NOT NULL,
    firewall_active      INTEGER NOT NULL DEFAULT 0,
    antivirus_active     INTEGER NOT NULL DEFAULT 0,
    agent_simulated      INTEGER NOT NULL DEFAULT 0,   -- the agent was started with a --fake-* demo flag
    last_heartbeat_ts    INTEGER,
    last_signature_valid INTEGER NOT NULL DEFAULT 0,
    signals_json         TEXT,                          -- browser-reported signals
    sim_screen_lock      INTEGER NOT NULL DEFAULT 1,    -- SIMULATED (a browser cannot measure these)
    sim_os_current       INTEGER NOT NULL DEFAULT 1,
    sim_protection       INTEGER NOT NULL DEFAULT 1,
    created_at           INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS endpoints (
    endpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
    method      TEXT NOT NULL,
    path        TEXT NOT NULL,          -- pattern: numeric segments are '*'
    sensitivity INTEGER NOT NULL,
    UNIQUE(method, path)
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role        TEXT NOT NULL,
    endpoint_id INTEGER NOT NULL REFERENCES endpoints(endpoint_id),
    PRIMARY KEY (role, endpoint_id)
);

CREATE TABLE IF NOT EXISTS patients (
    patient_id        INTEGER PRIMARY KEY,
    name              TEXT NOT NULL,
    dob               TEXT NOT NULL,
    ward              TEXT NOT NULL,
    next_appointment  TEXT,
    diagnosis         TEXT,
    medication        TEXT,
    care_notes        TEXT,
    ssn_encrypted     TEXT,
    billing_encrypted TEXT,
    created_at        INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS patient_assignments (
    user_id    TEXT NOT NULL REFERENCES users(user_id),
    patient_id INTEGER NOT NULL REFERENCES patients(patient_id),
    PRIMARY KEY (user_id, patient_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id     TEXT PRIMARY KEY,
    device_id      TEXT NOT NULL REFERENCES devices(device_id),
    user_id        TEXT NOT NULL REFERENCES users(user_id),
    origin_ip      TEXT,
    sim_ip         TEXT,                                -- SIMULATED network override (demo control)
    created_at     INTEGER NOT NULL,
    last_seen_ts   INTEGER NOT NULL,                    -- last protected request (heartbeats do not count)
    risk_points    INTEGER NOT NULL DEFAULT 0,          -- accumulated session risk; reaching the threshold revokes the session
    last_score     INTEGER NOT NULL DEFAULT 0,          -- last per-request risk score
    status         TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','REVOKED','LOGGED_OUT','EXPIRED')),
    revoked_at     INTEGER,
    revoked_by     TEXT,
    revoke_reason  TEXT,
    grants_used    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS security_events (
    event_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           INTEGER NOT NULL,
    type         TEXT NOT NULL,           -- DECISION, LOGIN_OK, LOGIN_FAIL, LOGIN_BLOCKED, LOGOUT, SESSION_REVOKED, LOCKOUT, UNLOCK, BREAK_GLASS, POLICY_CHANGE, SIMULATION, ADMIN_ACTION
    session_id   TEXT,
    user_id      TEXT,
    username     TEXT,
    role         TEXT,
    device_id    TEXT,
    origin_ip    TEXT,
    method       TEXT,
    path         TEXT,
    decision     TEXT,                    -- ALLOW, STEP_UP, DENY, REVOKE (or NULL for non-decision events)
    code         TEXT,                    -- machine-readable reason (role_denied, not_assigned, session_revoked, ...)
    risk_score   INTEGER,
    risk_delta   INTEGER,
    session_risk INTEGER,
    reason       TEXT NOT NULL,
    details      TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_session_ts ON security_events(session_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_ts ON security_events(ts);

CREATE TABLE IF NOT EXISTS break_glass_grants (
    grant_id      TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(user_id),
    session_id    TEXT NOT NULL,
    patient_id    INTEGER NOT NULL,
    justification TEXT NOT NULL,
    created_ts    INTEGER NOT NULL,
    expires_ts    INTEGER NOT NULL,
    status        TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','REVOKED')),
    revoked_by    TEXT
);

CREATE TABLE IF NOT EXISTS policy_settings (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    json       TEXT NOT NULL,
    updated_ts INTEGER NOT NULL,
    updated_by TEXT NOT NULL
);

-- Endpoint catalogue: sensitivity feeds the risk score; role_permissions is the hard RBAC gate (checked before any risk scoring).
INSERT OR IGNORE INTO endpoints (method, path, sensitivity) VALUES
    ('GET',  '/api/public/info',            0),
    ('GET',  '/api/patients/list',          10),
    ('GET',  '/api/patients/*/summary',     10),
    ('GET',  '/api/patients/*/records',     30),
    ('POST', '/api/patients/*/export-pdf',  60),
    ('POST', '/api/patients/*/appointment', 20),
    ('GET',  '/ctl/session',                0),
    ('GET',  '/ctl/policy',                 0),
    ('POST', '/ctl/heartbeat',              0),
    ('POST', '/ctl/renew',                  0),
    ('POST', '/ctl/logout',                 0),
    ('POST', '/ctl/simulate',               5),
    ('POST', '/ctl/break-glass',            35),
    ('GET',  '/admin/summary',              10),
    ('GET',  '/admin/sessions',             20),
    ('POST', '/admin/sessions/revoke',      30),
    ('GET',  '/admin/devices',              20),
    ('GET',  '/admin/events',               20),
    ('GET',  '/admin/policy',               10),
    ('POST', '/admin/policy/set',           40),
    ('GET',  '/admin/grants',               20),
    ('POST', '/admin/grants/revoke',        30),
    ('GET',  '/admin/users',                20),
    ('POST', '/admin/unlock',               30);

-- every role: public info and its own session functions (a user's own thresholds come with /ctl/session)
INSERT OR IGNORE INTO role_permissions (role, endpoint_id)
    SELECT r.role, e.endpoint_id FROM (SELECT 'doctor' AS role UNION SELECT 'nurse' UNION SELECT 'receptionist' UNION SELECT 'security_admin') r, endpoints e
    WHERE e.path IN ('/api/public/info','/ctl/session','/ctl/heartbeat','/ctl/renew','/ctl/logout','/ctl/simulate');
-- clinical staff
INSERT OR IGNORE INTO role_permissions (role, endpoint_id)
    SELECT r.role, e.endpoint_id FROM (SELECT 'doctor' AS role UNION SELECT 'nurse' UNION SELECT 'receptionist') r, endpoints e
    WHERE e.path IN ('/api/patients/list','/api/patients/*/summary');
INSERT OR IGNORE INTO role_permissions (role, endpoint_id)
    SELECT r.role, e.endpoint_id FROM (SELECT 'doctor' AS role UNION SELECT 'nurse') r, endpoints e
    WHERE e.path IN ('/api/patients/*/records');
INSERT OR IGNORE INTO role_permissions (role, endpoint_id)
    SELECT 'doctor', endpoint_id FROM endpoints WHERE path IN ('/api/patients/*/export-pdf','/ctl/break-glass');
-- appointment management (reschedule the next appointment): reception staff only; no clinical role and not the administrator
INSERT OR IGNORE INTO role_permissions (role, endpoint_id)
    SELECT 'receptionist', endpoint_id FROM endpoints WHERE path = '/api/patients/*/appointment';
-- security administrator: security management only, NO clinical endpoint; the full policy is theirs alone
INSERT OR IGNORE INTO role_permissions (role, endpoint_id)
    SELECT 'security_admin', endpoint_id FROM endpoints WHERE path LIKE '/admin/%' OR path = '/ctl/policy';
-- upgrade of databases created by an earlier version of this file: clinical roles lose /ctl/policy (idempotent)
DELETE FROM role_permissions WHERE role <> 'security_admin' AND endpoint_id IN (SELECT endpoint_id FROM endpoints WHERE path = '/ctl/policy');
