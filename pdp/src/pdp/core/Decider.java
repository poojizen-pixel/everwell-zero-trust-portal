package pdp.core;

import pdp.crypto.PasswordHasher;
import pdp.crypto.TokenService;
import pdp.db.Database;
import pdp.policy.Policy;
import pdp.policy.PolicyStore;

import java.net.InetAddress;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// The single policy decision function. Every protected request - patient data, session functions and administration - goes through
// decide(), in this fixed order; the first failing check ends the evaluation (fail closed):
//   token -> session state -> account lock / idle / absolute timeout -> endpoint known -> role (RBAC) -> managed-device rule
//   -> device posture -> network change -> patient scope (assignment / ward / break-glass) -> risk score and band -> step-up PIN.
// Denied and suspicious requests add penalty points to the SESSION; reaching the revoke threshold ends the session on the server
// and locks the account for a while. The token carries no role: role, ward and assignments are always read from the database.
public class Decider {
    private static final Pattern DIGITS = Pattern.compile("\\d+");
    private static final Pattern PATIENT = Pattern.compile("^/api/patients/(\\d{1,9})/(summary|records|export-pdf|appointment)$");
    // Functions the user needs even while the device is blocked (to see why, to send a fresh heartbeat, to sign out, to reset the simulation).
    private static final Set<String> EXEMPT = new HashSet<>(Arrays.asList("/ctl/session", "/ctl/heartbeat", "/ctl/logout", "/ctl/policy", "/ctl/simulate"));
    // Calls the page makes on a timer are not user activity: they never reset the idle timer, and when the DEVICE STATE forces a refusal of a
    // renewal nobody has done anything suspicious (the device simply no longer qualifies), so that refusal adds no risk. A wrong step-up PIN
    // sent with a renewal is still penalised, so the renewal endpoint cannot be used to guess the PIN for free.
    private static final Set<String> BACKGROUND = new HashSet<>(Arrays.asList("/ctl/renew", "/ctl/heartbeat"));
    private static final Set<String> STATE_DENIALS = new HashSet<>(Arrays.asList("posture_blocked", "risk_too_high", "network_blocked"));
    private static final List<String> RANK = Arrays.asList("ALLOW", "STEP_UP", "DENY", "REVOKE");
    private static final DateTimeFormatter HHMM = DateTimeFormatter.ofPattern("HH:mm").withZone(ZoneId.systemDefault());

    private final Database db;
    private final TokenService tokens;
    private final PolicyStore policies;
    private final EventLog events;
    private final SessionService sessions;
    private final DeviceService devices;
    private final ScopeService scope;
    private final Map<String, ArrayDeque<Long>> recent = new ConcurrentHashMap<>();

    public Decider(Database db, TokenService tokens, PolicyStore policies, EventLog events, SessionService sessions, DeviceService devices, ScopeService scope) {
        this.db = db;
        this.tokens = tokens;
        this.policies = policies;
        this.events = events;
        this.sessions = sessions;
        this.devices = devices;
        this.scope = scope;
    }

    private static final class Net {
        String change = "none", action = "ALLOW";
        int score;
    }

    public Decision decide(DecisionRequest r) {
        long now = System.currentTimeMillis() / 1000;
        Policy pol = policies.current();
        Decision d = new Decision();
        d.threshold = pol.session.revokeThreshold;

        // 1. token (signature, expiry, device binding)
        TokenService.TokenClaims claims;
        try {
            claims = tokens.verify(r.token, r.deviceId, r.allowGrace ? pol.tokens.renewGraceSeconds : 0);
        } catch (TokenService.TokenException e) {
            d.deny(401, e.code, "token_missing".equals(e.code) ? "Sign in required."
                    : "Your sign-in is no longer accepted (" + e.getMessage() + "). Please sign in again.");
            logDecision(r, d, null, now);
            return d;
        }

        // 2. server-side session state
        SessionService.Row s = sessions.load(claims.sessionId);
        if (s == null) {
            d.deny(401, "session_unknown", "This session does not exist. Please sign in again.");
            logDecision(r, d, null, now);
            return d;
        }
        Principal p = new Principal();
        p.userId = s.userId; p.username = s.username; p.displayName = s.displayName; p.role = s.role; p.ward = s.ward;
        p.sessionId = s.sessionId; p.deviceId = s.deviceId; p.ip = r.clientIp;
        d.principal = p;
        d.detail = "security_admin".equals(s.role) || pol.simulation.enabled;      // need-to-know for risk figures (see Decision.detail)
        d.sessionRisk = s.riskPoints;
        if (!"ACTIVE".equals(s.status)) {
            String code = "REVOKED".equals(s.status) ? "session_revoked" : "LOGGED_OUT".equals(s.status) ? "session_ended" : "session_expired";
            d.deny(401, code, "This session is no longer valid" + (s.revokeReason == null ? "" : " (" + s.revokeReason + ")") + ". Please sign in again.");
            d.sessionRevoked = true;
            logDecision(r, d, p, now);
            return d;
        }
        if (s.lockedUntil > now) {
            sessions.end(s.sessionId, "REVOKED", "SYSTEM", "account locked: " + s.lockReason, now);
            d.deny(423, "account_locked", "This account is locked until " + HHMM.format(Instant.ofEpochSecond(s.lockedUntil)) + " (" + s.lockReason + ").");
            d.sessionRevoked = true;
            logDecision(r, d, p, now);
            return d;
        }
        if (now - s.lastSeen > pol.session.idleTimeoutSeconds) {
            sessions.end(s.sessionId, "EXPIRED", "SYSTEM", "idle timeout (" + pol.session.idleTimeoutSeconds + " s)", now);
            d.deny(401, "session_expired", "Your session expired after " + (pol.session.idleTimeoutSeconds / 60) + " minutes without activity. Please sign in again.");
            d.sessionRevoked = true;
            logDecision(r, d, p, now);
            return d;
        }
        if (now - s.createdAt > pol.session.absoluteTimeoutSeconds) {
            sessions.end(s.sessionId, "EXPIRED", "SYSTEM", "maximum session length reached", now);
            d.deny(401, "session_expired", "Your session reached its maximum length. Please sign in again.");
            d.sessionRevoked = true;
            logDecision(r, d, p, now);
            return d;
        }

        // 3. endpoint known? (the path is normalised: numeric segments become '*'; anything else must match exactly)
        String pattern = DIGITS.matcher(r.path).replaceAll("*");
        int[] ep = endpoint(r.method, pattern);
        if (ep == null) {
            d.deny(404, "unknown_endpoint", "Unknown or unsupported request.");
            d.penalty = pol.penalties.unknownEndpoint;
            return conclude(r, d, s, p, pol, now);
        }
        boolean exempt = EXEMPT.contains(r.path);

        // 4. role-based access control: a hard gate before any scoring
        if (!roleAllowed(p.role, ep[0])) {
            d.deny(403, "role_denied", "Access denied: your role (" + roleLabel(p.role) + ") is not permitted to use this function.");
            d.penalty = pol.penalties.roleDenied;
            return conclude(r, d, s, p, pol, now);
        }
        DeviceService.Row dev = devices.load(s.deviceId);
        if (pol.admin.requireManagedDevice && r.path.startsWith("/admin/") && (dev == null || !"agent".equals(dev.kind))) {
            d.deny(403, "managed_device_required", "Administrative functions are only available from an agent-verified laptop (policy admin.require_managed_device).");
            d.penalty = pol.penalties.postureBlocked;
            return conclude(r, d, s, p, pol, now);
        }

        // 5. device posture
        DeviceService.Posture post = devices.evaluate(dev, r.clientIp, now, pol);
        if (post.blocked && !exempt) {
            if ("REVOKE".equals(pol.device.onBlocked)) {
                revokeByPolicy(d, s, p, now, "device no longer meets the policy - " + post.blockReason);
                return conclude(r, d, s, p, pol, now);
            }
            d.deny(403, "posture_blocked", "Access denied: this device does not currently meet the security policy - " + post.blockReason + ".");
            d.penalty = pol.penalties.postureBlocked;
            d.breakdown = "device blocked";
            return conclude(r, d, s, p, pol, now);
        }

        // 6. network change relative to the session baseline (a SIMULATED address, when set, replaces the real one for evaluation)
        String effIp = (s.simIp != null && !s.simIp.isEmpty()) ? s.simIp : r.clientIp;
        Net net = evalNetwork(s.originIp, effIp, pol);
        if (!exempt && "REVOKE".equals(net.action) && !"none".equals(net.change)) {
            revokeByPolicy(d, s, p, now, "network changed (" + s.originIp + " -> " + effIp + ") and the policy requires a new sign-in");
            return conclude(r, d, s, p, pol, now);
        }

        // 7. patient scope: assignment / ward / break-glass, decided on the server before any data is fetched
        Matcher pm = PATIENT.matcher(r.path);
        if (pm.matches() && !exempt) {
            ScopeService.Result sr = scope.authorize(p, Integer.parseInt(pm.group(1)), now);
            if (!sr.allowed) {
                d.deny("not_found".equals(sr.code) ? 404 : 403, sr.code, sr.message);
                d.penalty = "not_assigned".equals(sr.code) ? pol.penalties.notAssigned : "ward_denied".equals(sr.code) ? pol.penalties.wardDenied
                        : "not_found".equals(sr.code) ? pol.penalties.notFound : pol.penalties.roleDenied;
                return conclude(r, d, s, p, pol, now);
            }
            // Emergency access lets a doctor READ the summary and the clinical record of that one patient; the export (the only response that
            // decrypts SSN and billing) stays reserved for a doctor who is assigned to the patient.
            if ("break_glass".equals(sr.basis) && r.path.endsWith("/export-pdf")) {
                d.deny(403, "export_not_permitted", "Emergency access allows reading this patient's summary and clinical record, not exporting it. Only a doctor assigned to the patient can export.");
                d.penalty = pol.penalties.notAssigned;
                return conclude(r, d, s, p, pol, now);
            }
            p.basis = sr.basis;
            p.grantId = sr.grantId;
        }

        // 8. risk score and band
        int burst = exempt ? 0 : burstScore(s.sessionId, pol);
        int score = post.score + net.score + burst + sensitivity(ep[0]);
        d.riskScore = score;
        d.breakdown = "device=" + post.score + " (" + post.label + "), network=" + net.score + " (" + net.change + "), burst=" + burst
                + ", endpoint=" + sensitivity(ep[0]) + " -> total " + score + " (allow below " + pol.bands.allowBelow + ", step-up below " + pol.bands.stepUpBelow + ")";
        if (burst > 0) d.penalty += pol.penalties.burst;

        String band = score < pol.bands.allowBelow ? "ALLOW" : score < pol.bands.stepUpBelow ? "STEP_UP" : "DENY";
        String action = exempt ? "ALLOW" : rank(band) >= rank(net.action) ? band : net.action;
        boolean networkReason = !exempt && !"none".equals(net.change) && rank(net.action) > 0 && rank(net.action) >= rank(action);

        if ("DENY".equals(action)) {
            if (networkReason) {
                d.deny(403, "network_blocked", "Access denied: your network changed (" + s.originIp + " -> " + effIp + ") and the policy does not allow access from the new network.");
                d.penalty += pol.penalties.networkDenied;
            } else {
                d.deny(403, "risk_too_high", "Access denied: the risk score " + score + " is above the allowed limit (" + (pol.bands.stepUpBelow - 1) + ").");
                d.penalty += pol.penalties.riskTooHigh;
            }
            return conclude(r, d, s, p, pol, now);
        }
        if ("STEP_UP".equals(action)) {
            String why = networkReason ? "your network changed (" + s.originIp + " -> " + effIp + ")" : "the risk score " + score + " is in the step-up band";
            if (r.stepUpPin == null || r.stepUpPin.isEmpty()) {
                d.action = "STEP_UP"; d.httpStatus = 401; d.code = "step_up_required";
                d.message = "Additional verification required: " + why + ". Enter your step-up PIN.";
                return conclude(r, d, s, p, pol, now);
            }
            if (!verifyPin(p.userId, r.stepUpPin)) {
                d.deny(403, "bad_step_up_pin", "The step-up PIN is incorrect.");
                d.penalty += pol.penalties.badStepUpPin;
                return conclude(r, d, s, p, pol, now);
            }
            if (!"none".equals(net.change) && pol.network.rebindAfterStepUp) sessions.setOrigin(s.sessionId, effIp);
            d.message = "allowed after step-up verification (" + why + ")";
        } else {
            d.message = "allowed";
        }
        d.action = "ALLOW";
        d.httpStatus = 200;
        d.code = "ok";
        return conclude(r, d, s, p, pol, now);
    }

    // For callers outside decide() (the gateway) that found a request suspicious after it passed the policy: same accounting and revocation rules.
    public Decision penalize(DecisionRequest r, Principal p, int points, int status, String code, String message) {
        long now = System.currentTimeMillis() / 1000;
        Policy pol = policies.current();
        Decision d = new Decision();
        d.threshold = pol.session.revokeThreshold;
        d.principal = p;
        d.detail = "security_admin".equals(p.role) || pol.simulation.enabled;
        d.deny(status, code, message);
        d.penalty = points;
        SessionService.Row s = sessions.load(p.sessionId);
        if (s == null) return d;
        d.sessionRisk = s.riskPoints;
        return conclude(r, d, s, p, pol, now);
    }

    // {change, action, score} of the network comparison, for the session status view.
    public String[] networkInfo(String origin, String eff, Policy pol) {
        Net n = evalNetwork(origin, eff, pol);
        return new String[]{n.change, n.action, String.valueOf(n.score)};
    }

    // Accumulates penalty points, revokes at the threshold, records the decision.
    private Decision conclude(DecisionRequest r, Decision d, SessionService.Row s, Principal p, Policy pol, long now) {
        if (d.penalty > 0 && "/ctl/renew".equals(r.path) && STATE_DENIALS.contains(d.code)) d.penalty = 0;
        if (d.penalty > 0) {
            d.sessionRisk = sessions.addRisk(s.sessionId, d.penalty);
            if (d.sessionRisk >= pol.session.revokeThreshold && !d.sessionRevoked) revokeByRisk(d, s, p, pol, now);
        }
        if (!BACKGROUND.contains(r.path)) sessions.touch(s.sessionId, now, d.riskScore);
        logDecision(r, d, p, now);
        return d;
    }

    private void revokeByRisk(Decision d, SessionService.Row s, Principal p, Policy pol, long now) {
        String cause = d.code;
        String reason = "risk threshold reached (" + d.sessionRisk + " >= " + pol.session.revokeThreshold + ") after repeated denied or suspicious requests; last: " + cause;
        sessions.end(s.sessionId, "REVOKED", "SYSTEM", reason, now);
        long until = 0;
        if (pol.session.lockoutMinutes > 0) {
            until = now + pol.session.lockoutMinutes * 60L;
            sessions.lockUser(s.userId, until, reason);
        }
        EventLog.Event e = new EventLog.Event("SESSION_REVOKED").who(p);
        e.decision = "REVOKE"; e.code = "risk_threshold"; e.riskDelta = d.penalty; e.sessionRisk = d.sessionRisk; e.reason = reason;
        events.record(e);
        if (until > 0) {
            EventLog.Event l = new EventLog.Event("LOCKOUT").who(p);
            l.code = "account_locked"; l.reason = "account " + s.username + " locked until " + HHMM.format(Instant.ofEpochSecond(until)) + " (" + reason + ")";
            events.record(l);
        }
        d.sessionRevoked = true;
        d.action = "DENY";
        d.httpStatus = 401;
        d.code = "session_revoked";
        d.message = "Your session was revoked: " + reason + "." + (until > 0 ? " Your account is locked until " + HHMM.format(Instant.ofEpochSecond(until)) + "." : "") + " Please sign in again.";
    }

    private void revokeByPolicy(Decision d, SessionService.Row s, Principal p, long now, String why) {
        sessions.end(s.sessionId, "REVOKED", "POLICY", why, now);
        EventLog.Event e = new EventLog.Event("SESSION_REVOKED").who(p);
        e.decision = "REVOKE"; e.code = "policy_revocation"; e.reason = why;
        events.record(e);
        d.sessionRevoked = true;
        d.deny(401, "session_revoked", "Your session was revoked: " + why + ". Please sign in again.");
    }

    private void logDecision(DecisionRequest r, Decision d, Principal p, long now) {
        boolean audited = r.path.startsWith("/api/patients/") || r.path.equals("/ctl/break-glass") || r.path.equals("/ctl/simulate")
                || ("POST".equals(r.method) && r.path.startsWith("/admin/"));
        if (d.allowed() && !audited) return;       // routine polling (heartbeat, session status, dashboard refresh) is not logged
        EventLog.Event e = new EventLog.Event("DECISION").who(p);
        if (p == null) { e.deviceId = r.deviceId; e.ip = r.clientIp; }
        e.method = r.method; e.path = r.path; e.decision = d.action; e.code = d.code;
        e.riskScore = d.riskScore; e.riskDelta = d.penalty; e.sessionRisk = d.sessionRisk;
        e.reason = d.message; e.details = d.breakdown;
        if (p != null && !p.basis.isEmpty()) e.details = (e.details == null ? "" : e.details + "; ") + "basis=" + p.basis + (p.grantId.isEmpty() ? "" : " (" + p.grantId + ")");
        events.record(e);
    }

    private Net evalNetwork(String origin, String eff, Policy pol) {
        Net n = new Net();
        if (origin == null || origin.isEmpty() || DeviceService.normalize(origin).equals(DeviceService.normalize(eff))) return n;
        if (subnet(origin).equals(subnet(eff))) {
            n.change = "same_subnet"; n.score = pol.network.sameSubnetScore; n.action = pol.network.sameSubnetAction;
        } else {
            n.change = "different_subnet"; n.score = pol.network.differentSubnetScore; n.action = pol.network.differentSubnetAction;
        }
        return n;
    }

    static String subnet(String ip) {
        try {
            byte[] b = InetAddress.getByName(ip.split("%")[0]).getAddress();
            if (b.length == 4) return (b[0] & 255) + "." + (b[1] & 255) + "." + (b[2] & 255) + ".0/24";
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8; i++) sb.append(String.format("%02x", b[i]));
            return sb + "::/64";
        } catch (Exception e) {
            return ip;
        }
    }

    private int burstScore(String sessionId, Policy pol) {
        long nowMs = System.currentTimeMillis();
        ArrayDeque<Long> q = recent.computeIfAbsent(sessionId, k -> new ArrayDeque<>());
        synchronized (q) {
            long cutoff = nowMs - pol.behavior.burstWindowSeconds * 1000L;
            while (!q.isEmpty() && q.peekFirst() < cutoff) q.pollFirst();
            q.addLast(nowMs);
            return q.size() > pol.behavior.burstLimit ? pol.behavior.burstScore : 0;
        }
    }

    private int[] endpoint(String method, String pattern) {
        return db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("SELECT endpoint_id, sensitivity FROM endpoints WHERE method = ? AND path = ?")) {
                ps.setString(1, method); ps.setString(2, pattern);
                try (ResultSet rs = ps.executeQuery()) { return rs.next() ? new int[]{rs.getInt(1), rs.getInt(2)} : null; }
            }
        });
    }

    private int sensitivity(int endpointId) {
        return db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("SELECT sensitivity FROM endpoints WHERE endpoint_id = ?")) {
                ps.setInt(1, endpointId);
                try (ResultSet rs = ps.executeQuery()) { return rs.next() ? rs.getInt(1) : 0; }
            }
        });
    }

    private boolean roleAllowed(String role, int endpointId) {
        return db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("SELECT 1 FROM role_permissions WHERE role = ? AND endpoint_id = ?")) {
                ps.setString(1, role); ps.setInt(2, endpointId);
                try (ResultSet rs = ps.executeQuery()) { return rs.next(); }
            }
        });
    }

    private boolean verifyPin(String userId, String pin) {
        String h = db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("SELECT step_up_pin_hash FROM users WHERE user_id = ?")) {
                ps.setString(1, userId);
                try (ResultSet rs = ps.executeQuery()) { return rs.next() ? rs.getString(1) : null; }
            }
        });
        return h != null && PasswordHasher.verify(pin, h);
    }

    private static int rank(String action) { return RANK.indexOf(action); }

    public static String roleLabel(String role) {
        switch (role) {
            case "doctor": return "doctor";
            case "nurse": return "nurse";
            case "receptionist": return "receptionist";
            case "security_admin": return "security administrator";
            default: return role;
        }
    }

    public static String hhmm(long epochSeconds) { return HHMM.format(Instant.ofEpochSecond(epochSeconds)); }
}
