package pdp.http.handlers;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import pdp.Config;
import pdp.core.Decider;
import pdp.core.Decision;
import pdp.core.DecisionRequest;
import pdp.core.DeviceService;
import pdp.core.EventLog;
import pdp.core.Principal;
import pdp.core.ScopeService;
import pdp.core.SessionService;
import pdp.crypto.PasswordHasher;
import pdp.crypto.TokenService;
import pdp.db.Database;
import pdp.http.HttpUtil;
import pdp.policy.Policy;
import pdp.policy.PolicyStore;

import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

// POST /pdp/gateway - the control plane. The PEP wraps every /ctl/* and /admin/* request in an envelope
// {client_ip, device_id, authorization, method, path, query, body, step_up_pin} and relays the answer {status, body}.
// Sign-in and the list of reporting laptops are the only functions that need no session; every other function runs through
// Decider.decide() first (token, session, role, posture, network, risk), then performs its action with the principal the SERVER loaded.
public class GatewayHandler implements HttpHandler {
    private static final Pattern DEVICE_ID = Pattern.compile("^[A-Za-z0-9._:-]{6,80}$");
    private static final Pattern IP_LITERAL = Pattern.compile("^[0-9a-fA-F:.]{3,45}$");

    private final Database db;
    private final Decider decider;
    private final PolicyStore policies;
    private final SessionService sessions;
    private final DeviceService devices;
    private final ScopeService scope;
    private final EventLog events;
    private final TokenService tokens;
    private final Map<String, long[]> ipFailures = new ConcurrentHashMap<>();   // client ip -> {failures, window start}

    public GatewayHandler(Database db, Decider decider, PolicyStore policies, SessionService sessions, DeviceService devices, ScopeService scope,
                          EventLog events, TokenService tokens) {
        this.db = db; this.decider = decider; this.policies = policies; this.sessions = sessions; this.devices = devices;
        this.scope = scope; this.events = events; this.tokens = tokens;
    }

    private static final class Res {
        final int status;
        final JsonObject body;
        Res(int status, JsonObject body) { this.status = status; this.body = body; }
    }

    private static Res ok(JsonObject body) { return new Res(200, body); }

    private static Res err(int status, String code, String message) {
        JsonObject o = new JsonObject();
        o.addProperty("error", code);
        o.addProperty("message", message);
        return new Res(status, o);
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        Res res;
        try {
            res = route(exchange);
        } catch (Exception e) {
            res = err(500, "internal_error", "The request could not be processed (fail closed).");
        }
        JsonObject out = new JsonObject();
        out.addProperty("status", res.status);
        out.add("body", res.body);
        HttpUtil.sendJson(exchange, 200, out);
    }

    private Res route(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) return err(405, "method_not_allowed", "POST only.");
        JsonObject env;
        try {
            env = HttpUtil.readJsonBody(exchange);
        } catch (Exception e) {
            return err(400, "bad_request", "Malformed request.");
        }
        String method = HttpUtil.str(env, "method"), path = HttpUtil.str(env, "path"), ip = HttpUtil.str(env, "client_ip");
        if (method == null || path == null || ip == null || path.length() > 256) return err(400, "bad_request", "Malformed request.");
        String deviceId = HttpUtil.str(env, "device_id");
        String bodyText = HttpUtil.str(env, "body");
        String auth = HttpUtil.str(env, "authorization");

        if (method.equals("POST") && path.equals("/ctl/login")) return login(bodyText, ip, deviceId);
        if (method.equals("GET") && path.equals("/ctl/agents")) {
            JsonObject o = new JsonObject();
            // The laptop's device id and host name are offered only to a client that is on the laptop itself (that is where the sign-in screen
            // needs them); anyone else asking before sign-in learns nothing about the machine.
            o.add("agents", devices.isLocalAddress(ip) ? devices.freshAgents(System.currentTimeMillis() / 1000, policies.current()) : new JsonArray());
            return ok(o);
        }

        DecisionRequest r = new DecisionRequest();
        r.method = method; r.path = path; r.query = HttpUtil.str(env, "query") == null ? "" : HttpUtil.str(env, "query");
        r.clientIp = ip; r.deviceId = deviceId == null ? "" : deviceId; r.stepUpPin = HttpUtil.str(env, "step_up_pin");
        r.token = auth != null && auth.startsWith("Bearer ") ? auth.substring(7) : null;
        r.allowGrace = path.equals("/ctl/renew");
        Decision d = decider.decide(r);
        if (!d.allowed()) return new Res(d.httpStatus, d.toErrorBody());

        Principal p = d.principal;
        long now = System.currentTimeMillis() / 1000;
        Policy pol = policies.current();
        JsonObject body = new JsonObject();
        if ("POST".equals(method) && bodyText != null && !bodyText.isEmpty()) {
            try {
                body = JsonParser.parseString(bodyText).getAsJsonObject();
            } catch (Exception e) {
                return new Res(400, decider.penalize(r, p, pol.penalties.badRequest, 400, "bad_request", "The request body is not valid JSON.").toErrorBody());
            }
        }
        switch (method + " " + path) {
            case "GET /ctl/session": return session(p, pol, now, ip);
            case "GET /ctl/policy": { JsonObject o = new JsonObject(); o.add("policy", policies.currentJson()); return ok(o); }
            case "POST /ctl/heartbeat": return heartbeat(p, body, now);
            case "POST /ctl/renew": return renew(p, ip, pol);
            case "POST /ctl/logout": return logout(p, now);
            case "POST /ctl/simulate": return simulate(p, body, pol);
            case "POST /ctl/break-glass": return breakGlass(r, p, body, pol, now);
            case "GET /admin/summary": return summary(now);
            case "GET /admin/sessions": { JsonObject o = new JsonObject(); o.add("sessions", sessions.list(100)); o.addProperty("server_time", now); return ok(o); }
            case "POST /admin/sessions/revoke": return adminRevoke(p, body, now);
            case "GET /admin/devices": return adminDevices(now, pol);
            case "GET /admin/events": return adminEvents(r.query);
            case "GET /admin/policy": { JsonObject o = new JsonObject(); o.add("policy", policies.currentJson()); return ok(o); }
            case "POST /admin/policy/set": return policySet(p, body);
            case "GET /admin/grants": { JsonObject o = new JsonObject(); o.add("grants", scope.grants(now)); return ok(o); }
            case "POST /admin/grants/revoke": return grantRevoke(p, body);
            case "GET /admin/users": { JsonObject o = new JsonObject(); o.add("users", sessions.users()); return ok(o); }
            case "POST /admin/unlock": return unlock(p, body);
            default: return err(404, "unknown_endpoint", "Unknown or unsupported request.");
        }
    }

    // ---- sign-in ------------------------------------------------------------------------------------------------------------

    private Res login(String bodyText, String ip, String deviceId) {
        long now = System.currentTimeMillis() / 1000;
        Policy pol = policies.current();
        JsonObject b;
        try {
            b = JsonParser.parseString(bodyText == null ? "{}" : bodyText).getAsJsonObject();
        } catch (Exception e) {
            return err(400, "bad_request", "Malformed sign-in request.");
        }
        String username = HttpUtil.str(b, "username"), password = HttpUtil.str(b, "password");
        String kind = HttpUtil.str(b, "device_kind");
        String label = HttpUtil.str(b, "device_label");
        if (username == null || password == null || deviceId == null || kind == null || !DEVICE_ID.matcher(deviceId).matches()
                || username.length() > 64 || password.length() > 200 || !(kind.equals("agent") || kind.equals("browser"))) {
            return err(400, "bad_request", "Username, password, device and device kind are required.");
        }
        long[] ipf = ipFailures.get(ip);
        if (ipf != null && now - ipf[1] <= pol.login.windowSeconds && ipf[0] >= pol.login.maxFailures * 4L) {
            return err(429, "rate_limited", "Too many failed sign-in attempts from this address. Try again later.");
        }

        String[] u = loadUser(username);  // {user_id, password_hash, display_name, role, ward, locked_until, lock_reason, failed_logins, failed_window_start}
        // The password is checked FIRST, also for a locked account: only someone who knows it is told that the account is locked and why.
        // Anybody else gets the same answer as for a wrong password or an unknown user (no account or lock-state enumeration).
        boolean good;
        if (u == null) { PasswordHasher.burn(password); good = false; } else good = PasswordHasher.verify(password, u[1]);
        if (u != null && Long.parseLong(u[5]) > now) {
            EventLog.Event e = new EventLog.Event(good ? "LOGIN_BLOCKED" : "LOGIN_FAIL");
            e.userId = u[0]; e.username = username; e.role = u[3]; e.deviceId = deviceId; e.ip = ip; e.code = good ? "account_locked" : "invalid_credentials";
            if (!good) {
                ipFailures.compute(ip, (k, v) -> (v == null || now - v[1] > pol.login.windowSeconds) ? new long[]{1, now} : new long[]{v[0] + 1, v[1]});
                e.decision = "DENY";
                e.reason = "sign-in failed for '" + trim(username, 40) + "' (wrong password; the account is also locked until " + Decider.hhmm(Long.parseLong(u[5])) + ")";
                events.record(e);
                return err(401, "invalid_credentials", "Invalid username or password.");
            }
            e.reason = "sign-in refused: account locked until " + Decider.hhmm(Long.parseLong(u[5])) + " (" + u[6] + ")";
            events.record(e);
            JsonObject o = new JsonObject();
            o.addProperty("error", "account_locked");
            // the reason of a risk lock quotes scores and limits: only the administrator (and, while the evaluation tools are on, the account owner) is told
            boolean showWhy = "security_admin".equals(u[3]) || pol.simulation.enabled;
            o.addProperty("message", "This account is temporarily locked until " + Decider.hhmm(Long.parseLong(u[5])) + (showWhy ? " (" + u[6] + ")" : "") + ". Wait or ask a security administrator to unlock it.");
            o.addProperty("locked_until", Long.parseLong(u[5]));
            return new Res(423, o);
        }
        if (!good) {
            recordLoginFailure(u, username, deviceId, ip, pol, now);
            return err(401, "invalid_credentials", "Invalid username or password.");
        }
        if (u != null) resetFailures(u[0]);

        DeviceService.Row dev;
        if (kind.equals("agent")) {
            dev = devices.load(deviceId);
            if (dev == null || !"agent".equals(dev.kind)) {
                loginBlocked(u, username, deviceId, ip, "no posture agent is reporting for device " + deviceId);
                return err(403, "posture_blocked", "Sign-in refused: no posture agent is reporting for this laptop. Start the agent and try again.");
            }
        } else {
            JsonObject sg = new JsonObject();
            if (b.has("signals") && b.get("signals").isJsonObject()) sg = sanitizeSignals(b.getAsJsonObject("signals"));
            String os = HttpUtil.str(b, "platform") == null ? "browser" : trim(HttpUtil.str(b, "platform"), 40);
            if (!devices.upsertBrowser(deviceId, browserLabel(label), os, sg.toString(), now)) {
                loginBlocked(u, username, deviceId, ip, "browser tried to use the id of a measured laptop");
                return err(403, "posture_blocked", "Sign-in refused: this device id belongs to a measured laptop.");
            }
            dev = devices.load(deviceId);
        }
        DeviceService.Posture post = devices.evaluate(dev, ip, now, pol);
        if (post.blocked) {
            loginBlocked(u, username, deviceId, ip, post.blockReason);
            return err(403, "posture_blocked", "Sign-in refused: this device does not currently meet the security policy - " + post.blockReason + ".");
        }

        String sid = sessions.create(u[0], deviceId, ip, now);
        String token = tokens.issue(sid, u[0], deviceId, ip, pol.tokens.ttlSeconds);
        EventLog.Event e = new EventLog.Event("LOGIN_OK");
        e.sessionId = sid; e.userId = u[0]; e.username = username; e.role = u[3]; e.deviceId = deviceId; e.ip = ip; e.decision = "ALLOW"; e.code = "ok";
        e.sessionRisk = 0;
        e.reason = "signed in as " + username + " (" + u[3] + ") on " + dev.kind + " device " + deviceId + " from " + ip;
        events.record(e);

        JsonObject o = new JsonObject();
        o.addProperty("token", token);
        o.addProperty("expires_in", pol.tokens.ttlSeconds);
        o.addProperty("session_id", sid);
        JsonObject user = new JsonObject();
        user.addProperty("username", username); user.addProperty("display_name", u[2]); user.addProperty("role", u[3]); user.addProperty("ward", u[4]);
        o.add("user", user);
        return ok(o);
    }

    private void loginBlocked(String[] u, String username, String deviceId, String ip, String why) {
        EventLog.Event e = new EventLog.Event("LOGIN_BLOCKED");
        e.userId = u == null ? null : u[0]; e.username = username; e.role = u == null ? null : u[3]; e.deviceId = deviceId; e.ip = ip;
        e.decision = "DENY"; e.code = "posture_blocked"; e.reason = "sign-in refused: " + why;
        events.record(e);
    }

    private String[] loadUser(String username) {
        return db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT user_id, password_hash, display_name, role, COALESCE(ward,''), locked_until, COALESCE(lock_reason,''), failed_logins, failed_window_start FROM users WHERE username = ?")) {
                ps.setString(1, username);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) return null;
                    String[] a = new String[9];
                    for (int i = 0; i < 9; i++) a[i] = rs.getString(i + 1);
                    return a;
                }
            }
        });
    }

    private void recordLoginFailure(String[] u, String username, String deviceId, String ip, Policy pol, long now) {
        long[] f = ipFailures.compute(ip, (k, v) -> (v == null || now - v[1] > pol.login.windowSeconds) ? new long[]{1, now} : new long[]{v[0] + 1, v[1]});
        EventLog.Event e = new EventLog.Event("LOGIN_FAIL");
        e.userId = u == null ? null : u[0]; e.username = username; e.deviceId = deviceId; e.ip = ip; e.decision = "DENY"; e.code = "invalid_credentials";
        e.reason = "sign-in failed for '" + trim(username, 40) + "' (" + (u == null ? "unknown user" : "wrong password") + "), attempts from this address in the window: " + f[0];
        events.record(e);
        if (u == null) return;
        long start = Long.parseLong(u[8]);
        int count = Integer.parseInt(u[7]);
        if (now - start > pol.login.windowSeconds) { count = 0; start = now; }
        count++;
        final int c = count;
        final long st = start;
        db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("UPDATE users SET failed_logins = ?, failed_window_start = ? WHERE user_id = ?")) {
                ps.setInt(1, c); ps.setLong(2, st); ps.setString(3, u[0]); ps.executeUpdate();
            }
            return null;
        });
        if (count >= pol.login.maxFailures) {
            long until = now + pol.login.lockoutMinutes * 60L;
            sessions.lockUser(u[0], until, "too many failed sign-ins");
            resetFailures(u[0]);
            EventLog.Event l = new EventLog.Event("LOCKOUT");
            l.userId = u[0]; l.username = username; l.role = u[3]; l.ip = ip; l.code = "account_locked";
            l.reason = "account " + username + " locked until " + Decider.hhmm(until) + " after " + count + " failed sign-ins";
            events.record(l);
        }
    }

    private void resetFailures(String userId) {
        db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("UPDATE users SET failed_logins = 0, failed_window_start = 0 WHERE user_id = ?")) {
                ps.setString(1, userId); ps.executeUpdate();
            }
            return null;
        });
    }

    // ---- session functions --------------------------------------------------------------------------------------------------

    // The caller's OWN session, shaped by need-to-know. Every role gets what it needs to work: who it is, when the session must end (idle and
    // maximum length), the emergency-access rules (doctors), whether evaluation tools are on, and the server's clock. The risk points, the
    // device posture and the network addresses of the session are returned only to the security administrator and, for other roles, only while
    // the administrator has left the evaluation tools enabled (policy simulation.enabled): "detail" says which of the two answers this is.
    private Res session(Principal p, Policy pol, long now, String clientIp) {
        SessionService.Row s = sessions.load(p.sessionId);
        boolean admin = "security_admin".equals(p.role);
        boolean detail = admin || pol.simulation.enabled;
        JsonObject o = new JsonObject();
        JsonObject user = new JsonObject();
        user.addProperty("username", s.username); user.addProperty("display_name", s.displayName); user.addProperty("role", s.role); user.addProperty("ward", s.ward == null ? "" : s.ward);
        o.add("user", user);
        JsonObject ses = new JsonObject();
        ses.addProperty("created_at", s.createdAt);
        ses.addProperty("idle_timeout_seconds", pol.session.idleTimeoutSeconds);
        ses.addProperty("absolute_expires_at", s.createdAt + pol.session.absoluteTimeoutSeconds);
        if (detail) {
            ses.addProperty("session_id", s.sessionId); ses.addProperty("risk_points", s.riskPoints);
            ses.addProperty("revoke_threshold", pol.session.revokeThreshold); ses.addProperty("last_score", s.lastScore); ses.addProperty("status", s.status);
            ses.addProperty("lockout_minutes", pol.session.lockoutMinutes);
        }
        o.add("session", ses);
        if (detail) {
            DeviceService.Row dev = devices.load(s.deviceId);
            DeviceService.Posture post = devices.evaluate(dev, clientIp, now, pol);
            String eff = (s.simIp != null && !s.simIp.isEmpty()) ? s.simIp : clientIp;
            String[] net = decider.networkInfo(s.originIp, eff, pol);
            JsonObject dv = new JsonObject();
            dv.addProperty("device_id", s.deviceId); dv.addProperty("kind", dev == null ? "unknown" : dev.kind); dv.addProperty("label", dev == null ? "" : dev.hostname);
            dv.addProperty("posture", post.label); dv.addProperty("score", post.score); dv.addProperty("block_reason", post.blockReason);
            dv.addProperty("heartbeat_age", dev == null || dev.heartbeat <= 0 ? -1 : Math.max(0, now - dev.heartbeat));
            dv.addProperty("stale_after_seconds", dev != null && "agent".equals(dev.kind) ? pol.device.laptopStaleSeconds : pol.device.phoneStaleSeconds);
            dv.add("signals", post.signals);
            o.add("device", dv);
            JsonObject nw = new JsonObject();
            nw.addProperty("origin_ip", s.originIp); nw.addProperty("simulated_ip", s.simIp == null ? "" : s.simIp); nw.addProperty("effective_ip", eff);
            nw.addProperty("change", net[0]); nw.addProperty("action", net[1]); nw.addProperty("score", Integer.parseInt(net[2]));
            nw.addProperty("checked_at", now);
            o.add("network", nw);
        }
        o.add("policy", admin ? policies.currentJson() : userPolicy(pol, p.role, detail));
        o.addProperty("token_ttl_seconds", pol.tokens.ttlSeconds);
        o.addProperty("simulation_enabled", pol.simulation.enabled);
        o.addProperty("server_time", now);
        o.addProperty("detail", detail ? "full" : "limited");
        return ok(o);
    }

    // What a signed-in clinical user needs: the emergency-access rules (doctors only) and the idle limit. While the evaluation tools are on, also
    // the bands, the revoke threshold and the lockout, so the evaluation screens can explain the user's own risk status. Penalty weights, device
    // and network scoring and login rules are for the security administrator.
    private static JsonObject userPolicy(Policy pol, String role, boolean detail) {
        JsonObject o = new JsonObject();
        JsonObject ses = new JsonObject();
        ses.addProperty("idle_timeout_seconds", pol.session.idleTimeoutSeconds);
        if (detail) {
            JsonObject bands = new JsonObject();
            bands.addProperty("allow_below", pol.bands.allowBelow); bands.addProperty("step_up_below", pol.bands.stepUpBelow);
            o.add("bands", bands);
            ses.addProperty("revoke_threshold", pol.session.revokeThreshold); ses.addProperty("lockout_minutes", pol.session.lockoutMinutes);
        }
        o.add("session", ses);
        if ("doctor".equals(role)) {
            JsonObject bg = new JsonObject();
            bg.addProperty("enabled", pol.breakGlass.enabled); bg.addProperty("duration_seconds", pol.breakGlass.durationSeconds);
            bg.addProperty("min_justification_chars", pol.breakGlass.minJustificationChars); bg.addProperty("max_grants_per_session", pol.breakGlass.maxGrantsPerSession);
            o.add("break_glass", bg);
        }
        return o;
    }

    private Res heartbeat(Principal p, JsonObject body, long now) {
        DeviceService.Row dev = devices.load(p.deviceId);
        if (dev == null || !"browser".equals(dev.kind)) return err(400, "not_applicable", "Heartbeats are only used by browser devices; a laptop is reported by its posture agent.");
        JsonObject sg = sanitizeSignals(body.has("signals") && body.get("signals").isJsonObject() ? body.getAsJsonObject("signals") : new JsonObject());
        devices.upsertBrowser(p.deviceId, dev.hostname, dev.os, sg.toString(), now);
        JsonObject o = new JsonObject();
        o.addProperty("ok", true);
        o.addProperty("server_time", now);
        return ok(o);
    }

    private static JsonObject sanitizeSignals(JsonObject in) {
        JsonObject out = new JsonObject();
        for (String k : new String[]{"secure_context", "standalone", "online", "visible"}) {
            if (in.has(k) && in.get(k).isJsonPrimitive() && in.get(k).getAsJsonPrimitive().isBoolean()) out.addProperty(k, in.get(k).getAsBoolean());
        }
        for (String k : new String[]{"connection", "platform"}) {
            if (in.has(k) && in.get(k).isJsonPrimitive()) out.addProperty(k, trim(in.get(k).getAsString().replaceAll("[^A-Za-z0-9 ._-]", "?"), 40));
        }
        return out;
    }

    private static String trim(String s, int max) { return s.length() <= max ? s : s.substring(0, max); }

    // The page names the kind of browser it runs in (from its user agent); only these three names are kept, so a client cannot label itself
    // "Registered laptop" or write free text into the administrator's device list. Anything else is just "Browser".
    private static String browserLabel(String label) {
        if ("Phone browser".equals(label) || "Tablet browser".equals(label) || "Desktop browser".equals(label)) return label;
        if ("Web browser".equals(label)) return "Desktop browser";      // pages served before the labels were refined
        return "Browser";
    }

    private Res renew(Principal p, String ip, Policy pol) {
        SessionService.Row s = sessions.load(p.sessionId);
        String token = tokens.issue(p.sessionId, p.userId, p.deviceId, s.originIp == null ? ip : s.originIp, pol.tokens.ttlSeconds);
        JsonObject o = new JsonObject();
        o.addProperty("token", token);
        o.addProperty("expires_in", pol.tokens.ttlSeconds);
        return ok(o);
    }

    private Res logout(Principal p, long now) {
        sessions.end(p.sessionId, "LOGGED_OUT", p.username, "user signed out", now);
        EventLog.Event e = new EventLog.Event("LOGOUT").who(p);
        e.decision = "ALLOW"; e.code = "ok"; e.reason = "user " + p.username + " signed out";
        events.record(e);
        JsonObject o = new JsonObject();
        o.addProperty("ok", true);
        return ok(o);
    }

    // ---- demo controls (clearly labelled SIMULATED) -------------------------------------------------------------------------

    private Res simulate(Principal p, JsonObject b, Policy pol) {
        if (!pol.simulation.enabled) return err(403, "simulation_disabled", "Simulation controls are disabled by policy (simulation.enabled).");
        String kind = HttpUtil.str(b, "kind");
        EventLog.Event e = new EventLog.Event("SIMULATION").who(p);
        e.decision = "ALLOW"; e.code = "simulation";
        if ("network".equals(kind)) {
            String ip = HttpUtil.str(b, "ip");
            if (ip == null || ip.equals("reset") || ip.isEmpty()) {
                sessions.setSimIp(p.sessionId, null);
                e.reason = "SIMULATED network override removed";
            } else {
                if (!IP_LITERAL.matcher(ip).matches()) return err(400, "bad_request", "Not an IP address.");
                sessions.setSimIp(p.sessionId, ip);
                e.reason = "SIMULATED network change: the server now evaluates this session as coming from " + ip;
            }
            events.record(e);
            return ok(okBody());
        }
        if ("posture".equals(kind)) {
            DeviceService.Row dev = devices.load(p.deviceId);
            if (dev == null || !"browser".equals(dev.kind)) {
                return err(400, "not_simulatable", "This device's posture is MEASURED by the posture agent; it cannot be simulated here. Use the agent's --fake-* switches instead.");
            }
            devices.setSim(p.deviceId, bool(b, "screen_lock"), bool(b, "os_current"), bool(b, "protection"));
            e.reason = "SIMULATED phone posture changed: screen_lock=" + b.get("screen_lock") + " os_current=" + b.get("os_current") + " protection=" + b.get("protection");
            events.record(e);
            return ok(okBody());
        }
        return err(400, "bad_request", "kind must be 'network' or 'posture'.");
    }

    private static Boolean bool(JsonObject b, String k) {
        return b.has(k) && b.get(k).isJsonPrimitive() && b.get(k).getAsJsonPrimitive().isBoolean() ? b.get(k).getAsBoolean() : null;
    }

    private static JsonObject okBody() { JsonObject o = new JsonObject(); o.addProperty("ok", true); return o; }

    // ---- break-glass --------------------------------------------------------------------------------------------------------

    private Res breakGlass(DecisionRequest r, Principal p, JsonObject b, Policy pol, long now) {
        if (!pol.breakGlass.enabled) return err(403, "break_glass_disabled", "Break-glass access is disabled by policy.");
        // patient_id must be a whole number in range: no fractions, no values that wrap around to another id when truncated to 32 bits
        Integer pid = null;
        if (b.has("patient_id") && b.get("patient_id").isJsonPrimitive() && b.get("patient_id").getAsJsonPrimitive().isNumber()) {
            java.math.BigDecimal bd = b.get("patient_id").getAsBigDecimal();
            if (bd.signum() > 0 && bd.stripTrailingZeros().scale() <= 0 && bd.compareTo(java.math.BigDecimal.valueOf(999_999_999L)) <= 0) pid = bd.intValueExact();
        }
        String just = HttpUtil.str(b, "justification");
        just = just == null ? "" : just.trim();
        if (pid == null) return err(400, "bad_request", "patient_id must be a whole number between 1 and 999999999.");
        // The justification is checked BEFORE the patient number is looked up: without a written justification an emergency request answers the
        // same for every number, so it cannot be used to find out which patient numbers exist. With one, a missing number costs as much session
        // risk as asking for a patient who is not assigned (the request is audited either way).
        if (just.length() < pol.breakGlass.minJustificationChars) {
            return err(400, "justification_required", "A justification of at least " + pol.breakGlass.minJustificationChars + " characters is required for break-glass access.");
        }
        if (just.length() > 500) return err(400, "justification_too_long", "The justification is limited to 500 characters.");
        if (scope.patientWard(pid) == null) {
            return new Res(404, decider.penalize(r, p, pol.penalties.notAssigned, 404, "not_found", "No such patient.").toErrorBody());
        }
        ScopeService.Result sr = scope.authorize(p, pid, now);
        if (sr.allowed) return err(400, "not_needed", "You already have access to this patient (basis: " + sr.basis + ").");
        SessionService.Row s = sessions.load(p.sessionId);
        if (s.grantsUsed >= pol.breakGlass.maxGrantsPerSession) return err(429, "break_glass_limit", "The limit of " + pol.breakGlass.maxGrantsPerSession + " break-glass grants per session has been reached.");
        String gid = scope.createGrant(p.userId, p.sessionId, pid, just, now, pol.breakGlass.durationSeconds);
        sessions.incGrants(p.sessionId);
        int total = sessions.addRisk(p.sessionId, pol.penalties.breakGlassUsed);
        String span = pol.breakGlass.durationSeconds >= 120 ? (pol.breakGlass.durationSeconds / 60) + " minutes" : pol.breakGlass.durationSeconds + " seconds";
        EventLog.Event e = new EventLog.Event("BREAK_GLASS").who(p);
        e.decision = "ALLOW"; e.code = "break_glass_granted"; e.riskDelta = pol.penalties.breakGlassUsed; e.sessionRisk = total; e.path = "/ctl/break-glass";
        e.reason = "BREAK-GLASS: " + p.username + " obtained time-limited access to patient " + pid + " for " + span + ". Justification: " + just;
        e.details = "grant " + gid;
        events.record(e);
        JsonObject o = new JsonObject();
        o.addProperty("grant_id", gid); o.addProperty("patient_id", pid); o.addProperty("seconds", pol.breakGlass.durationSeconds);
        o.addProperty("expires_ts", now + pol.breakGlass.durationSeconds);
        o.addProperty("message", "Emergency access granted for " + span + ". This access is recorded and reviewed.");
        return ok(o);
    }

    // ---- administration (security administrator only; RBAC is enforced by Decider before this code runs) --------------------

    private Res summary(long now) {
        JsonObject o = new JsonObject();
        o.addProperty("active_sessions", count("SELECT COUNT(*) FROM sessions WHERE status = 'ACTIVE'"));
        o.addProperty("revoked_sessions", count("SELECT COUNT(*) FROM sessions WHERE status = 'REVOKED'"));
        o.addProperty("devices", count("SELECT COUNT(*) FROM devices"));
        o.addProperty("denials_last_hour", count("SELECT COUNT(*) FROM security_events WHERE type = 'DECISION' AND decision = 'DENY' AND ts > ?", now - 3600));
        o.addProperty("step_ups_last_hour", count("SELECT COUNT(*) FROM security_events WHERE type = 'DECISION' AND decision = 'STEP_UP' AND ts > ?", now - 3600));
        o.addProperty("revocations_total", count("SELECT COUNT(*) FROM security_events WHERE type = 'SESSION_REVOKED'"));
        o.addProperty("active_break_glass", count("SELECT COUNT(*) FROM break_glass_grants WHERE status = 'ACTIVE' AND expires_ts > ?", now));
        o.addProperty("locked_users", count("SELECT COUNT(*) FROM users WHERE locked_until > ?", now));
        o.addProperty("server_time", now);
        return ok(o);
    }

    private int count(String sql, Object... args) {
        return db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                for (int i = 0; i < args.length; i++) ps.setObject(i + 1, args[i]);
                try (ResultSet rs = ps.executeQuery()) { return rs.next() ? rs.getInt(1) : 0; }
            }
        });
    }

    private Res adminRevoke(Principal p, JsonObject b, long now) {
        String sid = HttpUtil.str(b, "session_id");
        String reason = HttpUtil.str(b, "reason");
        if (sid == null || sid.length() > 80) return err(400, "bad_request", "session_id is required.");
        reason = reason == null || reason.trim().isEmpty() ? "revoked by a security administrator" : trim(reason.trim(), 200);
        SessionService.Row s = sessions.load(sid);
        if (s == null) return err(404, "not_found", "No such session.");
        if (!sessions.end(sid, "REVOKED", p.username, reason, now)) return err(409, "already_ended", "The session is not active.");
        EventLog.Event e = new EventLog.Event("SESSION_REVOKED").who(p);
        e.sessionId = sid; e.decision = "REVOKE"; e.code = "admin_revocation"; e.method = "POST"; e.path = "/admin/sessions/revoke";
        e.reason = "session " + sid + " of " + s.username + " revoked by " + p.username + ": " + reason;
        events.record(e);
        return ok(okBody());
    }

    private Res adminDevices(long now, Policy pol) {
        JsonArray list = devices.list(now);
        for (int i = 0; i < list.size(); i++) {
            JsonObject o = list.get(i).getAsJsonObject();
            DeviceService.Posture post = devices.evaluate(devices.load(o.get("device_id").getAsString()), "127.0.0.1", now, pol);
            o.addProperty("posture", post.label); o.addProperty("score", post.score); o.addProperty("block_reason", post.blockReason);
            // evidence freshness: how old the last report may be before the server treats the device as stale (it differs by kind)
            o.addProperty("stale_after_seconds", "agent".equals(o.get("kind").getAsString()) ? pol.device.laptopStaleSeconds : pol.device.phoneStaleSeconds);
            o.add("signals", post.signals);
        }
        JsonObject out = new JsonObject();
        out.add("devices", list);
        out.addProperty("server_time", now);
        return ok(out);
    }

    private Res adminEvents(String query) {
        long since = 0; int limit = 100; String decision = null, type = null, session = null;
        if (query != null && !query.isEmpty()) {
            for (String kv : query.split("&")) {
                String[] a = kv.split("=", 2);
                if (a.length != 2) continue;
                try {
                    String v = java.net.URLDecoder.decode(a[1], "UTF-8");
                    switch (a[0]) {
                        case "since_id": since = Long.parseLong(v); break;
                        case "limit": limit = Integer.parseInt(v); break;
                        case "decision": decision = v.matches("[A-Z_]{1,12}") ? v : null; break;
                        case "type": type = v.matches("[A-Z_]{1,24}") ? v : null; break;
                        case "session": session = v.matches("[A-Za-z0-9-]{1,80}") ? v : null; break;
                        default: break;
                    }
                } catch (Exception ignored) { }
            }
        }
        JsonObject out = new JsonObject();
        out.add("events", events.query(since, limit, decision, type, session));
        return ok(out);
    }

    private Res policySet(Principal p, JsonObject b) {
        String path = HttpUtil.str(b, "path");
        JsonElement value = b.get("value");
        try {
            PolicyStore.Change c = policies.set(path, value, p.username);
            EventLog.Event e = new EventLog.Event("POLICY_CHANGE").who(p);
            e.decision = "ALLOW"; e.code = "policy_change"; e.method = "POST"; e.path = "/admin/policy/set";
            e.reason = "policy " + c.path + " changed from " + c.oldValue + " to " + c.newValue + " by " + p.username;
            events.record(e);
            JsonObject o = new JsonObject();
            o.add("policy", policies.currentJson());
            return ok(o);
        } catch (IllegalArgumentException ex) {
            return err(400, "bad_policy_change", ex.getMessage());
        }
    }

    private Res grantRevoke(Principal p, JsonObject b) {
        String gid = HttpUtil.str(b, "grant_id");
        if (gid == null || gid.length() > 40) return err(400, "bad_request", "grant_id is required.");
        if (!scope.revokeGrant(gid, p.username)) return err(404, "not_found", "No active grant with that id.");
        EventLog.Event e = new EventLog.Event("ADMIN_ACTION").who(p);
        e.decision = "ALLOW"; e.code = "grant_revoked"; e.method = "POST"; e.path = "/admin/grants/revoke";
        e.reason = "break-glass grant " + gid + " revoked by " + p.username;
        events.record(e);
        return ok(okBody());
    }

    private Res unlock(Principal p, JsonObject b) {
        String username = HttpUtil.str(b, "username");
        if (username == null || username.length() > 64) return err(400, "bad_request", "username is required.");
        String[] u = loadUser(username);
        if (u == null) return err(404, "not_found", "No such user.");
        sessions.lockUser(u[0], 0, null);
        resetFailures(u[0]);
        EventLog.Event e = new EventLog.Event("UNLOCK").who(p);
        e.decision = "ALLOW"; e.code = "unlocked"; e.method = "POST"; e.path = "/admin/unlock";
        e.reason = "account " + username + " unlocked by " + p.username;
        events.record(e);
        return ok(okBody());
    }
}
