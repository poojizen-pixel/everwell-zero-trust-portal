package pdp.http.handlers;

import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import pdp.Config;
import pdp.crypto.PasswordHasher;
import pdp.crypto.TokenService;
import pdp.db.Database;
import pdp.http.EventBroadcaster;
import pdp.http.HttpUtil;

import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.UUID;

// POST /pdp/auth/login - identity pillar. A session cannot even begin
// unless BOTH the credentials are correct AND the device's most recent
// heartbeat is fresh and healthy - trust starts conditional, not granted
// by default the moment a password matches.
public class LoginHandler implements HttpHandler {
    private final Database db;
    private final TokenService tokenService;
    private final EventBroadcaster broadcaster;

    public LoginHandler(Database db, TokenService tokenService, EventBroadcaster broadcaster) {
        this.db = db;
        this.tokenService = tokenService;
        this.broadcaster = broadcaster;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            HttpUtil.sendJson(exchange, 405, error("method not allowed"));
            return;
        }

        JsonObject body;
        try {
            body = HttpUtil.readJsonBody(exchange);
        } catch (Exception e) {
            HttpUtil.sendJson(exchange, 400, error("malformed json"));
            return;
        }

        String username = body.has("username") ? body.get("username").getAsString() : null;
        String password = body.has("password") ? body.get("password").getAsString() : null;
        String deviceId = body.has("device_id") ? body.get("device_id").getAsString() : null;
        // The PEP is the only thing that ever calls the PDP directly, so
        // exchange.getRemoteAddress() would just be "the PEP" once the full
        // system is wired up - it must forward the real browser client's IP
        // explicitly. Falling back to the raw connection IP only supports
        // direct-to-PDP testing (curl, no PEP in front).
        String originIp = body.has("origin_ip") ? body.get("origin_ip").getAsString() : HttpUtil.clientIp(exchange);

        if (username == null || password == null || deviceId == null) {
            HttpUtil.sendJson(exchange, 400, error("missing username, password, or device_id"));
            return;
        }

        String passwordHash = PasswordHasher.sha256Hex(password);

        // Fail closed by default; only an explicit successful path below sets this.
        final JsonObject[] result = { null };
        final int[] status = { 401 };

        db.withConnection(conn -> {
            String userId = null, role = null;
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT user_id, role FROM users WHERE username = ? AND password_hash = ?")) {
                ps.setString(1, username);
                ps.setString(2, passwordHash);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        userId = rs.getString("user_id");
                        role = rs.getString("role");
                    }
                }
            }
            if (userId == null) {
                result[0] = error("invalid username or password");
                status[0] = 401;
                return null;
            }

            boolean deviceHealthy = false;
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT firewall_active, antivirus_active, last_signature_valid, last_heartbeat_ts FROM devices WHERE device_id = ?")) {
                ps.setString(1, deviceId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        long age = System.currentTimeMillis() / 1000 - rs.getLong("last_heartbeat_ts");
                        deviceHealthy = rs.getInt("firewall_active") == 1
                                && rs.getInt("antivirus_active") == 1
                                && rs.getInt("last_signature_valid") == 1
                                && age <= Config.HEARTBEAT_STALE_SECONDS;
                    }
                }
            }
            if (!deviceHealthy) {
                result[0] = error("device posture unhealthy or agent not running - cannot start a session");
                status[0] = 403;
                return null;
            }

            String sessionId = "S-" + UUID.randomUUID();
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO sessions (session_id, device_id, user_id, origin_ip, created_at, last_seen_ts, current_risk_score, status) "
                            + "VALUES (?, ?, ?, ?, ?, ?, 0, 'ACTIVE')")) {
                long now = System.currentTimeMillis() / 1000;
                ps.setString(1, sessionId);
                ps.setString(2, deviceId);
                ps.setString(3, userId);
                ps.setString(4, originIp);
                ps.setLong(5, now);
                ps.setLong(6, now);
                ps.executeUpdate();
            }

            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO risk_events (session_id, device_id, endpoint_id, request_method, request_path, risk_score, decision, reason) "
                            + "VALUES (?, ?, NULL, 'LOGIN', '/pdp/auth/login', 0, 'ALLOW', ?)")) {
                ps.setString(1, sessionId);
                ps.setString(2, deviceId);
                ps.setString(3, "login granted for user " + username + " (" + role + ") from " + originIp);
                ps.executeUpdate();
            }

            String token = tokenService.issue(sessionId, userId, deviceId, originIp);

            JsonObject ok = new JsonObject();
            ok.addProperty("status", "ok");
            ok.addProperty("token", token);
            ok.addProperty("session_id", sessionId);
            ok.addProperty("role", role);
            result[0] = ok;
            status[0] = 200;
            return null;
        });

        if (status[0] == 200) {
            JsonObject evt = new JsonObject();
            evt.addProperty("type", "LOGIN");
            evt.addProperty("username", username);
            evt.addProperty("decision", "ALLOW");
            broadcaster.broadcast(evt.toString());
        }

        HttpUtil.sendJson(exchange, status[0], result[0]);
    }

    private static JsonObject error(String reason) {
        JsonObject o = new JsonObject();
        o.addProperty("status", "denied");
        o.addProperty("reason", reason);
        return o;
    }
}
