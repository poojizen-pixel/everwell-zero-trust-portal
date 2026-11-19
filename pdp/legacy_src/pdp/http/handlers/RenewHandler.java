package pdp.http.handlers;

import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import pdp.Config;
import pdp.crypto.TokenService;
import pdp.db.Database;
import pdp.http.HttpUtil;

import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

// POST /pdp/token/renew - the client calls this every ~15s (before the
// current ~20s token expires). A new token is only issued if the session is
// still ACTIVE and the device's heartbeat is still fresh and healthy right
// now - not "was healthy when the token was first issued". This is what
// makes trust actually expire on its own: stop renewing (agent killed,
// posture degraded, session terminated) and the client is left holding a
// token that dies within seconds, with nobody having to revoke anything.
public class RenewHandler implements HttpHandler {
    private final Database db;
    private final TokenService tokenService;

    public RenewHandler(Database db, TokenService tokenService) {
        this.db = db;
        this.tokenService = tokenService;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            HttpUtil.sendJson(exchange, 405, denied("method not allowed"));
            return;
        }

        JsonObject body;
        try {
            body = HttpUtil.readJsonBody(exchange);
        } catch (Exception e) {
            HttpUtil.sendJson(exchange, 400, denied("malformed json"));
            return;
        }

        String token = body.has("token") ? body.get("token").getAsString() : null;
        String deviceId = body.has("device_id") ? body.get("device_id").getAsString() : null;
        if (token == null || deviceId == null) {
            HttpUtil.sendJson(exchange, 400, denied("missing token or device_id"));
            return;
        }

        TokenService.TokenClaims claims;
        try {
            claims = tokenService.verify(token, deviceId);
        } catch (TokenService.TokenException e) {
            HttpUtil.sendJson(exchange, 401, denied("token rejected: " + e.getMessage()));
            return;
        }

        Boolean[] sessionActive = { false };
        db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("SELECT status FROM sessions WHERE session_id = ?")) {
                ps.setString(1, claims.sessionId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) sessionActive[0] = "ACTIVE".equals(rs.getString("status"));
                }
            }
            return null;
        });
        if (!sessionActive[0]) {
            HttpUtil.sendJson(exchange, 403, denied("session no longer active"));
            return;
        }

        boolean deviceHealthy = db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT firewall_active, antivirus_active, last_signature_valid, last_heartbeat_ts FROM devices WHERE device_id = ?")) {
                ps.setString(1, deviceId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) return false;
                    long age = System.currentTimeMillis() / 1000 - rs.getLong("last_heartbeat_ts");
                    return rs.getInt("firewall_active") == 1
                            && rs.getInt("antivirus_active") == 1
                            && rs.getInt("last_signature_valid") == 1
                            && age <= Config.HEARTBEAT_STALE_SECONDS;
                }
            }
        });
        if (!deviceHealthy) {
            HttpUtil.sendJson(exchange, 403, denied("device posture no longer healthy - renewal refused"));
            return;
        }

        // See LoginHandler for why this must come from the body, not
        // exchange.getRemoteAddress(), once the PEP sits in front of the PDP.
        String originIp = body.has("origin_ip") ? body.get("origin_ip").getAsString() : HttpUtil.clientIp(exchange);
        String newToken = tokenService.issue(claims.sessionId, claims.userId, deviceId, originIp);
        JsonObject ok = new JsonObject();
        ok.addProperty("status", "ok");
        ok.addProperty("token", newToken);
        HttpUtil.sendJson(exchange, 200, ok);
    }

    private static JsonObject denied(String reason) {
        JsonObject o = new JsonObject();
        o.addProperty("status", "denied");
        o.addProperty("reason", reason);
        return o;
    }
}
