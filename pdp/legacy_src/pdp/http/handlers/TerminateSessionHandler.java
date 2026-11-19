package pdp.http.handlers;

import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import pdp.db.Database;
import pdp.http.EventBroadcaster;
import pdp.http.HttpUtil;

import java.io.IOException;
import java.sql.PreparedStatement;

// POST /pdp/admin/terminate-session - the manual SOC kill switch. Trust
// doesn't only end by expiry or a dead agent; an operator can end it
// immediately from the dashboard, and because /pdp/evaluate checks session
// status on every single request, this takes effect on the very next call -
// no waiting for the current token to expire.
public class TerminateSessionHandler implements HttpHandler {
    private final Database db;
    private final EventBroadcaster broadcaster;

    public TerminateSessionHandler(Database db, EventBroadcaster broadcaster) {
        this.db = db;
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

        String sessionId = body.has("session_id") ? body.get("session_id").getAsString() : null;
        String terminatedBy = body.has("terminated_by") ? body.get("terminated_by").getAsString() : "SOC-operator";
        String reason = body.has("reason") ? body.get("reason").getAsString() : "manual termination";

        if (sessionId == null) {
            HttpUtil.sendJson(exchange, 400, error("missing session_id"));
            return;
        }

        int updated = db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE sessions SET status = 'TERMINATED', terminated_by = ?, terminated_reason = ? WHERE session_id = ? AND status = 'ACTIVE'")) {
                ps.setString(1, terminatedBy);
                ps.setString(2, reason);
                ps.setString(3, sessionId);
                return ps.executeUpdate();
            }
        });

        if (updated == 0) {
            HttpUtil.sendJson(exchange, 404, error("session not found or already terminated"));
            return;
        }

        db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO risk_events (session_id, device_id, endpoint_id, request_method, request_path, risk_score, decision, reason) "
                            + "SELECT session_id, device_id, NULL, 'ADMIN', '/pdp/admin/terminate-session', 100, 'DENY', ? FROM sessions WHERE session_id = ?")) {
                ps.setString(1, "manually terminated by " + terminatedBy + ": " + reason);
                ps.setString(2, sessionId);
                ps.executeUpdate();
            }
            return null;
        });

        JsonObject evt = new JsonObject();
        evt.addProperty("type", "ADMIN_TERMINATE");
        evt.addProperty("session_id", sessionId);
        evt.addProperty("decision", "DENY");
        evt.addProperty("reason", reason);
        broadcaster.broadcast(evt.toString());

        JsonObject ok = new JsonObject();
        ok.addProperty("status", "ok");
        HttpUtil.sendJson(exchange, 200, ok);
    }

    private static JsonObject error(String reason) {
        JsonObject o = new JsonObject();
        o.addProperty("status", "error");
        o.addProperty("reason", reason);
        return o;
    }
}
