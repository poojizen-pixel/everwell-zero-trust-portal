package pdp.http.handlers;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import pdp.db.Database;
import pdp.http.HttpUtil;

import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

// GET /pdp/sessions/list - lets a SOC operator see every session, active or
// terminated, with enough context (user, role, device, current risk) to
// decide whether to kill one from the dashboard's Sessions view.
public class SessionsListHandler implements HttpHandler {
    private final Database db;

    public SessionsListHandler(Database db) {
        this.db = db;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        JsonArray arr = db.withConnection(conn -> {
            JsonArray a = new JsonArray();
            String sql = "SELECT s.session_id, s.device_id, s.user_id, u.username, u.role, s.origin_ip, "
                    + "s.created_at, s.last_seen_ts, s.current_risk_score, s.status, s.terminated_by, s.terminated_reason "
                    + "FROM sessions s JOIN users u ON u.user_id = s.user_id "
                    + "ORDER BY s.last_seen_ts DESC LIMIT 100";
            try (PreparedStatement ps = conn.prepareStatement(sql); ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    JsonObject o = new JsonObject();
                    o.addProperty("session_id", rs.getString("session_id"));
                    o.addProperty("device_id", rs.getString("device_id"));
                    o.addProperty("username", rs.getString("username"));
                    o.addProperty("role", rs.getString("role"));
                    o.addProperty("origin_ip", rs.getString("origin_ip"));
                    o.addProperty("created_at", rs.getLong("created_at"));
                    o.addProperty("last_seen_ts", rs.getLong("last_seen_ts"));
                    o.addProperty("current_risk_score", rs.getInt("current_risk_score"));
                    o.addProperty("status", rs.getString("status"));
                    o.addProperty("terminated_by", rs.getString("terminated_by"));
                    o.addProperty("terminated_reason", rs.getString("terminated_reason"));
                    a.add(o);
                }
            }
            return a;
        });
        HttpUtil.sendJson(exchange, 200, arr);
    }
}
