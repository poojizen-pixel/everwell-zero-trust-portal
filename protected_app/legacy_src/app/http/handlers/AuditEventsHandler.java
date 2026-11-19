package app.http.handlers;

import app.db.Database;
import app.http.HttpUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

// The auditor role's in-app view of the same risk_events table the PDP
// writes to - distinct from the PDP's own /pdp/events/recent (the always-on
// SOC monitoring feed): this one is a normal protected resource, reached
// only by a logged-in auditor going through the full PEP/PDP evaluation
// like any other endpoint.
public class AuditEventsHandler implements HttpHandler {
    private final Database db;

    public AuditEventsHandler(Database db) {
        this.db = db;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        JsonArray arr = db.withConnection(conn -> {
            JsonArray a = new JsonArray();
            String sql = "SELECT event_id, session_id, device_id, request_method, request_path, risk_score, decision, reason, ts "
                    + "FROM risk_events ORDER BY event_id DESC LIMIT 50";
            try (PreparedStatement ps = conn.prepareStatement(sql); ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    JsonObject o = new JsonObject();
                    o.addProperty("event_id", rs.getInt("event_id"));
                    o.addProperty("session_id", rs.getString("session_id"));
                    o.addProperty("device_id", rs.getString("device_id"));
                    o.addProperty("method", rs.getString("request_method"));
                    o.addProperty("path", rs.getString("request_path"));
                    o.addProperty("risk_score", rs.getInt("risk_score"));
                    o.addProperty("decision", rs.getString("decision"));
                    o.addProperty("reason", rs.getString("reason"));
                    o.addProperty("ts", rs.getLong("ts"));
                    a.add(o);
                }
            }
            return a;
        });
        HttpUtil.sendJson(exchange, 200, arr.toString());
    }
}
