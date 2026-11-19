package pdp.http.handlers;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import pdp.db.Database;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

// GET /pdp/events/recent - backfills the dashboard's event feed on page
// load, before the live SSE stream has produced anything new.
public class EventsRecentHandler implements HttpHandler {
    private final Database db;

    public EventsRecentHandler(Database db) {
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

        byte[] bytes = arr.toString().getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
