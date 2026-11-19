package pdp.http.handlers;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import pdp.Config;
import pdp.db.Database;
import pdp.http.HttpUtil;

import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

// GET /pdp/devices/list - the Device pillar's inventory view. Status is
// computed the exact same way DevicePostureVector would score it, so the
// dashboard's "STALE" badge and the PDP's actual hard-block decision can
// never disagree with each other.
public class DevicesListHandler implements HttpHandler {
    private final Database db;

    public DevicesListHandler(Database db) {
        this.db = db;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        long now = System.currentTimeMillis() / 1000;
        JsonArray arr = db.withConnection(conn -> {
            JsonArray a = new JsonArray();
            String sql = "SELECT device_id, hostname, os, firewall_active, antivirus_active, "
                    + "last_heartbeat_ts, last_signature_valid FROM devices ORDER BY last_heartbeat_ts DESC";
            try (PreparedStatement ps = conn.prepareStatement(sql); ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    long lastSeen = rs.getLong("last_heartbeat_ts");
                    long age = now - lastSeen;
                    boolean sigValid = rs.getInt("last_signature_valid") == 1;
                    boolean firewall = rs.getInt("firewall_active") == 1;
                    boolean av = rs.getInt("antivirus_active") == 1;

                    String status;
                    if (!sigValid || age > Config.HEARTBEAT_STALE_SECONDS) status = "STALE";
                    else if (!firewall || !av) status = "DEGRADED";
                    else status = "HEALTHY";

                    JsonObject o = new JsonObject();
                    o.addProperty("device_id", rs.getString("device_id"));
                    o.addProperty("hostname", rs.getString("hostname"));
                    o.addProperty("os", rs.getString("os"));
                    o.addProperty("firewall_active", firewall);
                    o.addProperty("antivirus_active", av);
                    o.addProperty("signature_valid", sigValid);
                    o.addProperty("heartbeat_age_seconds", age);
                    o.addProperty("status", status);
                    a.add(o);
                }
            }
            return a;
        });
        HttpUtil.sendJson(exchange, 200, arr);
    }
}
