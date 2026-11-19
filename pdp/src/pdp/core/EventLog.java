package pdp.core;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import pdp.db.Database;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Types;

// Append-only server-side security event log: the evidence behind every decision shown on the dashboard.
public class EventLog {
    private final Database db;

    public EventLog(Database db) { this.db = db; }

    public static class Event {
        public final String type;
        public String sessionId, userId, username, role, deviceId, ip, method, path, decision, code, reason = "", details;
        public Integer riskScore, riskDelta, sessionRisk;

        public Event(String type) { this.type = type; }

        public Event who(Principal p) {
            if (p != null) {
                sessionId = p.sessionId; userId = p.userId; username = p.username; role = p.role; deviceId = p.deviceId; ip = p.ip;
            }
            return this;
        }
    }

    public void record(Event e) {
        db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO security_events (ts, type, session_id, user_id, username, role, device_id, origin_ip, method, path, decision, code, "
                            + "risk_score, risk_delta, session_risk, reason, details) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")) {
                int i = 1;
                ps.setLong(i++, System.currentTimeMillis() / 1000);
                ps.setString(i++, e.type);
                i = str(ps, i, e.sessionId); i = str(ps, i, e.userId); i = str(ps, i, e.username); i = str(ps, i, e.role);
                i = str(ps, i, e.deviceId); i = str(ps, i, e.ip); i = str(ps, i, e.method); i = str(ps, i, e.path);
                i = str(ps, i, e.decision); i = str(ps, i, e.code);
                i = num(ps, i, e.riskScore); i = num(ps, i, e.riskDelta); i = num(ps, i, e.sessionRisk);
                ps.setString(i++, e.reason == null ? "" : e.reason);
                str(ps, i, e.details);
                ps.executeUpdate();
            }
            return null;
        });
    }

    private static int str(PreparedStatement ps, int i, String v) throws java.sql.SQLException {
        if (v == null) ps.setNull(i, Types.VARCHAR); else ps.setString(i, v);
        return i + 1;
    }

    private static int num(PreparedStatement ps, int i, Integer v) throws java.sql.SQLException {
        if (v == null) ps.setNull(i, Types.INTEGER); else ps.setInt(i, v);
        return i + 1;
    }

    // Newest first. decisionFilter / typeFilter may be null; sinceId returns only events with a larger id.
    public JsonArray query(long sinceId, int limit, String decisionFilter, String typeFilter, String sessionFilter) {
        return db.withConnection(conn -> {
            StringBuilder sql = new StringBuilder("SELECT * FROM security_events WHERE event_id > ?");
            if (decisionFilter != null) sql.append(" AND decision = ?");
            if (typeFilter != null) sql.append(" AND type = ?");
            if (sessionFilter != null) sql.append(" AND session_id = ?");
            sql.append(" ORDER BY event_id DESC LIMIT ?");
            JsonArray a = new JsonArray();
            try (PreparedStatement ps = conn.prepareStatement(sql.toString())) {
                int i = 1;
                ps.setLong(i++, sinceId);
                if (decisionFilter != null) ps.setString(i++, decisionFilter);
                if (typeFilter != null) ps.setString(i++, typeFilter);
                if (sessionFilter != null) ps.setString(i++, sessionFilter);
                ps.setInt(i, Math.max(1, Math.min(limit, 500)));
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        JsonObject o = new JsonObject();
                        o.addProperty("event_id", rs.getLong("event_id"));
                        o.addProperty("ts", rs.getLong("ts"));
                        for (String c : new String[]{"type", "session_id", "user_id", "username", "role", "device_id", "origin_ip", "method", "path", "decision", "code", "reason", "details"}) {
                            o.addProperty(c, rs.getString(c));
                        }
                        for (String c : new String[]{"risk_score", "risk_delta", "session_risk"}) {
                            int v = rs.getInt(c);
                            if (rs.wasNull()) o.add(c, com.google.gson.JsonNull.INSTANCE); else o.addProperty(c, v);
                        }
                        a.add(o);
                    }
                }
            }
            return a;
        });
    }
}
