package pdp.core;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import pdp.db.Database;

import java.security.SecureRandom;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

// Server-side session state: creation, risk points, revocation and account locks. A session is valid only while status = ACTIVE.
public class SessionService {
    private static final SecureRandom RNG = new SecureRandom();
    private final Database db;

    public SessionService(Database db) { this.db = db; }

    public static class Row {
        public String sessionId, deviceId, userId, originIp, simIp, status, revokedBy, revokeReason, username, displayName, role, ward, lockReason;
        public long createdAt, lastSeen, revokedAt, lockedUntil;
        public int riskPoints, lastScore, grantsUsed;
    }

    public String newId() {
        byte[] b = new byte[16];
        RNG.nextBytes(b);
        StringBuilder sb = new StringBuilder("S-");
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    public Row load(String sessionId) {
        return db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT s.session_id, s.device_id, s.user_id, s.origin_ip, s.sim_ip, s.created_at, s.last_seen_ts, s.risk_points, s.last_score, s.status, "
                            + "s.revoked_by, s.revoke_reason, s.revoked_at, s.grants_used, u.username, u.display_name, u.role, u.ward, u.locked_until, u.lock_reason "
                            + "FROM sessions s JOIN users u ON u.user_id = s.user_id WHERE s.session_id = ?")) {
                ps.setString(1, sessionId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) return null;
                    Row r = new Row();
                    r.sessionId = rs.getString(1); r.deviceId = rs.getString(2); r.userId = rs.getString(3); r.originIp = rs.getString(4);
                    r.simIp = rs.getString(5); r.createdAt = rs.getLong(6); r.lastSeen = rs.getLong(7); r.riskPoints = rs.getInt(8);
                    r.lastScore = rs.getInt(9); r.status = rs.getString(10); r.revokedBy = rs.getString(11); r.revokeReason = rs.getString(12);
                    r.revokedAt = rs.getLong(13); r.grantsUsed = rs.getInt(14); r.username = rs.getString(15); r.displayName = rs.getString(16);
                    r.role = rs.getString(17); r.ward = rs.getString(18); r.lockedUntil = rs.getLong(19); r.lockReason = rs.getString(20);
                    return r;
                }
            }
        });
    }

    public String create(String userId, String deviceId, String ip, long now) {
        String id = newId();
        db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO sessions (session_id, device_id, user_id, origin_ip, created_at, last_seen_ts, status) VALUES (?,?,?,?,?,?, 'ACTIVE')")) {
                ps.setString(1, id); ps.setString(2, deviceId); ps.setString(3, userId); ps.setString(4, ip);
                ps.setLong(5, now); ps.setLong(6, now);
                ps.executeUpdate();
            }
            return null;
        });
        return id;
    }

    // Only an ACTIVE session can be ended; returns false when it was already ended.
    public boolean end(String sessionId, String status, String by, String reason, long now) {
        return db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE sessions SET status = ?, revoked_at = ?, revoked_by = ?, revoke_reason = ? WHERE session_id = ? AND status = 'ACTIVE'")) {
                ps.setString(1, status); ps.setLong(2, now); ps.setString(3, by); ps.setString(4, reason); ps.setString(5, sessionId);
                return ps.executeUpdate() > 0;
            }
        });
    }

    public int addRisk(String sessionId, int points) {
        return db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("UPDATE sessions SET risk_points = risk_points + ? WHERE session_id = ?")) {
                ps.setInt(1, points); ps.setString(2, sessionId); ps.executeUpdate();
            }
            try (PreparedStatement ps = conn.prepareStatement("SELECT risk_points FROM sessions WHERE session_id = ?")) {
                ps.setString(1, sessionId);
                try (ResultSet rs = ps.executeQuery()) { return rs.next() ? rs.getInt(1) : 0; }
            }
        });
    }

    public void touch(String sessionId, long now, int score) {
        db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("UPDATE sessions SET last_seen_ts = ?, last_score = ? WHERE session_id = ?")) {
                ps.setLong(1, now); ps.setInt(2, score); ps.setString(3, sessionId); ps.executeUpdate();
            }
            return null;
        });
    }

    public void setOrigin(String sessionId, String ip) {
        db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("UPDATE sessions SET origin_ip = ? WHERE session_id = ?")) {
                ps.setString(1, ip); ps.setString(2, sessionId); ps.executeUpdate();
            }
            return null;
        });
    }

    public void setSimIp(String sessionId, String ipOrNull) {
        db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("UPDATE sessions SET sim_ip = ? WHERE session_id = ?")) {
                if (ipOrNull == null) ps.setNull(1, java.sql.Types.VARCHAR); else ps.setString(1, ipOrNull);
                ps.setString(2, sessionId); ps.executeUpdate();
            }
            return null;
        });
    }

    public void incGrants(String sessionId) {
        db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("UPDATE sessions SET grants_used = grants_used + 1 WHERE session_id = ?")) {
                ps.setString(1, sessionId); ps.executeUpdate();
            }
            return null;
        });
    }

    public void lockUser(String userId, long until, String reason) {
        db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("UPDATE users SET locked_until = ?, lock_reason = ? WHERE user_id = ?")) {
                ps.setLong(1, until); ps.setString(2, reason); ps.setString(3, userId); ps.executeUpdate();
            }
            return null;
        });
    }

    public JsonArray list(int limit) {
        return db.withConnection(conn -> {
            JsonArray a = new JsonArray();
            // evidence_ip / evidence_ts: the address the server saw at the latest recorded event of the session (sign-in, or a later audited request)
            // and when that was. They show how current the network evidence is; the server records no source address for unaudited polling.
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT s.session_id, s.user_id, u.username, u.role, s.device_id, s.origin_ip, s.sim_ip, s.created_at, s.last_seen_ts, s.risk_points, s.last_score, "
                            + "s.status, s.revoked_at, s.revoked_by, s.revoke_reason, "
                            + "(SELECT e.origin_ip FROM security_events e WHERE e.session_id = s.session_id AND e.origin_ip IS NOT NULL ORDER BY e.event_id DESC LIMIT 1), "
                            + "(SELECT e.ts FROM security_events e WHERE e.session_id = s.session_id AND e.origin_ip IS NOT NULL ORDER BY e.event_id DESC LIMIT 1) "
                            + "FROM sessions s JOIN users u ON u.user_id = s.user_id "
                            + "ORDER BY (s.status = 'ACTIVE') DESC, s.created_at DESC LIMIT ?")) {
                ps.setInt(1, Math.max(1, Math.min(limit, 200)));
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        JsonObject o = new JsonObject();
                        o.addProperty("session_id", rs.getString(1)); o.addProperty("user_id", rs.getString(2)); o.addProperty("username", rs.getString(3));
                        o.addProperty("role", rs.getString(4)); o.addProperty("device_id", rs.getString(5)); o.addProperty("origin_ip", rs.getString(6));
                        o.addProperty("simulated_ip", rs.getString(7)); o.addProperty("created_at", rs.getLong(8)); o.addProperty("last_seen", rs.getLong(9));
                        o.addProperty("risk_points", rs.getInt(10)); o.addProperty("last_score", rs.getInt(11)); o.addProperty("status", rs.getString(12));
                        o.addProperty("revoked_at", rs.getLong(13)); o.addProperty("revoked_by", rs.getString(14)); o.addProperty("revoke_reason", rs.getString(15));
                        o.addProperty("evidence_ip", rs.getString(16));
                        long evTs = rs.getLong(17);
                        if (rs.wasNull()) o.add("evidence_ts", com.google.gson.JsonNull.INSTANCE); else o.addProperty("evidence_ts", evTs);
                        a.add(o);
                    }
                }
            }
            return a;
        });
    }

    public JsonArray users() {
        return db.withConnection(conn -> {
            JsonArray a = new JsonArray();
            try (PreparedStatement ps = conn.prepareStatement("SELECT user_id, username, display_name, role, ward, locked_until, lock_reason, failed_logins FROM users ORDER BY username");
                 ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    JsonObject o = new JsonObject();
                    o.addProperty("user_id", rs.getString(1)); o.addProperty("username", rs.getString(2)); o.addProperty("display_name", rs.getString(3));
                    o.addProperty("role", rs.getString(4)); o.addProperty("ward", rs.getString(5)); o.addProperty("locked_until", rs.getLong(6));
                    o.addProperty("lock_reason", rs.getString(7)); o.addProperty("failed_logins", rs.getInt(8));
                    a.add(o);
                }
            }
            return a;
        });
    }
}
