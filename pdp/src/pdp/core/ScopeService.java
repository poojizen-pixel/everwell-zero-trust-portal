package pdp.core;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import pdp.db.Database;

import java.security.SecureRandom;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

// Resource-level least privilege: WHICH patients a role may reach, enforced on the server before any data is fetched.
//   doctor       : only patients assigned to them, or a patient covered by an ACTIVE break-glass grant they created
//   nurse        : patients of their own ward (or assigned to them)
//   receptionist : demographics and appointment only (the endpoint catalogue keeps clinical endpoints away from this role)
//   security_admin: no patient endpoint at all (RBAC)
public class ScopeService {
    private static final SecureRandom RNG = new SecureRandom();
    private final Database db;

    public ScopeService(Database db) { this.db = db; }

    public static class Result {
        public boolean allowed;
        public String basis = "", grantId = "", code = "", message = "";
    }

    public String patientWard(int patientId) {
        return db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("SELECT ward FROM patients WHERE patient_id = ?")) {
                ps.setInt(1, patientId);
                try (ResultSet rs = ps.executeQuery()) { return rs.next() ? rs.getString(1) : null; }
            }
        });
    }

    private boolean assigned(String userId, int patientId) {
        return db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("SELECT 1 FROM patient_assignments WHERE user_id = ? AND patient_id = ?")) {
                ps.setString(1, userId); ps.setInt(2, patientId);
                try (ResultSet rs = ps.executeQuery()) { return rs.next(); }
            }
        });
    }

    // Emergency access belongs to the SESSION that asked for it: another session of the same doctor (or a later sign-in) does not inherit it.
    public String activeGrant(String userId, String sessionId, int patientId, long now) {
        return db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT grant_id FROM break_glass_grants WHERE user_id = ? AND session_id = ? AND patient_id = ? AND status = 'ACTIVE' AND expires_ts > ? ORDER BY expires_ts DESC LIMIT 1")) {
                ps.setString(1, userId); ps.setString(2, sessionId); ps.setInt(3, patientId); ps.setLong(4, now);
                try (ResultSet rs = ps.executeQuery()) { return rs.next() ? rs.getString(1) : null; }
            }
        });
    }

    // A patient number that does not exist gets exactly the same answer as a patient the caller may not see (same code, text, status and
    // penalty), so a doctor or nurse cannot use the patient endpoints to find out which numbers exist. The front desk is the exception: it works
    // with the whole directory, so a missing number is no secret for that role.
    public Result authorize(Principal p, int patientId, long now) {
        Result r = new Result();
        String ward = patientWard(patientId);
        boolean exists = ward != null;
        switch (p.role) {
            case "doctor":
                if (exists) {
                    if (assigned(p.userId, patientId)) { r.allowed = true; r.basis = "assigned"; return r; }
                    String g = activeGrant(p.userId, p.sessionId, patientId, now);
                    if (g != null) { r.allowed = true; r.basis = "break_glass"; r.grantId = g; return r; }
                }
                r.code = "not_assigned";
                r.message = "Access denied: this patient is not assigned to you. If this is an emergency you can request break-glass access with a justification.";
                return r;
            case "nurse":
                if (exists) {
                    if (p.ward != null && p.ward.equalsIgnoreCase(ward)) { r.allowed = true; r.basis = "ward"; return r; }
                    if (assigned(p.userId, patientId)) { r.allowed = true; r.basis = "assigned"; return r; }
                }
                r.code = "ward_denied";
                r.message = "Access denied: this patient is not on your ward (" + (p.ward == null ? "none" : p.ward) + ").";
                return r;
            case "receptionist":
                if (!exists) { r.code = "not_found"; r.message = "No such patient."; return r; }
                r.allowed = true; r.basis = "front_desk";
                return r;
            default:
                r.code = "role_denied"; r.message = "Access denied: your role has no access to patient data.";
                return r;
        }
    }

    public String createGrant(String userId, String sessionId, int patientId, String justification, long now, int seconds) {
        byte[] b = new byte[8];
        RNG.nextBytes(b);
        StringBuilder sb = new StringBuilder("BG-");
        for (byte x : b) sb.append(String.format("%02x", x));
        String id = sb.toString();
        db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO break_glass_grants (grant_id, user_id, session_id, patient_id, justification, created_ts, expires_ts) VALUES (?,?,?,?,?,?,?)")) {
                ps.setString(1, id); ps.setString(2, userId); ps.setString(3, sessionId); ps.setInt(4, patientId);
                ps.setString(5, justification); ps.setLong(6, now); ps.setLong(7, now + seconds);
                ps.executeUpdate();
            }
            return null;
        });
        return id;
    }

    public boolean revokeGrant(String grantId, String by) {
        return db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("UPDATE break_glass_grants SET status = 'REVOKED', revoked_by = ? WHERE grant_id = ? AND status = 'ACTIVE'")) {
                ps.setString(1, by); ps.setString(2, grantId);
                return ps.executeUpdate() > 0;
            }
        });
    }

    public JsonArray grants(long now) {
        return db.withConnection(conn -> {
            JsonArray a = new JsonArray();
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT g.grant_id, g.user_id, u.username, g.session_id, g.patient_id, g.justification, g.created_ts, g.expires_ts, g.status, g.revoked_by "
                            + "FROM break_glass_grants g JOIN users u ON u.user_id = g.user_id ORDER BY g.created_ts DESC LIMIT 100");
                 ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    JsonObject o = new JsonObject();
                    o.addProperty("grant_id", rs.getString(1)); o.addProperty("user_id", rs.getString(2)); o.addProperty("username", rs.getString(3));
                    o.addProperty("session_id", rs.getString(4)); o.addProperty("patient_id", rs.getInt(5)); o.addProperty("justification", rs.getString(6));
                    o.addProperty("created_ts", rs.getLong(7)); o.addProperty("expires_ts", rs.getLong(8));
                    String st = rs.getString(9);
                    o.addProperty("status", "ACTIVE".equals(st) && rs.getLong(8) <= now ? "EXPIRED" : st);
                    o.addProperty("revoked_by", rs.getString(10));
                    a.add(o);
                }
            }
            return a;
        });
    }
}
