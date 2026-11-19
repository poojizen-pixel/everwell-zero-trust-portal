package app.http.handlers;

import app.db.Database;
import app.http.Claims;

import java.sql.PreparedStatement;
import java.sql.ResultSet;

// Resource-level authorisation INSIDE the protected app, independent of the PDP's decision (defence in depth): even if a decision were
// wrongly ALLOW, or the PEP vouched for the wrong identity, the data layer re-checks the account itself - role and ward come from the account
// in the database (the signed claims must agree with it), and assignment, ward and break-glass grant are read from the database too.
final class Access {
    private Access() {}

    // The account the signed claims name: {role, ward}; null when there is no such account.
    private static String[] account(Database db, Claims c) {
        return db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("SELECT role, COALESCE(ward, '') FROM users WHERE user_id = ?")) {
                ps.setString(1, c.userId);
                try (ResultSet rs = ps.executeQuery()) { return rs.next() ? new String[]{rs.getString(1), rs.getString(2)} : null; }
            }
        });
    }

    // null when the claims are consistent with the account, otherwise the reason. Decisions below use the DATABASE's role and ward.
    static String identity(Database db, Claims c) {
        if (c == null) return "no identity";
        String[] a = account(db, c);
        if (a == null) return "unknown account";
        if (!a[0].equals(c.role)) return "identity claims do not match the account";
        if (a[0].equals("nurse") && !a[1].equalsIgnoreCase(c.ward == null ? "" : c.ward)) return "identity claims do not match the account";
        return null;
    }

    // kind: summary | records | export.  Returns null when allowed, otherwise the reason.
    static String check(Database db, Claims c, int patientId, String kind) {
        String bad = identity(db, c);
        if (bad != null) return bad;
        String[] acct = account(db, c);
        String ward = db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("SELECT ward FROM patients WHERE patient_id = ?")) {
                ps.setInt(1, patientId);
                try (ResultSet rs = ps.executeQuery()) { return rs.next() ? rs.getString(1) : null; }
            }
        });
        boolean exists = ward != null;
        if (kind.equals("appointment") && !acct[0].equals("receptionist")) return "only reception staff may change appointments";
        // A missing patient number is answered exactly like a patient the caller may not see (doctor, nurse): no existence oracle at the data layer
        // either. The front desk works with the whole directory, so only that role is told "no such patient".
        switch (acct[0]) {
            case "receptionist":
                if (!exists) return "no such patient";
                return (kind.equals("summary") || kind.equals("appointment")) ? null : "receptionists may only read demographics and manage appointments";
            case "nurse":
                if (kind.equals("export")) return "nurses may not export records";
                if (exists && !acct[1].isEmpty() && acct[1].equalsIgnoreCase(ward)) return null;
                return exists && assigned(db, c.userId, patientId) ? null : "patient is not on the nurse's ward";
            case "doctor":
                if (exists && assigned(db, c.userId, patientId)) return null;
                // emergency access: only the granted patient, only in the session that asked for it, and never the export
                if (kind.equals("export")) return "export requires an assignment to this patient (emergency access does not include it)";
                if (exists && grant(db, c.userId, c.sessionId, patientId)) return null;
                return "patient is not assigned to this doctor and no break-glass grant is active";
            default:
                return "role has no access to patient data";
        }
    }

    static boolean assigned(Database db, String userId, int patientId) {
        return db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("SELECT 1 FROM patient_assignments WHERE user_id = ? AND patient_id = ?")) {
                ps.setString(1, userId); ps.setInt(2, patientId);
                try (ResultSet rs = ps.executeQuery()) { return rs.next(); }
            }
        });
    }

    private static boolean grant(Database db, String userId, String sessionId, int patientId) {
        return db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT 1 FROM break_glass_grants WHERE user_id = ? AND session_id = ? AND patient_id = ? AND status = 'ACTIVE' AND expires_ts > ?")) {
                ps.setString(1, userId); ps.setString(2, sessionId); ps.setInt(3, patientId); ps.setLong(4, System.currentTimeMillis() / 1000);
                try (ResultSet rs = ps.executeQuery()) { return rs.next(); }
            }
        });
    }
}
