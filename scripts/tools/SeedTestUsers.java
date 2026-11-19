import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * CP3 helper for a DISPOSABLE copy of the legacy database. It never prints a hash, a password or a PIN.
 *
 *   verify <db>                  read-only: checks the fixture facts the CP3 predictions rely on (users, patients, assignments,
 *                                endpoints, policies, role permissions, columns). Exit 0 only if every fact holds.
 *   reset <db>                   reads "username TAB password TAB pin" lines from STDIN (never from the command line) and stores the
 *                                SHA-256 hex of the password and of the PIN for exactly the four demo users, all or nothing.
 *   check-login <db> <username>  reads a password from STDIN; prints MATCH or NO MATCH using the same comparison as the legacy login query.
 *   check-pin <db> <username>    reads a PIN from STDIN; prints MATCH or NO MATCH using the same comparison as the legacy step-up query.
 *
 * Safety: refuses any path that contains "Ap project" or "Ap_project" (the live project and the backups). The hash is plain SHA-256 of the
 * UTF-8 bytes in lower-case hex because that is what the legacy PasswordHasher verifies (read from its source); the end-to-end proof is
 * the CP3 login scenario.
 */
public final class SeedTestUsers {
    private SeedTestUsers() { }

    private static final String[][] USERS = {
        {"dr_alice", "U-DOC-001", "doctor"},
        {"nurse_bob", "U-NUR-001", "nurse"},
        {"front_carol", "U-REC-001", "receptionist"},
        {"audit_dan", "U-AUD-001", "auditor"},
    };

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("usage: SeedTestUsers verify <db> | reset <db> | check-login <db> <username> | check-pin <db> <username>");
            System.exit(2);
        }
        String cmd = args[0];
        String db = args[1];
        guard(db);
        int code;
        switch (cmd) {
            case "verify": code = verify(db); break;
            case "reset": code = reset(db); break;
            case "check-login": code = check(db, args.length > 2 ? args[2] : "", "password_hash"); break;
            case "check-pin": code = check(db, args.length > 2 ? args[2] : "", "step_up_pin_hash"); break;
            default:
                System.out.println("unknown command " + cmd);
                code = 2;
        }
        System.exit(code);
    }

    private static void guard(String db) throws IOException {
        String canonical = new File(db).getCanonicalPath().toLowerCase();
        if (canonical.contains("ap project") || canonical.contains("ap_project")) {
            System.out.println("Refusing: the database path points into the live project or a backup folder.");
            System.exit(2);
        }
        if (!new File(db).isFile()) {
            System.out.println("database file not found");
            System.exit(2);
        }
    }

    private static Connection open(String db, boolean readOnly) throws SQLException {
        java.util.Properties p = new java.util.Properties();
        if (readOnly) p.setProperty("open_mode", "1"); // SQLITE_OPEN_READONLY
        return DriverManager.getConnection("jdbc:sqlite:" + db, p);
    }

    private static String sha256Hex(String s) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : d) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static int checks = 0;
    private static int failed = 0;

    private static void expect(String name, boolean ok, String detail) {
        checks++;
        if (!ok) failed++;
        System.out.println((ok ? "PASS  " : "FAIL  ") + name + (detail.isEmpty() ? "" : "  [" + detail + "]"));
    }

    private static List<String> rows(Connection c, String sql) throws SQLException {
        List<String> out = new ArrayList<>();
        try (Statement s = c.createStatement(); ResultSet r = s.executeQuery(sql)) {
            int n = r.getMetaData().getColumnCount();
            while (r.next()) {
                StringBuilder sb = new StringBuilder();
                for (int i = 1; i <= n; i++) {
                    if (i > 1) sb.append('|');
                    sb.append(String.valueOf(r.getObject(i)));
                }
                out.add(sb.toString());
            }
        }
        return out;
    }

    private static List<String> sorted(List<String> in) {
        return new ArrayList<>(new TreeSet<>(in));
    }

    private static int verify(String db) throws Exception {
        try (Connection c = open(db, true)) {
            // These queries select only non-secret columns. The password and PIN hash columns are never selected.
            List<String> users = sorted(rows(c, "SELECT username, user_id, role FROM users"));
            List<String> wantUsers = new ArrayList<>();
            for (String[] u : USERS) wantUsers.add(u[0] + "|" + u[1] + "|" + u[2]);
            expect("users: exactly the 4 demo users with these ids and roles", users.equals(sorted(wantUsers)), users.size() + " rows");

            List<String> cols = rows(c, "SELECT name FROM pragma_table_info('users')");
            expect("users has the columns the legacy queries use", cols.containsAll(Arrays.asList("user_id", "username", "password_hash", "step_up_pin_hash", "role")), "");

            List<String> patients = sorted(rows(c, "SELECT patient_id FROM patients"));
            expect("patients: ids 101, 102, 103, 104", patients.equals(Arrays.asList("101", "102", "103", "104")), patients.size() + " rows");

            List<String> assign = sorted(rows(c, "SELECT user_id, patient_id FROM patient_assignments"));
            expect("assignments: exactly (U-DOC-001,101) (U-DOC-001,102) (U-NUR-001,101) (U-NUR-001,103)",
                assign.equals(sorted(Arrays.asList("U-DOC-001|101", "U-DOC-001|102", "U-NUR-001|101", "U-NUR-001|103"))), assign.size() + " rows");

            List<String> endpoints = sorted(rows(c, "SELECT method, path, sensitivity FROM endpoints"));
            expect("endpoints: 5 rows with sensitivities 0/20/40/60/10",
                endpoints.equals(sorted(Arrays.asList("GET|/api/public/info|0", "GET|/api/patients/list|20", "GET|/api/patients/*/records|40", "POST|/api/patients/*/export-pdf|60", "GET|/api/audit/events|10"))), endpoints.size() + " rows");

            List<String> policies = sorted(rows(c, "SELECT name, min_risk, max_risk, action FROM policies"));
            expect("policies: allow 0-40, step-up 40-70, deny 70-1000",
                policies.equals(sorted(Arrays.asList("allow_full|0|40|ALLOW", "step_up_mfa|40|70|STEP_UP", "deny_hard|70|1000|DENY"))), policies.size() + " rows");

            List<String> perms = sorted(rows(c, "SELECT rp.role, e.method, e.path FROM role_permissions rp JOIN endpoints e ON e.endpoint_id = rp.endpoint_id"));
            List<String> wantPerms = Arrays.asList(
                "doctor|GET|/api/public/info", "doctor|GET|/api/patients/list", "doctor|GET|/api/patients/*/records", "doctor|POST|/api/patients/*/export-pdf",
                "nurse|GET|/api/public/info", "nurse|GET|/api/patients/list", "nurse|GET|/api/patients/*/records",
                "receptionist|GET|/api/public/info", "receptionist|GET|/api/patients/list",
                "auditor|GET|/api/public/info", "auditor|GET|/api/audit/events");
            expect("role permissions: doctor 4, nurse 3, receptionist 2, auditor 2 endpoints as in schema.sql", perms.equals(sorted(wantPerms)), perms.size() + " rows");

            List<String> dcols = rows(c, "SELECT name FROM pragma_table_info('devices')");
            expect("devices has the columns the PDP uses", dcols.containsAll(Arrays.asList("device_id", "hostname", "os", "firewall_active", "antivirus_active", "last_heartbeat_ts", "last_signature_valid")), "");
            List<String> scols = rows(c, "SELECT name FROM pragma_table_info('sessions')");
            expect("sessions has the columns the PDP uses", scols.containsAll(Arrays.asList("session_id", "device_id", "user_id", "origin_ip", "created_at", "last_seen_ts", "current_risk_score", "status", "terminated_by", "terminated_reason")), "");
            List<String> rcols = rows(c, "SELECT name FROM pragma_table_info('risk_events')");
            expect("risk_events has the columns the PDP uses", rcols.containsAll(Arrays.asList("event_id", "session_id", "device_id", "endpoint_id", "request_method", "request_path", "risk_score", "decision", "reason", "ts")), "");
        }
        System.out.println("SUMMARY checks=" + checks + " failed=" + failed);
        return failed == 0 ? 0 : 1;
    }

    /**
     * Reads all of stdin as UTF-8 lines. A leading byte-order mark is dropped: the .NET Process class of Windows PowerShell 5.1
     * prepends one to a redirected stdin when the console code page is UTF-8, and a BOM is never part of a user name or a secret.
     */
    private static List<String> readStdinLines() throws IOException {
        byte[] all = System.in.readAllBytes();
        int start = 0;
        if (all.length >= 3 && (all[0] & 0xFF) == 0xEF && (all[1] & 0xFF) == 0xBB && (all[2] & 0xFF) == 0xBF) start = 3;
        String text = new String(all, start, all.length - start, StandardCharsets.UTF_8);
        List<String> lines = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new java.io.StringReader(text))) {
            String line;
            while ((line = br.readLine()) != null) lines.add(line);
        }
        return lines;
    }

    private static int reset(String db) throws Exception {
        Map<String, String[]> input = new LinkedHashMap<>();
        for (String line : readStdinLines()) {
            if (line.trim().isEmpty()) continue;
            String[] p = line.split("\t", -1);
            if (p.length != 3 || p[0].isEmpty() || p[1].isEmpty() || p[2].isEmpty()) {
                System.out.println("input line has the wrong shape (expected username TAB password TAB pin)");
                return 2;
            }
            input.put(p[0], new String[] {p[1], p[2]});
        }
        List<String> wantNames = new ArrayList<>();
        for (String[] u : USERS) wantNames.add(u[0]);
        if (input.size() != USERS.length || !new TreeSet<>(input.keySet()).equals(new TreeSet<>(wantNames))) {
            System.out.println("input must contain exactly the 4 demo usernames");
            return 2;
        }
        try (Connection c = open(db, false)) {
            c.setAutoCommit(false);
            int updated = 0;
            try (PreparedStatement ps = c.prepareStatement("UPDATE users SET password_hash = ?, step_up_pin_hash = ? WHERE username = ?")) {
                for (Map.Entry<String, String[]> e : input.entrySet()) {
                    ps.setString(1, sha256Hex(e.getValue()[0]));
                    ps.setString(2, sha256Hex(e.getValue()[1]));
                    ps.setString(3, e.getKey());
                    int n = ps.executeUpdate();
                    if (n != 1) {
                        c.rollback();
                        System.out.println("expected to update exactly 1 row for a user, updated " + n + "; rolled back");
                        return 1;
                    }
                    updated++;
                }
            }
            c.commit();
            System.out.println("updated " + updated + " users (password hash and step-up PIN hash, 1 row each); no value printed");
        }
        return 0;
    }

    private static int check(String db, String username, String column) throws Exception {
        List<String> in = readStdinLines();
        String secret = in.isEmpty() ? "" : in.get(0);
        try (Connection c = open(db, true)) {
            // same shape as the legacy queries: SELECT ... WHERE username = ? AND <column> = ?
            String sql = "SELECT 1 FROM users WHERE username = ? AND " + column + " = ?";
            try (PreparedStatement ps = c.prepareStatement(sql)) {
                ps.setString(1, username);
                ps.setString(2, sha256Hex(secret));
                try (ResultSet r = ps.executeQuery()) {
                    boolean match = r.next();
                    System.out.println(match ? "MATCH" : "NO MATCH");
                    return match ? 0 : 1;
                }
            }
        }
    }
}
