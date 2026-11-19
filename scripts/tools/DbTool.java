import java.io.File;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Small database utility for the build and test scripts. It never prints a row value.
 *
 *   check  db            integrity_check, foreign_key_check, journal mode and row counts
 *   digest db            one SHA-256 per table over all row contents, to compare two copies without exposing data
 *   backup src dest      SQLite online backup (VACUUM INTO) of a database that may still have a -wal file; it then
 *                        verifies that source and backup have identical per-table digests
 *
 * Run it only against disposable copies. scripts/backup-db.ps1 refuses the project's live database folder.
 */
public final class DbTool {
    private DbTool() { }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            usage();
            System.exit(2);
        }
        int code;
        switch (args[0]) {
            case "check":
                code = check(args[1]);
                break;
            case "digest":
                code = digest(args[1]);
                break;
            case "backup":
                if (args.length < 3) {
                    usage();
                    code = 2;
                } else {
                    code = backup(args[1], args[2]);
                }
                break;
            default:
                usage();
                code = 2;
        }
        System.exit(code);
    }

    private static void usage() {
        System.out.println("usage: DbTool check <db> | digest <db> | backup <src-db> <dest-db>");
    }

    private static Connection open(String db) throws SQLException {
        return DriverManager.getConnection("jdbc:sqlite:" + db);
    }

    private static String scalar(Connection c, String sql) throws SQLException {
        try (Statement s = c.createStatement(); ResultSet r = s.executeQuery(sql)) {
            return r.next() ? String.valueOf(r.getObject(1)) : "(none)";
        }
    }

    private static List<String> firstColumn(Connection c, String sql) throws SQLException {
        List<String> out = new ArrayList<>();
        try (Statement s = c.createStatement(); ResultSet r = s.executeQuery(sql)) {
            while (r.next()) out.add(r.getString(1));
        }
        return out;
    }

    private static List<String> tables(Connection c) throws SQLException {
        return firstColumn(c, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name");
    }

    private static int check(String db) throws Exception {
        if (!new File(db).isFile()) {
            System.out.println("database file not found: " + db);
            return 2;
        }
        boolean ok = true;
        try (Connection c = open(db)) {
            System.out.println("database          : " + db);
            System.out.println("sqlite_version    : " + scalar(c, "SELECT sqlite_version()"));
            System.out.println("journal_mode      : " + scalar(c, "PRAGMA journal_mode"));
            System.out.println("user_version      : " + scalar(c, "PRAGMA user_version"));
            List<String> ic = firstColumn(c, "PRAGMA integrity_check");
            boolean icOk = ic.size() == 1 && ic.get(0).equals("ok");
            System.out.println("integrity_check   : " + (icOk ? "ok" : "PROBLEMS " + ic));
            ok &= icOk;
            int fk = firstColumn(c, "PRAGMA foreign_key_check").size();
            System.out.println("foreign_key_check : " + fk + " violations");
            ok &= fk == 0;
            for (String t : tables(c)) {
                System.out.println("rows " + t + " = " + scalar(c, "SELECT COUNT(*) FROM \"" + t + "\""));
            }
        }
        System.out.println("RESULT: " + (ok ? "PASS" : "FAIL"));
        return ok ? 0 : 1;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    private static String hex(byte[] d) {
        StringBuilder sb = new StringBuilder();
        for (byte x : d) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static ResultSet selectAll(Statement s, String table) throws SQLException {
        try {
            return s.executeQuery("SELECT * FROM \"" + table + "\" ORDER BY rowid");
        } catch (SQLException e) {
            return s.executeQuery("SELECT * FROM \"" + table + "\"");
        }
    }

    /** table name -> "rows=N sha256=..." over every column of every row. */
    private static Map<String, String> digests(Connection c) throws Exception {
        Map<String, String> out = new TreeMap<>();
        for (String t : tables(c)) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            long rows = 0;
            try (Statement s = c.createStatement(); ResultSet r = selectAll(s, t)) {
                int n = r.getMetaData().getColumnCount();
                while (r.next()) {
                    rows++;
                    for (int i = 1; i <= n; i++) {
                        Object o = r.getObject(i);
                        byte[] b;
                        if (o == null) b = new byte[] {0};
                        else if (o instanceof byte[]) b = concat(new byte[] {2}, (byte[]) o);
                        else b = concat(new byte[] {1}, String.valueOf(o).getBytes("UTF-8"));
                        md.update(b);
                        md.update((byte) 0x1F);
                    }
                    md.update((byte) 0x1E);
                }
            }
            out.put(t, "rows=" + rows + " sha256=" + hex(md.digest()));
        }
        return out;
    }

    private static int digest(String db) throws Exception {
        if (!new File(db).isFile()) {
            System.out.println("database file not found: " + db);
            return 2;
        }
        try (Connection c = open(db)) {
            for (Map.Entry<String, String> e : digests(c).entrySet()) {
                System.out.println(String.format("%-24s %s", e.getKey(), e.getValue()));
            }
        }
        return 0;
    }

    private static int backup(String src, String dest) throws Exception {
        if (!new File(src).isFile()) {
            System.out.println("source database not found: " + src);
            return 2;
        }
        if (new File(dest).exists()) {
            System.out.println("Refusing: destination already exists: " + dest);
            return 2;
        }
        Map<String, String> before;
        try (Connection c = open(src)) {
            before = digests(c);
            try (Statement s = c.createStatement()) {
                s.execute("VACUUM INTO '" + dest.replace("'", "''") + "'");
            }
        }
        Map<String, String> after;
        try (Connection c = open(dest)) {
            after = digests(c);
        }
        boolean same = before.equals(after);
        System.out.println("tables compared   : " + before.size());
        System.out.println("backup written    : " + dest);
        System.out.println("BACKUP: " + (same ? "OK (every per-table digest is identical)" : "FAIL (per-table digests differ)"));
        return same ? 0 : 1;
    }
}
