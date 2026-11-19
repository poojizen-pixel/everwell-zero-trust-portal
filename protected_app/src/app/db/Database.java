package app.db;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

// Same shared-SQLite-file pattern as the PDP's Database class: the PDP owns
// devices/sessions/risk_events/users/policies/role_permissions/endpoints,
// this process owns patients/patient_assignments, both processes read the
// same file (WAL mode) since SQLite handles concurrent readers fine.
public class Database {
    private final Connection conn;

    public Database(String sqliteFilePath) throws SQLException {
        this.conn = DriverManager.getConnection("jdbc:sqlite:" + sqliteFilePath);
        try (Statement st = conn.createStatement()) {
            st.execute("PRAGMA foreign_keys = ON");
            st.execute("PRAGMA journal_mode = WAL");
        }
    }

    public synchronized <T> T withConnection(SqlFunction<T> fn) {
        try {
            return fn.apply(conn);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @FunctionalInterface
    public interface SqlFunction<T> {
        T apply(Connection conn) throws SQLException;
    }
}
