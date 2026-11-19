package pdp.db;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

// All access goes through withConnection(), synchronized on this instance -
// SQLite has no meaningful concurrent-writer story, so requests are
// serialized here rather than pretending a connection pool would help.
public class Database {
    private final Connection conn;

    public Database(String sqliteFilePath) throws SQLException {
        this.conn = DriverManager.getConnection("jdbc:sqlite:" + sqliteFilePath);
        try (Statement st = conn.createStatement()) {
            st.execute("PRAGMA foreign_keys = ON");
            st.execute("PRAGMA journal_mode = WAL");
        }
    }

    public void applySchema(String schemaFilePath) throws SQLException, IOException {
        String schema = new String(Files.readAllBytes(Paths.get(schemaFilePath)));
        try (Statement st = conn.createStatement()) {
            st.executeUpdate(schema);
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
