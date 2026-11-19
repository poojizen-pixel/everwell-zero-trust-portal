package pdp;

import java.nio.file.Path;
import java.nio.file.Paths;

// Every setting comes from a system property (-Dzt.x=...) or an environment variable (ZT_X).
// Secrets and file locations deliberately have NO defaults: the process refuses to start without them, so it can never run
// with hard-coded keys, and it can never be pointed at the legacy live database by accident (see the guard at the bottom).
public final class Config {
    private Config() {}

    private static String raw(String key) {
        String v = System.getProperty(key);
        if (v == null || v.isEmpty()) v = System.getenv(key.toUpperCase().replace('.', '_'));
        return (v == null || v.isEmpty()) ? null : v;
    }

    static String req(String key) {
        String v = raw(key);
        if (v == null) {
            throw new IllegalStateException("missing required setting '" + key + "' (system property -D" + key
                    + " or environment variable " + key.toUpperCase().replace('.', '_') + ")");
        }
        return v;
    }

    static String opt(String key, String def) {
        String v = raw(key);
        return v == null ? def : v;
    }

    static long optLong(String key, long def) {
        String v = raw(key);
        return v == null ? def : Long.parseLong(v.trim());
    }

    // Shared secret the C++ posture agent signs telemetry heartbeats with (generated per run by the launcher).
    public static final String AGENT_HMAC_SECRET = req("zt.agent.secret");

    // Signs the session tokens issued to clients after login (generated per run by the launcher).
    public static final String TOKEN_HMAC_SECRET = req("zt.token.secret");

    // Only the PEP knows this key; every /pdp/* call from the PEP carries it (X-Internal-Key). Telemetry uses its own HMAC.
    public static final String INTERNAL_KEY = req("zt.internal.key");

    public static final String BIND_HOST = opt("zt.pdp.bind", "127.0.0.1"); // internal component: loopback only by default
    public static final int PORT = (int) optLong("zt.pdp.port", 8443);
    public static final String DB_PATH = req("zt.db");
    public static final String SCHEMA_PATH = req("zt.schema");
    public static final String KEYSTORE_PATH = req("zt.pdp.keystore");
    public static final String KEYSTORE_PASSWORD = req("zt.pdp.keystore.password");

    // Optional JSON file with the demo accounts (plain text secrets) written by the launcher; it is deleted after it has been used.
    public static final String SEED_USERS_FILE = opt("zt.seed.users", null);
    public static final int PBKDF2_ITERATIONS = (int) optLong("zt.pbkdf2.iterations", 310_000);

    static {
        // The legacy live database lives at C:/Ap project/db/zero_trust.db and must never be opened by this program.
        Path db = Paths.get(DB_PATH).toAbsolutePath().normalize();
        Path live = Paths.get("C:/Ap project/db/zero_trust.db").toAbsolutePath().normalize();
        if (db.toString().equalsIgnoreCase(live.toString()) && !"true".equals(raw("zt.allow.live"))) {
            throw new IllegalStateException("refusing to run against the legacy live database " + live);
        }
    }
}
