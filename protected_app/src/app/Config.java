package app;

import java.nio.file.Path;
import java.nio.file.Paths;

// Same rules as pdp.Config: settings come from -Dzt.x / ZT_X environment variables, secrets and paths have no defaults,
// and the legacy live database can never be opened by accident.
public final class Config {
    private Config() {}

    private static String raw(String key) {
        String v = System.getProperty(key);
        if (v == null || v.isEmpty()) v = System.getenv(key.toUpperCase().replace('.', '_'));
        return (v == null || v.isEmpty()) ? null : v;
    }

    private static String req(String key) {
        String v = raw(key);
        if (v == null) {
            throw new IllegalStateException("missing required setting '" + key + "' (system property -D" + key
                    + " or environment variable " + key.toUpperCase().replace('.', '_') + ")");
        }
        return v;
    }

    private static String opt(String key, String def) {
        String v = raw(key);
        return v == null ? def : v;
    }

    public static final int PORT = Integer.parseInt(opt("zt.app.port", "9000"));
    public static final String BIND_HOST = opt("zt.app.bind", "127.0.0.1"); // never wildcard - unreachable except via the PEP

    public static final String DB_PATH = req("zt.db");
    public static final String KEYSTORE_PATH = req("zt.app.keystore");
    public static final String KEYSTORE_PASSWORD = req("zt.app.keystore.password");

    // Must match the PEP's ZT_PEP_APP_SECRET.
    public static final String PEP_SHARED_SECRET = req("zt.pep.app.secret");
    public static final long PEP_SIGNATURE_MAX_AGE_SECONDS = Long.parseLong(opt("zt.pep.sigmaxage", "5"));

    // Key material (SHA-256 of a passphrase, giving exactly 32 bytes for AES-256) held ONLY by this process.
    public static final String PATIENT_DATA_PASSPHRASE = req("zt.patient.passphrase");

    static {
        Path db = Paths.get(DB_PATH).toAbsolutePath().normalize();
        Path live = Paths.get("C:/Ap project/db/zero_trust.db").toAbsolutePath().normalize();
        if (db.toString().equalsIgnoreCase(live.toString()) && !"true".equals(raw("zt.allow.live"))) {
            throw new IllegalStateException("refusing to run against the legacy live database " + live);
        }
    }
}
