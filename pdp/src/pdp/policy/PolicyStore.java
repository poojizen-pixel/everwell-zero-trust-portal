package pdp.policy;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import pdp.db.Database;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.List;

// Holds the active policy (loaded from / saved to the policy_settings table) and applies validated single-value changes.
public class PolicyStore {
    private static final Gson GSON = new GsonBuilder().setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES).create();
    private static final List<String> ACTIONS = Arrays.asList("ALLOW", "STEP_UP", "DENY", "REVOKE");

    private final Database db;
    private volatile Policy current;

    public PolicyStore(Database db) {
        this.db = db;
        String json = db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("SELECT json FROM policy_settings WHERE id = 1");
                 ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString(1) : null;
            }
        });
        if (json == null) {
            current = new Policy();
            save("system", current);
        } else {
            current = GSON.fromJson(json, Policy.class);   // fields missing in an older stored policy keep their defaults
        }
    }

    public Policy current() { return current; }

    public JsonObject currentJson() { return GSON.toJsonTree(current).getAsJsonObject(); }

    public static final class Change {
        public final String path, oldValue, newValue;
        Change(String path, String oldValue, String newValue) { this.path = path; this.oldValue = oldValue; this.newValue = newValue; }
    }

    // Throws IllegalArgumentException (message shown to the administrator) when the path or value is not acceptable.
    public synchronized Change set(String path, JsonElement value, String by) {
        if (path == null || path.isEmpty() || value == null) throw new IllegalArgumentException("path and value are required");
        JsonObject tree = currentJson();
        String[] parts = path.split("\\.");
        JsonObject node = tree;
        for (int i = 0; i < parts.length - 1; i++) {
            JsonElement e = node.get(parts[i]);
            if (e == null || !e.isJsonObject()) throw new IllegalArgumentException("unknown policy setting: " + path);
            node = e.getAsJsonObject();
        }
        String leaf = parts[parts.length - 1];
        JsonElement old = node.get(leaf);
        if (old == null || !old.isJsonPrimitive()) throw new IllegalArgumentException("unknown policy setting: " + path);
        if (!value.isJsonPrimitive()) throw new IllegalArgumentException("the value must be a number, a boolean or a string");
        JsonPrimitive oldP = old.getAsJsonPrimitive();
        JsonPrimitive newP = value.getAsJsonPrimitive();
        if (oldP.isBoolean() != newP.isBoolean() || oldP.isNumber() != newP.isNumber() || oldP.isString() != newP.isString()) {
            throw new IllegalArgumentException("wrong value type for " + path);
        }
        validate(path, newP);
        node.add(leaf, newP);
        Policy next = GSON.fromJson(tree, Policy.class);
        if (next.bands.allowBelow >= next.bands.stepUpBelow) throw new IllegalArgumentException("bands.allow_below must stay below bands.step_up_below");
        if (next.session.revokeThreshold < 1) throw new IllegalArgumentException("session.revoke_threshold must be at least 1");
        save(by, next);
        current = next;
        return new Change(path, old.getAsString(), newP.getAsString());
    }

    private static void validate(String path, JsonPrimitive v) {
        if (v.isString()) {
            String s = v.getAsString();
            if (!(path.endsWith("_action") || path.endsWith("on_blocked")) || !ACTIONS.contains(s)) {
                throw new IllegalArgumentException("not an accepted value for " + path + " (allowed: ALLOW, STEP_UP, DENY, REVOKE)");
            }
            if (path.equals("device.on_blocked") && !(s.equals("DENY") || s.equals("REVOKE"))) {
                throw new IllegalArgumentException("device.on_blocked accepts DENY or REVOKE");
            }
        } else if (v.isNumber()) {
            double d = v.getAsDouble();
            if (d != Math.rint(d) || d < 0 || d > 100000) throw new IllegalArgumentException("the value must be a whole number between 0 and 100000");
            if (path.equals("tokens.ttl_seconds") && (d < 10 || d > 3600)) throw new IllegalArgumentException("tokens.ttl_seconds must be between 10 and 3600");
            if (path.equals("session.idle_timeout_seconds") && d < 5) throw new IllegalArgumentException("session.idle_timeout_seconds must be at least 5 (a smaller value would end every session, including the administrator's)");
            if (path.equals("session.absolute_timeout_seconds") && d < 60) throw new IllegalArgumentException("session.absolute_timeout_seconds must be at least 60");
        }
    }

    private void save(String by, Policy p) {
        String json = GSON.toJson(p);
        db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO policy_settings (id, json, updated_ts, updated_by) VALUES (1, ?, ?, ?) "
                            + "ON CONFLICT(id) DO UPDATE SET json = excluded.json, updated_ts = excluded.updated_ts, updated_by = excluded.updated_by")) {
                ps.setString(1, json);
                ps.setLong(2, System.currentTimeMillis() / 1000);
                ps.setString(3, by);
                ps.executeUpdate();
            }
            return null;
        });
    }
}
