package pdp.seed;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import pdp.crypto.PasswordHasher;
import pdp.db.Database;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

// Creates the demo accounts (synthetic people, generated per-run passwords) the first time the database is empty.
// The launcher writes a JSON file [{username, display_name, role, ward, password, pin}]; it is hashed here (PBKDF2, salted) and the file is
// deleted as soon as it has been used, so no plain-text secret stays in the run folder except the presenter's credentials sheet.
public class Seeder {
    public static void seedUsers(Database db, String file, int iterations) throws Exception {
        boolean empty = db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("SELECT COUNT(*) FROM users"); ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1) == 0;
            }
        });
        if (!empty) { System.out.println("[PDP] Users already present, no seeding."); return; }
        if (file == null) { System.out.println("[PDP] No users and no seed file configured (zt.seed.users): nobody can sign in."); return; }
        Path path = Paths.get(file);
        if (!Files.exists(path)) { System.out.println("[PDP] Seed file not found: " + path); return; }
        JsonArray arr = JsonParser.parseString(new String(Files.readAllBytes(path), StandardCharsets.UTF_8)).getAsJsonArray();
        int n = 0;
        for (JsonElement el : arr) {
            JsonObject o = el.getAsJsonObject();
            String role = o.get("role").getAsString();
            String id = "U-" + role.substring(0, 3).toUpperCase() + "-" + String.format("%03d", ++n);
            String ward = o.has("ward") && !o.get("ward").isJsonNull() ? o.get("ward").getAsString() : null;
            String pwHash = PasswordHasher.hash(o.get("password").getAsString(), iterations);
            String pinHash = PasswordHasher.hash(o.get("pin").getAsString(), iterations);
            db.withConnection(conn -> {
                try (PreparedStatement ps = conn.prepareStatement(
                        "INSERT INTO users (user_id, username, display_name, password_hash, step_up_pin_hash, role, ward) VALUES (?,?,?,?,?,?,?)")) {
                    ps.setString(1, id); ps.setString(2, o.get("username").getAsString()); ps.setString(3, o.get("display_name").getAsString());
                    ps.setString(4, pwHash); ps.setString(5, pinHash); ps.setString(6, role);
                    if (ward == null) ps.setNull(7, java.sql.Types.VARCHAR); else ps.setString(7, ward);
                    ps.executeUpdate();
                }
                return null;
            });
        }
        Files.delete(path);
        System.out.println("[PDP] Seeded " + n + " demo accounts (salted PBKDF2 hashes); the seed file was deleted.");
    }
}
