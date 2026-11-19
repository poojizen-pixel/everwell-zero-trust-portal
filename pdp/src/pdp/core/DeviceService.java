package pdp.core;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import pdp.db.Database;
import pdp.policy.Policy;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

// Device pillar. Two kinds of device with different evidence:
//   agent   - the laptop; firewall / antivirus are MEASURED by the C++ posture agent and arrive HMAC-signed with a fresh timestamp.
//   browser - the phone (or any browser); only what a web page can observe is SELF-REPORTED, the rest is SIMULATED (demo switches).
public class DeviceService {
    private final Database db;
    private volatile Set<String> localCache = Collections.emptySet();
    private volatile long localCacheTs;

    public DeviceService(Database db) { this.db = db; }

    public static class Row {
        public String deviceId, kind, hostname, os, signalsJson;
        public boolean firewall, antivirus, agentSimulated, sigValid, simScreenLock, simOsCurrent, simProtection;
        public long heartbeat;
    }

    public static class Posture {
        public boolean known, blocked;
        public String blockReason = "", label = "healthy", kind = "";
        public int score;
        public JsonArray signals = new JsonArray();   // [{name, value, source: measured|self-reported|simulated}]
    }

    public Row load(String deviceId) {
        return db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement(
                    "SELECT device_id, kind, hostname, os, firewall_active, antivirus_active, agent_simulated, last_heartbeat_ts, last_signature_valid, signals_json, "
                            + "sim_screen_lock, sim_os_current, sim_protection FROM devices WHERE device_id = ?")) {
                ps.setString(1, deviceId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) return null;
                    Row r = new Row();
                    r.deviceId = rs.getString(1); r.kind = rs.getString(2); r.hostname = rs.getString(3); r.os = rs.getString(4);
                    r.firewall = rs.getInt(5) == 1; r.antivirus = rs.getInt(6) == 1; r.agentSimulated = rs.getInt(7) == 1;
                    r.heartbeat = rs.getLong(8); r.sigValid = rs.getInt(9) == 1; r.signalsJson = rs.getString(10);
                    r.simScreenLock = rs.getInt(11) == 1; r.simOsCurrent = rs.getInt(12) == 1; r.simProtection = rs.getInt(13) == 1;
                    return r;
                }
            }
        });
    }

    public void upsertAgent(String deviceId, String hostname, String os, boolean fw, boolean av, boolean simulated, long now) {
        db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO devices (device_id, kind, hostname, os, firewall_active, antivirus_active, agent_simulated, last_heartbeat_ts, last_signature_valid) "
                            + "VALUES (?, 'agent', ?, ?, ?, ?, ?, ?, 1) ON CONFLICT(device_id) DO UPDATE SET hostname = excluded.hostname, os = excluded.os, "
                            + "firewall_active = excluded.firewall_active, antivirus_active = excluded.antivirus_active, agent_simulated = excluded.agent_simulated, "
                            + "last_heartbeat_ts = excluded.last_heartbeat_ts, last_signature_valid = 1 WHERE devices.kind = 'agent'")) {
                ps.setString(1, deviceId); ps.setString(2, hostname); ps.setString(3, os); ps.setInt(4, fw ? 1 : 0); ps.setInt(5, av ? 1 : 0);
                ps.setInt(6, simulated ? 1 : 0); ps.setLong(7, now);
                ps.executeUpdate();
            }
            return null;
        });
    }

    public void markBadSignature(String deviceId) {
        db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("UPDATE devices SET last_signature_valid = 0 WHERE device_id = ? AND kind = 'agent'")) {
                ps.setString(1, deviceId); ps.executeUpdate();
            }
            return null;
        });
    }

    // Returns false when the id already belongs to an agent device (a browser must not take over a measured laptop identity).
    public boolean upsertBrowser(String deviceId, String label, String os, String signalsJson, long now) {
        return db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement("SELECT kind FROM devices WHERE device_id = ?")) {
                ps.setString(1, deviceId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next() && !"browser".equals(rs.getString(1))) return false;
                }
            }
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO devices (device_id, kind, hostname, os, last_heartbeat_ts, last_signature_valid, signals_json) VALUES (?, 'browser', ?, ?, ?, 0, ?) "
                            + "ON CONFLICT(device_id) DO UPDATE SET hostname = excluded.hostname, os = excluded.os, last_heartbeat_ts = excluded.last_heartbeat_ts, signals_json = excluded.signals_json")) {
                ps.setString(1, deviceId); ps.setString(2, label); ps.setString(3, os); ps.setLong(4, now); ps.setString(5, signalsJson);
                ps.executeUpdate();
            }
            return true;
        });
    }

    public void setSim(String deviceId, Boolean screenLock, Boolean osCurrent, Boolean protection) {
        db.withConnection(conn -> {
            try (PreparedStatement ps = conn.prepareStatement(
                    "UPDATE devices SET sim_screen_lock = COALESCE(?, sim_screen_lock), sim_os_current = COALESCE(?, sim_os_current), sim_protection = COALESCE(?, sim_protection) "
                            + "WHERE device_id = ? AND kind = 'browser'")) {
                setBool(ps, 1, screenLock); setBool(ps, 2, osCurrent); setBool(ps, 3, protection); ps.setString(4, deviceId);
                ps.executeUpdate();
            }
            return null;
        });
    }

    private static void setBool(PreparedStatement ps, int i, Boolean b) throws java.sql.SQLException {
        if (b == null) ps.setNull(i, java.sql.Types.INTEGER); else ps.setInt(i, b ? 1 : 0);
    }

    public Posture evaluate(Row d, String ip, long now, Policy pol) {
        Posture p = new Posture();
        if (d == null) {
            p.blocked = true; p.blockReason = "this device is not registered"; p.label = "blocked";
            return p;
        }
        p.known = true;
        p.kind = d.kind;
        long age = Math.max(0, now - d.heartbeat);
        if ("agent".equals(d.kind)) {
            sig(p, "firewall", d.firewall ? "on" : "off", "measured by the posture agent (Windows Firewall, active profile)");
            sig(p, "antivirus", d.antivirus ? "registered" : "none", "measured by the posture agent (Windows Security Center lists a product; this does not prove real-time protection)");
            sig(p, "agent signature", d.sigValid ? "valid" : "INVALID", "measured (HMAC-SHA256 over every heartbeat, fresh timestamp required)");
            sig(p, "heartbeat age", age + " s", "measured");
            if (d.agentSimulated) sig(p, "agent mode", "SIMULATED", "the agent was started with a --fake-* demo flag");
            if (!d.sigValid) block(p, "agent heartbeat signature invalid (possible forged telemetry)");
            else if (age > pol.device.laptopStaleSeconds) block(p, "posture agent stopped: last heartbeat " + age + " s ago (limit " + pol.device.laptopStaleSeconds + " s)");
            else if (!isLocalAddress(ip)) block(p, "agent-verified laptop identity used from another machine (" + ip + ")");
            else {
                if (!d.firewall) p.score += pol.device.firewallOffScore;
                if (!d.antivirus) p.score += pol.device.antivirusOffScore;
            }
        } else {
            JsonObject sg = new JsonObject();
            try { if (d.signalsJson != null) sg = JsonParser.parseString(d.signalsJson).getAsJsonObject(); } catch (Exception ignored) { }
            boolean secure = !sg.has("secure_context") || sg.get("secure_context").getAsBoolean();
            sig(p, "secure context (HTTPS)", String.valueOf(secure), "self-reported by the page");
            sig(p, "installed app (standalone)", sg.has("standalone") ? sg.get("standalone").getAsString() : "unknown", "self-reported by the page");
            sig(p, "online", sg.has("online") ? sg.get("online").getAsString() : "unknown", "self-reported by the page");
            sig(p, "connection type", sg.has("connection") ? sg.get("connection").getAsString() : "not exposed by this browser", "self-reported by the page");
            sig(p, "screen lock", d.simScreenLock ? "enabled" : "disabled", "SIMULATED - a browser cannot read this");
            sig(p, "OS patch level", d.simOsCurrent ? "current" : "outdated", "SIMULATED - a browser cannot read this");
            sig(p, "device protection", d.simProtection ? "active" : "inactive", "SIMULATED - a browser cannot read this");
            sig(p, "heartbeat age", age + " s", "measured by the server");
            if (age > pol.device.phoneStaleSeconds) block(p, "browser heartbeat stale: " + age + " s (limit " + pol.device.phoneStaleSeconds + " s)");
            else if (!secure) block(p, "the page is not running in a secure context");
            else {
                p.score += pol.device.browserBaseScore;
                if (!d.simScreenLock) p.score += pol.device.screenLockOffScore;
                if (!d.simOsCurrent) p.score += pol.device.osOutdatedScore;
                if (!d.simProtection) p.score += pol.device.protectionOffScore;
            }
        }
        if (p.blocked) p.label = "blocked"; else if (p.score > ("agent".equals(d.kind) ? 0 : pol.device.browserBaseScore)) p.label = "degraded";
        return p;
    }

    private static void block(Posture p, String why) { p.blocked = true; p.blockReason = why; }

    private static void sig(Posture p, String name, String value, String source) {
        JsonObject o = new JsonObject();
        o.addProperty("name", name); o.addProperty("value", value); o.addProperty("source", source);
        p.signals.add(o);
    }

    public JsonArray list(long now) {
        return db.withConnection(conn -> {
            JsonArray a = new JsonArray();
            try (PreparedStatement ps = conn.prepareStatement("SELECT device_id FROM devices ORDER BY kind, device_id");
                 ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    Row d = load(rs.getString(1));
                    JsonObject o = new JsonObject();
                    o.addProperty("device_id", d.deviceId); o.addProperty("kind", d.kind); o.addProperty("hostname", d.hostname); o.addProperty("os", d.os);
                    o.addProperty("heartbeat_age", Math.max(0, now - d.heartbeat));
                    o.addProperty("firewall", d.firewall); o.addProperty("antivirus", d.antivirus); o.addProperty("agent_simulated", d.agentSimulated);
                    o.addProperty("sim_screen_lock", d.simScreenLock); o.addProperty("sim_os_current", d.simOsCurrent); o.addProperty("sim_protection", d.simProtection);
                    a.add(o);
                }
            }
            return a;
        });
    }

    // Agent devices with a recent heartbeat (the sign-in screen offers one as the "registered laptop"). Only the id the page needs to address
    // the device is returned: the computer name is never sent to the sign-in screen.
    public JsonArray freshAgents(long now, Policy pol) {
        JsonArray out = new JsonArray();
        JsonArray all = list(now);
        for (int i = 0; i < all.size(); i++) {
            JsonObject o = all.get(i).getAsJsonObject();
            if ("agent".equals(o.get("kind").getAsString()) && o.get("heartbeat_age").getAsLong() <= pol.device.laptopStaleSeconds * 5L) {
                JsonObject x = new JsonObject();
                x.addProperty("device_id", o.get("device_id").getAsString());
                out.add(x);
            }
        }
        return out;
    }

    public boolean isLocalAddress(String ip) {
        long now = System.currentTimeMillis();
        if (now - localCacheTs > 30_000) {
            Set<String> s = new HashSet<>();
            try {
                Enumeration<NetworkInterface> nics = NetworkInterface.getNetworkInterfaces();
                while (nics != null && nics.hasMoreElements()) {
                    Enumeration<InetAddress> addrs = nics.nextElement().getInetAddresses();
                    while (addrs.hasMoreElements()) s.add(normalize(addrs.nextElement().getHostAddress()));
                }
            } catch (Exception ignored) { }
            s.add("127.0.0.1");
            s.add("0:0:0:0:0:0:0:1");
            localCache = s;
            localCacheTs = now;
        }
        return localCache.contains(normalize(ip));
    }

    public static String normalize(String ip) {
        if (ip == null) return "";
        try { return InetAddress.getByName(ip.split("%")[0]).getHostAddress(); } catch (Exception e) { return ip; }
    }
}
