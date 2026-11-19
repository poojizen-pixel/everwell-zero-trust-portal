package pdp.http.handlers;

import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import pdp.core.DeviceService;
import pdp.crypto.HmacSigner;
import pdp.http.HttpUtil;

import java.io.IOException;

// POST /pip/telemetry - the posture information point. Receives the C++ agent's signed heartbeat.
// The signature covers every field including the timestamp, and the timestamp must be fresh (replay protection): a captured
// heartbeat cannot keep a stopped agent "alive". An invalid signature never updates the posture, it only flags the device
// (DeviceService treats a flagged device as hard-blocked on the next evaluation).
public class TelemetryHandler implements HttpHandler {
    private static final long MAX_SKEW_SECONDS = 30;
    private final DeviceService devices;
    private final HmacSigner agentSigner;

    public TelemetryHandler(DeviceService devices, HmacSigner agentSigner) {
        this.devices = devices;
        this.agentSigner = agentSigner;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            HttpUtil.sendJson(exchange, 405, error("method not allowed"));
            return;
        }
        JsonObject body;
        try {
            body = HttpUtil.readJsonBody(exchange);
        } catch (Exception e) {
            HttpUtil.sendJson(exchange, 400, error("malformed json"));
            return;
        }
        try {
            String deviceId = HttpUtil.str(body, "device_id");
            String hostname = nz(HttpUtil.str(body, "hostname"));
            String os = nz(HttpUtil.str(body, "os"));
            boolean firewall = bool(body, "firewall_active");
            boolean antivirus = bool(body, "antivirus_active");
            boolean simulated = bool(body, "simulated");
            long timestamp = body.has("timestamp") ? body.get("timestamp").getAsLong() : 0;
            String signature = HttpUtil.str(body, "signature");
            if (deviceId == null || signature == null || deviceId.length() > 80 || hostname.length() > 80 || os.length() > 40) {
                HttpUtil.sendJson(exchange, 400, error("missing or oversized fields"));
                return;
            }
            String canonical = String.join("|", deviceId, hostname, os, Boolean.toString(firewall), Boolean.toString(antivirus),
                    Boolean.toString(simulated), Long.toString(timestamp));
            long now = System.currentTimeMillis() / 1000;
            if (!agentSigner.verifyHex(canonical, signature)) {
                devices.markBadSignature(deviceId);
                HttpUtil.sendJson(exchange, 401, error("signature verification failed"));
                return;
            }
            if (Math.abs(now - timestamp) > MAX_SKEW_SECONDS) {
                HttpUtil.sendJson(exchange, 401, error("stale timestamp (replay protection)"));
                return;
            }
            devices.upsertAgent(deviceId, hostname, os, firewall, antivirus, simulated, now);
            JsonObject ok = new JsonObject();
            ok.addProperty("status", "ok");
            HttpUtil.sendJson(exchange, 200, ok);
        } catch (RuntimeException e) {
            HttpUtil.sendJson(exchange, 400, error("malformed telemetry"));
        }
    }

    private static boolean bool(JsonObject o, String key) {
        return o.has(key) && o.get(key).isJsonPrimitive() && o.get(key).getAsBoolean();
    }

    private static String nz(String s) { return s == null ? "" : s; }

    private static JsonObject error(String reason) {
        JsonObject o = new JsonObject();
        o.addProperty("status", "error");
        o.addProperty("reason", reason);
        return o;
    }
}
