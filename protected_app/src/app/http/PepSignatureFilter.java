package app.http;

import app.Config;
import app.crypto.HmacSigner;
import com.sun.net.httpserver.Filter;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

// Applied to every context: this workload does not trust "the request reached me on port 9000". It verifies an HMAC that only the PEP
// can produce over the method, path, timestamp AND the identity claims of the PDP decision (user, role, ward, access basis, session).
// A caller without the shared secret gets nothing, and the claims cannot be altered or replayed after the timestamp window.
public class PepSignatureFilter extends Filter {
    public static final String CLAIMS_ATTRIBUTE = "zt.claims";
    private final HmacSigner signer = new HmacSigner(Config.PEP_SHARED_SECRET);

    @Override
    public String description() {
        return "Rejects any request not signed by the PEP";
    }

    @Override
    public void doFilter(HttpExchange exchange, Chain chain) throws IOException {
        String timestamp = exchange.getRequestHeaders().getFirst("X-PEP-Timestamp");
        String signature = exchange.getRequestHeaders().getFirst("X-PEP-Signature");
        String user = header(exchange, "X-ZT-User"), role = header(exchange, "X-ZT-Role"), ward = header(exchange, "X-ZT-Ward");
        String basis = header(exchange, "X-ZT-Basis"), session = header(exchange, "X-ZT-Session");

        if (timestamp == null || signature == null || user.isEmpty() || role.isEmpty() || session.isEmpty()) {
            reject(exchange, "missing PEP signature or identity headers - this workload only accepts requests forwarded by the PEP");
            return;
        }
        String method = exchange.getRequestMethod();
        String path = exchange.getRequestURI().getRawPath();
        String canonical = String.join("|", method, path, timestamp, user, role, ward, basis, session);
        if (!signer.verifyHex(canonical, signature)) {
            reject(exchange, "invalid PEP signature");
            return;
        }
        long ts;
        try {
            ts = Long.parseLong(timestamp);
        } catch (NumberFormatException e) {
            reject(exchange, "malformed PEP timestamp");
            return;
        }
        long now = System.currentTimeMillis() / 1000;
        if (Math.abs(now - ts) > Config.PEP_SIGNATURE_MAX_AGE_SECONDS) {
            reject(exchange, "PEP signature expired - possible replay");
            return;
        }
        exchange.setAttribute(CLAIMS_ATTRIBUTE, new Claims(user, role, ward, basis, session));
        chain.doFilter(exchange);
    }

    private static String header(HttpExchange ex, String name) {
        String v = ex.getRequestHeaders().getFirst(name);
        return v == null ? "" : v;
    }

    private void reject(HttpExchange exchange, String reason) throws IOException {
        String body = "{\"error\":\"forbidden\",\"reason\":\"" + reason + "\"}";
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(403, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
