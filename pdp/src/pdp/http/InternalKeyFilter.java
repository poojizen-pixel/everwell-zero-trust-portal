package pdp.http;

import com.sun.net.httpserver.Filter;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

// The PDP's decision and gateway endpoints are for the PEP only. Without the per-run internal key a request is refused, so another
// local program cannot feed the PDP a forged client address or call the administration functions around the PEP.
public class InternalKeyFilter extends Filter {
    private final String key;

    public InternalKeyFilter(String key) { this.key = key; }

    @Override
    public String description() { return "requires the PEP's internal key"; }

    @Override
    public void doFilter(HttpExchange exchange, Chain chain) throws IOException {
        String v = exchange.getRequestHeaders().getFirst("X-Internal-Key");
        if (!HttpUtil.constantTimeEquals(key, v)) {
            byte[] b = "{\"error\":\"forbidden\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(403, b.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(b); }
            return;
        }
        chain.doFilter(exchange);
    }
}
