package edge;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.regex.Pattern;

// Two jobs only: (1) serve the public static shell of the portal, (2) relay /api, /ctl and /admin to the PEP.
// It never inspects or caches protected data and never trusts a client-supplied X-Forwarded-For.
class EdgeHandler implements HttpHandler {
    private static final int MAX_BODY = 64 * 1024;
    private static final Pattern STATIC = Pattern.compile("^/(index\\.html|app\\.js|styles\\.css|manifest\\.webmanifest|sw\\.js|offline\\.html|favicon\\.png|icons/[A-Za-z0-9_-]+\\.png)$");
    private static final String CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; "
            + "manifest-src 'self'; worker-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'";

    private final Path web;
    private final URI pep;
    private final String edgeKey;
    private final HttpClient client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(3)).build();

    EdgeHandler(Path web, URI pep, String edgeKey) {
        this.web = web;
        this.pep = pep;
        this.edgeKey = edgeKey;
    }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        int status = 500;
        try {
            status = route(ex);
        } catch (Exception e) {
            try { send(ex, 500, "application/json", "{\"error\":\"internal_error\",\"message\":\"The edge could not process the request.\"}", false); } catch (Exception ignored) { }
        } finally {
            System.out.println("[EDGE] " + ex.getRemoteAddress().getAddress().getHostAddress() + " " + ex.getRequestMethod() + " " + ex.getRequestURI().getRawPath() + " -> " + status);
            ex.close();
        }
    }

    private int route(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getRawPath();
        String method = ex.getRequestMethod();
        if (path == null || path.isEmpty()) path = "/";
        if (path.equals("/healthz")) return send(ex, 200, "application/json", "{\"status\":\"ok\"}", false);
        if (path.startsWith("/api/") || path.startsWith("/ctl/") || path.startsWith("/admin/")) {
            if (!method.equals("GET") && !method.equals("POST")) return send(ex, 405, "application/json", "{\"error\":\"method_not_allowed\",\"message\":\"Only GET and POST are used.\"}", false);
            return relay(ex, method, path, ex.getRequestURI().getRawQuery());
        }
        if (method.equals("GET") || method.equals("HEAD")) return serveStatic(ex, path, method.equals("HEAD"));
        return send(ex, 405, "application/json", "{\"error\":\"method_not_allowed\",\"message\":\"Only GET and POST are used.\"}", false);
    }

    private int serveStatic(HttpExchange ex, String path, boolean head) throws IOException {
        String rel = path.equals("/") ? "index.html" : path.substring(1);
        if (!path.equals("/") && !STATIC.matcher(path).matches()) return send(ex, 404, "text/plain; charset=utf-8", "Not found", head);
        Path file = web.resolve(rel).normalize();
        if (!file.startsWith(web) || !Files.isRegularFile(file)) return send(ex, 404, "text/plain; charset=utf-8", "Not found", head);
        byte[] bytes = Files.readAllBytes(file);
        String type = rel.endsWith(".html") ? "text/html; charset=utf-8" : rel.endsWith(".js") ? "text/javascript; charset=utf-8"
                : rel.endsWith(".css") ? "text/css; charset=utf-8" : rel.endsWith(".webmanifest") ? "application/manifest+json"
                : rel.endsWith(".png") ? "image/png" : "application/octet-stream";
        Headers h = ex.getResponseHeaders();
        h.set("Content-Type", type);
        h.set("Cache-Control", rel.startsWith("icons/") ? "public, max-age=3600" : "no-cache");   // the service worker revalidates the shell; nothing here is protected data
        securityHeaders(h);
        h.set("Content-Security-Policy", CSP);
        if (rel.equals("sw.js")) h.set("Service-Worker-Allowed", "/");
        ex.sendResponseHeaders(200, head ? -1 : bytes.length);
        if (!head) try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
        return 200;
    }

    private int relay(HttpExchange ex, String method, String path, String query) throws IOException {
        byte[] body = readBounded(ex.getRequestBody());
        if (body == null) return send(ex, 413, "application/json", "{\"error\":\"payload_too_large\",\"message\":\"The request body is too large.\"}", false);
        HttpRequest.Builder b;
        try {
            b = HttpRequest.newBuilder(URI.create(pep.toString() + path + (query == null ? "" : "?" + query))).timeout(Duration.ofSeconds(30));
        } catch (IllegalArgumentException bad) {
            return send(ex, 400, "application/json", "{\"error\":\"bad_request\",\"message\":\"The request target is not valid.\"}", false);
        }
        b.method(method, body.length == 0 && method.equals("GET") ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body));
        // whitelist: nothing else from the client reaches the PEP (no cookies, no forwarded-for, no host tricks)
        for (String name : new String[]{"Authorization", "X-Device-Id", "X-StepUp-Pin", "Content-Type"}) {
            String v = ex.getRequestHeaders().getFirst(name);
            if (v != null && v.length() <= 4096 && !name.equals("Content-Type")) b.header(name, v);
            if (name.equals("Content-Type") && v != null && body.length > 0) b.header(name, v);
        }
        b.header("X-Forwarded-For", ex.getRemoteAddress().getAddress().getHostAddress());
        b.header("X-Edge-Key", edgeKey);
        HttpResponse<byte[]> r;
        try {
            r = client.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            return send(ex, 502, "application/json", "{\"error\":\"bad_gateway\",\"message\":\"The portal back end did not answer.\"}", false);
        } catch (Exception e) {
            return send(ex, 502, "application/json", "{\"error\":\"bad_gateway\",\"message\":\"The portal back end did not answer.\"}", false);
        }
        Headers h = ex.getResponseHeaders();
        h.set("Content-Type", r.headers().firstValue("Content-Type").orElse("application/json"));
        h.set("Cache-Control", "no-store");
        securityHeaders(h);
        byte[] out = r.body();
        ex.sendResponseHeaders(r.statusCode(), out.length == 0 ? -1 : out.length);
        if (out.length > 0) try (OutputStream os = ex.getResponseBody()) { os.write(out); }
        return r.statusCode();
    }

    private static void securityHeaders(Headers h) {
        h.set("X-Content-Type-Options", "nosniff");
        h.set("Referrer-Policy", "no-referrer");
        h.set("X-Frame-Options", "DENY");
        h.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
        h.set("Cross-Origin-Opener-Policy", "same-origin");
        h.set("Cross-Origin-Resource-Policy", "same-origin");
    }

    private static byte[] readBounded(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        int n;
        while ((n = in.read(chunk)) != -1) {
            buf.write(chunk, 0, n);
            if (buf.size() > MAX_BODY) return null;
        }
        return buf.toByteArray();
    }

    private static int send(HttpExchange ex, int status, String type, String text, boolean head) throws IOException {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        Headers h = ex.getResponseHeaders();
        h.set("Content-Type", type);
        h.set("Cache-Control", "no-store");
        securityHeaders(h);
        ex.sendResponseHeaders(status, head ? -1 : bytes.length);
        if (!head) try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
        return status;
    }
}
