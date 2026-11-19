package pdp.http.handlers;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import pdp.http.EventBroadcaster;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

// GET /pdp/events/stream - the dashboard's SSE subscription. This handler's
// only job is to register the connection with EventBroadcaster and leave it
// open; it never learns about risk_events itself (Observer pattern).
public class EventsStreamHandler implements HttpHandler {
    private final EventBroadcaster broadcaster;

    public EventsStreamHandler(EventBroadcaster broadcaster) {
        this.broadcaster = broadcaster;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "text/event-stream");
        exchange.getResponseHeaders().set("Cache-Control", "no-cache");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.sendResponseHeaders(200, 0); // chunked, connection stays open

        OutputStream os = exchange.getResponseBody();
        broadcaster.subscribe(os);
        os.write(": connected\n\n".getBytes(StandardCharsets.UTF_8));
        os.flush();
    }
}
