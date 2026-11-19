package pdp.http.handlers;

import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import pdp.core.Decider;
import pdp.core.Decision;
import pdp.core.DecisionRequest;
import pdp.http.HttpUtil;

import java.io.IOException;

// POST /pdp/evaluate - the PEP calls this for EVERY /api request, no exceptions. The answer is always HTTP 200 with the
// decision in the body (http_status says what the PEP should return to the client). Any error here is a DENY, never a pass-through.
public class EvaluateHandler implements HttpHandler {
    private final Decider decider;

    public EvaluateHandler(Decider decider) { this.decider = decider; }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        Decision d;
        try {
            d = evaluate(exchange);
        } catch (Exception unexpected) {
            d = new Decision().deny(500, "internal_error", "The policy decision point could not evaluate the request (fail closed).");
        }
        HttpUtil.sendJson(exchange, 200, d.toJson());
    }

    private Decision evaluate(HttpExchange exchange) throws IOException {
        Decision bad = new Decision().deny(400, "bad_request", "Malformed request.");
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) return bad;
        JsonObject b;
        try {
            b = HttpUtil.readJsonBody(exchange);
        } catch (Exception e) {
            return bad;
        }
        DecisionRequest r = new DecisionRequest();
        r.token = HttpUtil.str(b, "token");
        r.deviceId = HttpUtil.str(b, "device_id");
        r.clientIp = HttpUtil.str(b, "origin_ip");
        r.method = HttpUtil.str(b, "method");
        r.path = HttpUtil.str(b, "path");
        String q = HttpUtil.str(b, "query");
        r.query = q == null ? "" : q;
        r.stepUpPin = HttpUtil.str(b, "step_up_pin");
        if (r.deviceId == null || r.clientIp == null || r.method == null || r.path == null) return bad;
        if (r.path.length() > 512 || r.deviceId.length() > 128 || (r.token != null && r.token.length() > 2048)
                || (r.stepUpPin != null && r.stepUpPin.length() > 64)) return bad;
        return decider.decide(r);
    }
}
