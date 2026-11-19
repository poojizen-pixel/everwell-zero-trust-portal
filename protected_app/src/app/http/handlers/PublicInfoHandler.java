package app.http.handlers;

import app.http.HttpUtil;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;

public class PublicInfoHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        JsonObject o = new JsonObject();
        o.addProperty("hospital", "Everwell Hospital");
        o.addProperty("hours", "24/7 Emergency, 8am-6pm Outpatient");
        o.addProperty("departments", "Cardiology, Endocrinology, Pulmonology, General Medicine");
        HttpUtil.sendJson(exchange, 200, o.toString());
    }
}
