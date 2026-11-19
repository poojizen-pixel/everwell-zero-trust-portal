package pdp.http;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

// Observer pattern: the SOC dashboard subscribes by registering its
// response stream here. RiskEngine/EvaluateHandler have no idea anyone is
// listening - they just call broadcast() after logging a risk_event, and
// every connected dashboard tab gets pushed the same event over SSE.
public class EventBroadcaster {
    private final List<OutputStream> subscribers = new CopyOnWriteArrayList<>();

    public void subscribe(OutputStream out) {
        subscribers.add(out);
    }

    public void broadcast(String json) {
        String frame = "data: " + json.replace("\n", "") + "\n\n";
        byte[] bytes = frame.getBytes(StandardCharsets.UTF_8);
        for (OutputStream out : subscribers) {
            try {
                out.write(bytes);
                out.flush();
            } catch (IOException e) {
                subscribers.remove(out);
            }
        }
    }
}
