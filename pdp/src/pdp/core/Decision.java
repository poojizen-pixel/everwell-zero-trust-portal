package pdp.core;

import com.google.gson.JsonObject;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

// The outcome of one policy evaluation. action: ALLOW | STEP_UP | DENY.  A request that ends the session is a DENY with sessionRevoked = true.
public class Decision {
    private static final Pattern LOCKED_UNTIL = Pattern.compile("locked until (\\d{1,2}:\\d{2})");

    public String action = "DENY";
    public int httpStatus = 403;
    public String code = "denied";
    public String message = "";
    public int riskScore;          // risk of this request
    public int penalty;            // points this decision adds to the session risk
    public int sessionRisk;        // session risk after this decision
    public int threshold;          // revoke threshold of the active policy
    public boolean sessionRevoked;
    public String breakdown = "";
    public Principal principal;
    // Need-to-know: risk figures, thresholds, scoring detail and policy wording go to the security administrator, and to other roles only while
    // the administrator has left the evaluation tools enabled (policy simulation.enabled). With false the client gets the plain outcome only.
    // The audit log always receives the full detail (it is written from message / breakdown, not from what is sent to the client).
    public boolean detail = true;

    public boolean allowed() { return "ALLOW".equals(action); }

    public Decision deny(int status, String code, String message) {
        this.action = "DENY";
        this.httpStatus = status;
        this.code = code;
        this.message = message;
        return this;
    }

    // What the client is told. Without need-to-know for risk detail the text says what happened and what to do, and never a score, a limit, a
    // network address, a posture detail or the reason an account was locked.
    String clientMessage() {
        if (detail) return message;
        Matcher m = LOCKED_UNTIL.matcher(message == null ? "" : message);
        String until = m.find() ? m.group(1) : null;
        switch (code) {
            case "risk_too_high": return "Access denied for security reasons.";
            case "step_up_required": return "Additional verification required. Enter your step-up PIN.";
            case "network_blocked": return "Access denied: the network connection of this session changed.";
            case "posture_blocked": return "Access denied: this device does not currently meet the hospital's security requirements.";
            case "session_revoked": return "Your session was ended for security reasons." + (until == null ? "" : " Your account is locked until " + until + ".") + " Please sign in again.";
            case "account_locked": return "This account is locked" + (until == null ? "" : " until " + until) + ".";
            default: return message;
        }
    }

    public JsonObject toJson() {
        JsonObject o = new JsonObject();
        o.addProperty("decision", action);
        o.addProperty("http_status", httpStatus);
        o.addProperty("code", code);
        o.addProperty("message", clientMessage());
        o.addProperty("session_revoked", sessionRevoked);
        if (principal != null && detail) {   // risk figures exist only for a signed-in session, and only for a caller entitled to them (the PEP relays them to that session's owner only)
            o.addProperty("risk_score", riskScore);
            o.addProperty("penalty", penalty);
            o.addProperty("session_risk", sessionRisk);
            o.addProperty("revoke_threshold", threshold);
            o.addProperty("breakdown", breakdown);
        }
        if (principal != null && allowed()) {
            JsonObject c = new JsonObject();
            c.addProperty("user_id", principal.userId);
            c.addProperty("username", principal.username);
            c.addProperty("role", principal.role);
            c.addProperty("ward", principal.ward == null ? "" : principal.ward);
            c.addProperty("session_id", principal.sessionId);
            c.addProperty("basis", principal.basis);
            c.addProperty("grant_id", principal.grantId);
            o.add("claims", c);
        }
        return o;
    }

    // Body shown to the client for every non-ALLOW outcome.
    public JsonObject toErrorBody() {
        JsonObject o = new JsonObject();
        o.addProperty("error", code);
        o.addProperty("message", clientMessage());
        o.addProperty("decision", action);
        o.addProperty("session_revoked", sessionRevoked);
        o.addProperty("step_up_required", "step_up_required".equals(code));
        if (principal != null && detail) {   // risk figures belong to a signed-in session: a caller without a valid session learns no threshold and no score
            o.addProperty("risk_score", riskScore);
            o.addProperty("session_risk", sessionRisk);
            o.addProperty("revoke_threshold", threshold);
            o.addProperty("detail", breakdown);
        }
        return o;
    }
}
