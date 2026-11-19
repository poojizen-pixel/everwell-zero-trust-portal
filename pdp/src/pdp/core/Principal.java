package pdp.core;

// The authenticated caller of one request, as loaded from the SERVER-SIDE session and user records (never from the client).
public class Principal {
    public String userId, username, displayName, role, ward, sessionId, deviceId, ip;
    public String basis = "";     // why access to a patient was granted: assigned | ward | front_desk | break_glass
    public String grantId = "";

    public boolean isClinical() { return "doctor".equals(role) || "nurse".equals(role) || "receptionist".equals(role); }
}
