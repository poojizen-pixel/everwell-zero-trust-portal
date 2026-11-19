package pdp.risk;

// Plain data carrier assembled by EvaluateHandler from DB lookups, then
// scored by every RiskVector. Fields are public - this class has no
// behavior of its own, it just moves facts from "gathered" to "scored".
public class RiskContext {
    public boolean deviceKnown;
    public boolean firewallActive;
    public boolean antivirusActive;
    public boolean signatureValid;
    public long heartbeatAgeSeconds;

    public boolean ipMatchesSessionOrigin;

    public int endpointSensitivity;

    public boolean assignmentRequired;
    public boolean assignmentSatisfied;

    // ratio = (seconds since this session's previous request) / (this
    // session's own historical average interval). < 1 means faster than the
    // user's own normal pace. -1 means "not enough history yet, skip".
    public double behaviorIntervalRatio = -1;
}
