package pdp.core;

public class DecisionRequest {
    public String method, path, query = "", token, deviceId, clientIp, stepUpPin;
    public boolean allowGrace;   // only /ctl/renew accepts a recently expired token
}
