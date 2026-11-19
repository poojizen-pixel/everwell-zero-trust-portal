package app.http;

// The caller as vouched for by the PDP decision and relayed by the PEP in HMAC-signed headers (see PepSignatureFilter).
public final class Claims {
    public final String userId, role, ward, basis, sessionId;

    public Claims(String userId, String role, String ward, String basis, String sessionId) {
        this.userId = userId;
        this.role = role;
        this.ward = ward;
        this.basis = basis;
        this.sessionId = sessionId;
    }
}
