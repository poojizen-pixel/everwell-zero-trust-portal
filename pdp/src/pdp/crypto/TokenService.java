package pdp.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

// Issues and verifies short-lived session tokens bound to the device they were issued for. The token carries NO role or
// permission: the server loads the role from the database on every request, so a client cannot assert one.
// A token proves "this session id was issued to this device"; whether the session is still ACTIVE is decided server-side
// on every request (revocation therefore works immediately, no matter how much lifetime the token has left).
public class TokenService {
    private final HmacSigner signer;

    public TokenService(HmacSigner signer) {
        this.signer = signer;
    }

    public String issue(String sessionId, String userId, String deviceId, String originIp, long ttlSeconds) {
        long now = System.currentTimeMillis() / 1000;
        long exp = now + ttlSeconds;
        String payload = String.join("|", sessionId, userId, deviceId, originIp, String.valueOf(now), String.valueOf(exp));
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        return encoded + "." + signer.signHex(payload);
    }

    // graceSeconds > 0 lets a recently expired token pass (used ONLY by the renew endpoint).
    public TokenClaims verify(String token, String expectedDeviceId, long graceSeconds) throws TokenException {
        if (token == null || token.isEmpty()) throw new TokenException("token_missing", "missing token");
        if (token.length() > 2048) throw new TokenException("token_invalid", "malformed token");
        int dot = token.indexOf('.');
        if (dot < 0) throw new TokenException("token_invalid", "malformed token");

        String encoded = token.substring(0, dot);
        String sig = token.substring(dot + 1);
        String payload;
        try {
            payload = new String(Base64.getUrlDecoder().decode(encoded), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new TokenException("token_invalid", "malformed token encoding");
        }
        if (!signer.verifyHex(payload, sig)) throw new TokenException("token_invalid", "signature mismatch");

        String[] parts = payload.split("\\|", -1);
        if (parts.length != 6) throw new TokenException("token_invalid", "malformed payload");
        long issuedAt, expiresAt;
        try {
            issuedAt = Long.parseLong(parts[4]);
            expiresAt = Long.parseLong(parts[5]);
        } catch (NumberFormatException e) {
            throw new TokenException("token_invalid", "malformed timestamps");
        }
        long now = System.currentTimeMillis() / 1000;
        boolean expired = now > expiresAt;
        if (expired && now > expiresAt + graceSeconds) throw new TokenException("token_expired", "token expired");
        if (!parts[2].equals(expectedDeviceId)) throw new TokenException("token_invalid", "device mismatch - possible token replay");
        return new TokenClaims(parts[0], parts[1], parts[2], parts[3], issuedAt, expiresAt, expired);
    }

    public static class TokenClaims {
        public final String sessionId, userId, deviceId, originIp;
        public final long issuedAt, expiresAt;
        public final boolean expired;

        TokenClaims(String sessionId, String userId, String deviceId, String originIp, long issuedAt, long expiresAt, boolean expired) {
            this.sessionId = sessionId;
            this.userId = userId;
            this.deviceId = deviceId;
            this.originIp = originIp;
            this.issuedAt = issuedAt;
            this.expiresAt = expiresAt;
            this.expired = expired;
        }
    }

    public static class TokenException extends Exception {
        public final String code;

        public TokenException(String code, String message) {
            super(message);
            this.code = code;
        }
    }
}
