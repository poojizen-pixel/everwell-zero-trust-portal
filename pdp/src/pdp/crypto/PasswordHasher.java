package pdp.crypto;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

// Salted, slow key derivation (PBKDF2-HMAC-SHA256, a NIST-approved KDF available in the JDK without any extra dependency).
// Stored form: pbkdf2-sha256$<iterations>$<salt b64>$<hash b64>.  This is NOT Argon2id; the stronger choice needs an approved dependency.
public class PasswordHasher {
    private static final SecureRandom RNG = new SecureRandom();
    public static final int DEFAULT_ITERATIONS = 310_000;
    private static final String DUMMY = hash("not-a-real-password", 10_000);

    public static String hash(String secret, int iterations) {
        byte[] salt = new byte[16];
        RNG.nextBytes(salt);
        byte[] h = pbkdf2(secret.toCharArray(), salt, iterations);
        Base64.Encoder b64 = Base64.getEncoder().withoutPadding();
        return "pbkdf2-sha256$" + iterations + "$" + b64.encodeToString(salt) + "$" + b64.encodeToString(h);
    }

    public static boolean verify(String secret, String stored) {
        try {
            String[] p = stored.split("\\$");
            if (p.length != 4 || !p[0].equals("pbkdf2-sha256")) return false;
            int iterations = Integer.parseInt(p[1]);
            byte[] salt = Base64.getDecoder().decode(p[2]);
            byte[] expected = Base64.getDecoder().decode(p[3]);
            byte[] actual = pbkdf2(secret.toCharArray(), salt, iterations);
            int diff = expected.length ^ actual.length;
            for (int i = 0; i < Math.min(expected.length, actual.length); i++) diff |= expected[i] ^ actual[i];
            return diff == 0;
        } catch (Exception e) {
            return false;
        }
    }

    // Spend roughly the same time as a real check when the user does not exist, so timing does not reveal valid user names.
    public static void burn(String secret) {
        verify(secret, DUMMY);
    }

    private static byte[] pbkdf2(char[] pw, byte[] salt, int iterations) {
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec(pw, salt, iterations, 256)).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
