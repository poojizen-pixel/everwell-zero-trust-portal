package pdp.policy;

// The complete, evaluator-visible policy. Every number here is a default that can be changed at run time through
// POST /admin/policy/set (security administrator only; the change is validated, stored and written to the security events).
// JSON names are the snake_case form of the field names (allowBelow -> allow_below).
public class Policy {
    public int version = 1;
    public Bands bands = new Bands();
    public Device device = new Device();
    public Network network = new Network();
    public Behavior behavior = new Behavior();
    public Session session = new Session();
    public Tokens tokens = new Tokens();
    public Penalties penalties = new Penalties();
    public BreakGlass breakGlass = new BreakGlass();
    public Login login = new Login();
    public Admin admin = new Admin();
    public Simulation simulation = new Simulation();

    // Per-request risk score = device + network + burst + endpoint sensitivity.  < allowBelow: ALLOW, < stepUpBelow: STEP_UP (PIN), else DENY.
    public static class Bands {
        public int allowBelow = 40;
        public int stepUpBelow = 70;
    }

    public static class Device {
        public int laptopStaleSeconds = 6;        // agent heartbeat older than this = agent stopped (hard block)
        public int phoneStaleSeconds = 90;        // browser heartbeat older than this = page closed or frozen (hard block)
        public int firewallOffScore = 45;         // MEASURED by the agent
        public int antivirusOffScore = 35;        // MEASURED by the agent (a security product is registered with Windows Security Center)
        public int browserBaseScore = 5;          // a browser device only self-reports, so it never reaches 0
        public int screenLockOffScore = 30;       // SIMULATED on the phone (a browser cannot read it)
        public int osOutdatedScore = 25;          // SIMULATED
        public int protectionOffScore = 35;       // SIMULATED
        public String onBlocked = "DENY";         // what a hard block does to the session: DENY (stays valid, recovers) or REVOKE
    }

    // Network change handling is a policy, not an accusation: an address change inside the same /24 is usually DHCP,
    // another subnet (other Wi-Fi, mobile data) needs the second factor by default.  Actions: ALLOW | STEP_UP | DENY | REVOKE.
    public static class Network {
        public int sameSubnetScore = 0;
        public String sameSubnetAction = "ALLOW";
        public int differentSubnetScore = 30;
        public String differentSubnetAction = "STEP_UP";
        public boolean rebindAfterStepUp = true;  // after a verified PIN the session adopts the new network as its baseline
    }

    public static class Behavior {
        public int burstWindowSeconds = 10;
        public int burstLimit = 25;
        public int burstScore = 25;
    }

    public static class Session {
        public int revokeThreshold = 60;          // accumulated penalty points that revoke the session
        public int lockoutMinutes = 5;            // account lock after a risk revocation
        public int idleTimeoutSeconds = 900;
        public int absoluteTimeoutSeconds = 28800;
    }

    public static class Tokens {
        public int ttlSeconds = 90;
        public int renewGraceSeconds = 300;       // a token that expired this recently may still be renewed (phone wakes up)
    }

    // Penalty points added to the SESSION risk by a denied or suspicious request.
    public static class Penalties {
        public int roleDenied = 15;
        public int notAssigned = 20;
        public int wardDenied = 20;
        public int unknownEndpoint = 10;
        public int badRequest = 10;
        public int badStepUpPin = 25;
        public int postureBlocked = 10;
        public int networkDenied = 10;
        public int riskTooHigh = 10;
        public int notFound = 5;
        public int breakGlassUsed = 15;
        public int burst = 10;
    }

    public static class BreakGlass {
        public boolean enabled = true;
        public int durationSeconds = 900;
        public int minJustificationChars = 20;
        public int maxGrantsPerSession = 3;
    }

    public static class Login {
        public int maxFailures = 5;
        public int windowSeconds = 300;
        public int lockoutMinutes = 5;
    }

    public static class Admin {
        public boolean requireManagedDevice = false;  // true: administrative endpoints only from an agent-verified laptop
    }

    public static class Simulation {
        public boolean enabled = true;            // demo controls (simulated network change / simulated phone posture)
    }
}
