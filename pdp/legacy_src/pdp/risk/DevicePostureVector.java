package pdp.risk;

import pdp.Config;

// Device pillar. An unknown device, a tampered heartbeat signature, or a
// stale heartbeat (agent killed/hung) all collapse to the same maximal
// score - deliberately, so this alone always pushes past the DENY
// threshold regardless of how healthy every other vector looks. This is
// what makes the "kill the agent" demo work without any special-casing
// elsewhere: a stale heartbeat just becomes a very large number here.
public class DevicePostureVector implements RiskVector {
    public static final int HARD_BLOCK = 200;

    @Override
    public String name() { return "device"; }

    @Override
    public int score(RiskContext ctx) {
        if (!ctx.deviceKnown || !ctx.signatureValid) return HARD_BLOCK;
        if (ctx.heartbeatAgeSeconds > Config.HEARTBEAT_STALE_SECONDS) return HARD_BLOCK;

        int score = 0;
        if (!ctx.firewallActive) score += 45;
        if (!ctx.antivirusActive) score += 35;
        return score;
    }
}
