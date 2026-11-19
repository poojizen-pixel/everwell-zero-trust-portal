package pdp.risk;

// Adaptive behavioral signal (NIST tenet: use collected telemetry to
// improve posture over time). Deliberately NOT a fixed global threshold
// like "10 requests/5 seconds for everyone" - EvaluateHandler computes each
// session's OWN historical average request interval, and this vector only
// flags a request that is anomalously fast relative to THAT baseline. A
// naturally fast-clicking user never trips it; a sudden burst relative to
// their own normal pace does.
public class BehavioralVector implements RiskVector {
    @Override
    public String name() { return "behavior"; }

    @Override
    public int score(RiskContext ctx) {
        if (ctx.behaviorIntervalRatio < 0) return 0; // not enough history yet
        if (ctx.behaviorIntervalRatio < 0.3) return 25;
        return 0;
    }
}
