package pdp.risk;

// Network pillar. No implicit trust from "where the request came from" -
// the only thing checked is whether THIS request's origin still matches
// where the session began. A mismatch reads as a possible session hijack.
public class NetworkContextVector implements RiskVector {
    @Override
    public String name() { return "network"; }

    @Override
    public int score(RiskContext ctx) {
        return ctx.ipMatchesSessionOrigin ? 0 : 40;
    }
}
