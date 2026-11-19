package pdp.risk;

import java.util.List;

// Aggregates whatever RiskVector strategies it's given - it has no idea
// what "device" or "network" even mean, it just sums scores and records
// which vector contributed what, for the audit trail.
public class RiskEngine {
    private final List<RiskVector> vectors;

    public RiskEngine(List<RiskVector> vectors) {
        this.vectors = vectors;
    }

    public Result evaluate(RiskContext ctx) {
        int total = 0;
        StringBuilder breakdown = new StringBuilder();
        for (RiskVector v : vectors) {
            int s = v.score(ctx);
            total += s;
            if (breakdown.length() > 0) breakdown.append(", ");
            breakdown.append(v.name()).append('=').append(s);
        }
        return new Result(total, breakdown.toString());
    }

    public static class Result {
        public final int totalScore;
        public final String breakdown;

        Result(int totalScore, String breakdown) {
            this.totalScore = totalScore;
            this.breakdown = breakdown;
        }
    }
}
