package pdp.risk;

import pdp.db.Database;

import java.sql.PreparedStatement;
import java.sql.ResultSet;

// Risk thresholds live in the policies TABLE, not as hardcoded if/else -
// the ABAC ruleset is data, so it's queryable/auditable/editable without a
// code change.
public class PolicyLookup {
    private final Database db;

    public PolicyLookup(Database db) {
        this.db = db;
    }

    public String actionFor(int riskScore) {
        return db.withConnection(conn -> {
            String sql = "SELECT action FROM policies WHERE ? >= min_risk AND ? < max_risk LIMIT 1";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setInt(1, riskScore);
                ps.setInt(2, riskScore);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) return rs.getString("action");
                }
            }
            // Fail-closed: an unmatched score (e.g. above every configured
            // band) is denied, never silently allowed.
            return "DENY";
        });
    }
}
