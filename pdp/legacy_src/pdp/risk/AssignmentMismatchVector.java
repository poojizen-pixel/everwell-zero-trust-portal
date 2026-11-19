package pdp.risk;

// Insider-threat mitigation, deliberately NOT a hard gate: a doctor/nurse
// opening a patient they are not assigned to is allowed to proceed (real
// hospitals need break-glass access for coverage/emergencies) but it costs
// real risk budget, which typically pushes the request into STEP_UP - so
// access outside your normal scope requires a justification and gets
// logged, rather than being silently allowed or silently blocked.
public class AssignmentMismatchVector implements RiskVector {
    @Override
    public String name() { return "assignment"; }

    @Override
    public int score(RiskContext ctx) {
        if (!ctx.assignmentRequired) return 0;
        // 25, not 30: a healthy doctor (0 device/network/behavior risk) on
        // an unassigned patient's *records* (sensitivity 40) must land at
        // 65 - inside STEP_UP (40-70), not DENY - so break-glass viewing is
        // possible with a justification. Export-pdf (sensitivity 60) still
        // lands at 85, past DENY - bulk-exporting an unassigned patient's
        // full record (SSN included) is NOT something step-up should wave
        // through, which is a deliberate, defensible distinction.
        return ctx.assignmentSatisfied ? 0 : 25;
    }
}
