package pdp.risk;

// Data pillar. The endpoint's own classification (0-60) is added directly -
// touching more sensitive data always costs more risk budget, independent
// of how trustworthy the rest of the request looks.
public class DataSensitivityVector implements RiskVector {
    @Override
    public String name() { return "data"; }

    @Override
    public int score(RiskContext ctx) {
        return ctx.endpointSensitivity;
    }
}
