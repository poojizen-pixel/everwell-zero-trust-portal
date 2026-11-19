package pdp.risk;

// Strategy interface: each risk factor (device, network, behavior, data
// sensitivity, assignment) is its own independent, swappable implementation.
// RiskEngine doesn't know or care how any one of them computes its number.
public interface RiskVector {
    String name();
    int score(RiskContext ctx);
}
