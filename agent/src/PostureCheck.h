#pragma once

// Real OS-level posture signals - not simulated. Callers must have already
// called CoInitializeEx/CoInitializeSecurity once at process startup;
// these functions assume COM is live and do not tear it down themselves.
namespace PostureCheck {
    // Queries the Windows Firewall COM API (INetFwPolicy2) for whether the
    // currently active network profile (Domain/Private/Public) has the
    // firewall enabled.
    bool isFirewallEnabled();

    // Queries WMI's root\SecurityCenter2 namespace for a registered
    // AntiVirusProduct - the same mechanism Windows Security Center itself
    // uses to report "is an AV present" (this includes Windows Defender
    // when it's the active provider, and any third-party AV that registers
    // itself with the OS).
    bool isAntivirusPresent();
}
