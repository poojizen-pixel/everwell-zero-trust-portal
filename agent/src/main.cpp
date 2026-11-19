// Endpoint Posture Agent - the Device pillar. Runs continuously on the
// client machine, checks REAL OS-level security state every 2 seconds, and
// sends a signed heartbeat to the PDP. There is no "send once at login" -
// as long as this process stays running, the PDP has a live, continuously
// refreshed picture of this device. Kill this process and the PDP notices
// within seconds (see DevicePostureVector's staleness check).
#include "Config.h"
#include "PostureCheck.h"
#include "../../shared/net/WinHttpClient.h"
#include "../../shared/include/json.hpp"
#include "../../shared/crypto/hmac_sha256.h"

#include <windows.h>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>

using json = nlohmann::json;

static std::string getHostname() {
    char buf[256];
    DWORD size = sizeof(buf);
    if (GetComputerNameA(buf, &size)) return std::string(buf);
    return "UNKNOWN-HOST";
}

static std::string boolStr(bool b) { return b ? "true" : "false"; }

int main(int argc, char** argv) {
    bool fakeFirewallOff = false;
    bool fakeAvOff = false;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--fake-firewall-off") fakeFirewallOff = true;
        if (arg == "--fake-av-off") fakeAvOff = true;
    }

    HRESULT hrInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hrInit) && hrInit != S_FALSE) {
        std::cerr << "[Agent] CoInitializeEx failed" << std::endl;
        return 1;
    }
    CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE, nullptr);

    std::string hostname = getHostname();
    std::string deviceId = "DEV-" + hostname;
    std::string os = "Windows";

    std::cout << "[Agent] Posture Agent starting." << std::endl;
    std::cout << "[Agent] device_id = " << deviceId << "  (use this exact value when logging in)" << std::endl;
    if (fakeFirewallOff) std::cout << "[Agent] --fake-firewall-off: reporting firewall as DISABLED regardless of real state (demo only)" << std::endl;
    if (fakeAvOff) std::cout << "[Agent] --fake-av-off: reporting antivirus as ABSENT regardless of real state (demo only)" << std::endl;
    std::cout << "[Agent] Sending signed heartbeats to https://127.0.0.1:" << Config::PDP_PORT << "/pip/telemetry every "
              << Config::HEARTBEAT_INTERVAL_SECONDS << "s. Close this window (or kill the process) to simulate device compromise." << std::endl;

    while (true) {
        bool firewallActive = fakeFirewallOff ? false : PostureCheck::isFirewallEnabled();
        bool antivirusActive = fakeAvOff ? false : PostureCheck::isAntivirusPresent();
        long long timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        // 'simulated' is signed too: a heartbeat produced with a --fake-* demo flag can never pass as a genuine measurement.
        bool simulated = fakeFirewallOff || fakeAvOff;
        std::string canonical = deviceId + "|" + hostname + "|" + os + "|"
            + boolStr(firewallActive) + "|" + boolStr(antivirusActive) + "|" + boolStr(simulated) + "|" + std::to_string(timestamp);
        std::string signature = hmacSha256Hex(Config::AGENT_HMAC_SECRET, canonical);

        json payload = {
            {"device_id", deviceId},
            {"hostname", hostname},
            {"os", os},
            {"firewall_active", firewallActive},
            {"antivirus_active", antivirusActive},
            {"simulated", simulated},
            {"timestamp", timestamp},
            {"signature", signature},
        };

        HttpResult result = WinHttpClient::request(Config::PDP_HOST, Config::PDP_PORT, L"POST",
            L"/pip/telemetry", payload.dump(), {}, true);

        std::cout << "[Agent] heartbeat: firewall=" << boolStr(firewallActive)
                  << " av=" << boolStr(antivirusActive)
                  << " -> ";
        if (result.success) {
            std::cout << "HTTP " << result.statusCode << " " << result.body << std::endl;
        } else {
            std::cout << "FAILED (" << result.error << ") - is the PDP running?" << std::endl;
        }

        std::this_thread::sleep_for(std::chrono::seconds(Config::HEARTBEAT_INTERVAL_SECONDS));
    }

    CoUninitialize();
    return 0;
}
