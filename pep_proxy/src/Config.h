#pragma once
#include <string>
#include "../../shared/config/EnvConfig.h"

// The PEP is the ONLY application component that clients (through the TLS edge) can reach. It listens on plain HTTP on the
// loopback interface only; TLS is terminated by the edge in front of it. Every hop behind it (PEP->PDP, PEP->Protected App)
// is TLS via WinHTTP/Schannel. All values come from environment variables (see shared/config/EnvConfig.h).
namespace Config {
    inline const std::string LISTEN_HOST = EnvConfig::str("ZT_PEP_BIND", "127.0.0.1");
    inline const int LISTEN_PORT = EnvConfig::num("ZT_PEP_PORT", 5000);

    inline const std::wstring PDP_HOST = EnvConfig::wide(EnvConfig::str("ZT_PDP_HOST", "127.0.0.1"));
    inline const int PDP_PORT = EnvConfig::num("ZT_PDP_PORT", 8443);

    inline const std::wstring APP_HOST = EnvConfig::wide(EnvConfig::str("ZT_APP_HOST", "127.0.0.1"));
    inline const int APP_PORT = EnvConfig::num("ZT_APP_PORT", 9000);

    // Workload self-verification: the Protected App independently checks this signature before serving anything.
    inline const std::string PEP_APP_SHARED_SECRET = EnvConfig::req("ZT_PEP_APP_SECRET");
}
