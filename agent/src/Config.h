#pragma once
#include <string>
#include "../../shared/config/EnvConfig.h"

namespace Config {
    inline const std::wstring PDP_HOST = EnvConfig::wide(EnvConfig::str("ZT_PDP_HOST", "127.0.0.1"));
    inline const int PDP_PORT = EnvConfig::num("ZT_PDP_PORT", 8443);

    // Must match the PDP's zt.agent.secret / ZT_AGENT_SECRET (generated per run by the launcher; no compiled-in default).
    inline const std::string AGENT_HMAC_SECRET = EnvConfig::req("ZT_AGENT_SECRET");

    inline const int HEARTBEAT_INTERVAL_SECONDS = EnvConfig::num("ZT_HEARTBEAT_INTERVAL", 2);
}
