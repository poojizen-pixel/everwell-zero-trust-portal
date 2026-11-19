#pragma once
#include <cstdlib>
#include <iostream>
#include <string>

// Settings for the C++ programs come from environment variables set by the launcher (scripts/demo).
// Secrets are read with envReq(): the process exits at start-up when one is missing, so a binary can never run
// with a key that is compiled into it.
namespace EnvConfig {
    inline std::string str(const char* key, const std::string& def = "") {
        const char* v = std::getenv(key);
        return (v && *v) ? std::string(v) : def;
    }

    inline std::string req(const char* key) {
        std::string v = str(key);
        if (v.empty()) {
            std::cerr << "[config] missing required environment variable " << key << std::endl;
            std::exit(2);
        }
        return v;
    }

    inline int num(const char* key, int def) {
        std::string v = str(key);
        if (v.empty()) return def;
        try {
            return std::stoi(v);
        } catch (...) {
            return def;
        }
    }

    // Host names and IP literals only (ASCII).
    inline std::wstring wide(const std::string& s) { return std::wstring(s.begin(), s.end()); }
}
