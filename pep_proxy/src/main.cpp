// PEP - Policy Enforcement Point. The only reachable door to the protected app (and, for sign-in / administration, to the PDP's gateway).
// It carries no decision logic of its own: every /api request is evaluated by the PDP before anything is forwarded, every /ctl and /admin
// request is wrapped in an envelope and answered by the PDP gateway. Nothing is cached; anything unclear is a refusal (fail closed).
//
// Robustness rules (the legacy PEP died on a non-numeric Content-Length and on an invalid UTF-8 header byte):
//   * request parsing never throws and is bounded (HttpServer.cpp)
//   * JSON is parsed without exceptions and dumped with the 'replace' error handler
//   * no exception can leave a connection thread: handleConnection catches everything
#include "Config.h"
#include "HttpServer.h"
#include "../../shared/net/WinHttpClient.h"
#include "../../shared/include/json.hpp"
#include "../../shared/crypto/hmac_sha256.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

#pragma comment(lib, "ws2_32.lib")

using json = nlohmann::json;

static const std::string kInternalKey = EnvConfig::req("ZT_INTERNAL_KEY");
static const std::string kEdgeKey = EnvConfig::str("ZT_EDGE_KEY", "");
static std::atomic<int> g_active{0};
constexpr int kMaxConcurrent = 128;

static std::wstring utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int size = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (size <= 0) return {};
    std::wstring out((size_t)size, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], size);
    return out;
}

static std::string safeDump(const json& j) { return j.dump(-1, ' ', false, json::error_handler_t::replace); }

static const char* statusText(int s) {
    switch (s) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 409: return "Conflict";
        case 413: return "Payload Too Large";
        case 423: return "Locked";
        case 429: return "Too Many Requests";
        case 431: return "Request Header Fields Too Large";
        case 500: return "Internal Server Error";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        default: return s < 400 ? "OK" : "Error";
    }
}

static void sendJson(SOCKET c, int status, const json& body) {
    sendHttpResponse(c, status, statusText(status), "application/json", safeDump(body));
}

static void sendError(SOCKET c, int status, const std::string& code, const std::string& message) {
    sendJson(c, status, json({{"error", code}, {"message", message}}));
}

static bool startsWith(const std::string& s, const char* prefix) { return s.rfind(prefix, 0) == 0; }

static bool constantTimeEq(const std::string& a, const std::string& b) {
    size_t n = std::max(a.size(), b.size());
    unsigned diff = (unsigned)(a.size() ^ b.size());
    for (size_t i = 0; i < n; i++) {
        unsigned char x = i < a.size() ? (unsigned char)a[i] : 0, y = i < b.size() ? (unsigned char)b[i] : 0;
        diff |= (unsigned)(x ^ y);
    }
    return diff == 0;
}

// The client address is taken from X-Forwarded-For ONLY when the request comes from the loopback interface and carries the per-run edge key;
// otherwise the TCP peer address is used, so a client can never choose the address the PDP evaluates.
static std::string clientIpOf(const HttpRequest& req, const std::string& peerIp) {
    if (!kEdgeKey.empty() && peerIp == "127.0.0.1" && constantTimeEq(headerOr(req, "x-edge-key", ""), kEdgeKey)) {
        std::string xff = headerOr(req, "x-forwarded-for", "");
        bool plausible = !xff.empty() && xff.size() <= 45 &&
            std::all_of(xff.begin(), xff.end(), [](unsigned char ch) { return std::isxdigit(ch) || ch == ':' || ch == '.'; });
        if (plausible) return xff;
    }
    return peerIp;
}

static HttpResult callPdp(const std::wstring& path, const json& payload) {
    std::vector<std::wstring> headers = { L"X-Internal-Key: " + utf8ToWide(kInternalKey) };
    return WinHttpClient::request(Config::PDP_HOST, Config::PDP_PORT, L"POST", path, safeDump(payload), headers, true);
}

// /ctl/* and /admin/*: the PDP gateway authenticates, authorises and answers; the PEP only relays {status, body}.
static void handleGateway(SOCKET client, const HttpRequest& req, const std::string& clientIp) {
    json env = {
        {"client_ip", clientIp},
        {"device_id", headerOr(req, "x-device-id", "")},
        {"authorization", headerOr(req, "authorization", "")},
        {"method", req.method},
        {"path", req.path},
        {"query", req.query},
        {"body", req.body},
        {"step_up_pin", headerOr(req, "x-stepup-pin", "")},
    };
    HttpResult r = callPdp(L"/pdp/gateway", env);
    if (!r.success) {
        sendError(client, 502, "pdp_unreachable", "The policy decision point is unreachable (fail closed).");
        return;
    }
    json out = json::parse(r.body, nullptr, false);
    if (out.is_discarded() || !out.is_object() || !out.contains("status") || !out["status"].is_number_integer() || !out.contains("body")) {
        sendError(client, 502, "bad_pdp_response", "The policy decision point returned an unusable answer (fail closed).");
        return;
    }
    int status = out["status"].get<int>();
    if (status < 200 || status > 599) status = 502;
    sendJson(client, status, out["body"]);
}

// /api/*: evaluate first, forward only on an explicit ALLOW, with the PDP's identity claims signed for the protected app.
static void handleDataRequest(SOCKET client, const HttpRequest& req, const std::string& clientIp) {
    std::string authHeader = headerOr(req, "authorization", "");
    std::string token = authHeader.rfind("Bearer ", 0) == 0 ? authHeader.substr(7) : "";
    json evalReq = {
        {"token", token},
        {"device_id", headerOr(req, "x-device-id", "")},
        {"origin_ip", clientIp},
        {"method", req.method},
        {"path", req.path},
        {"query", req.query},
    };
    std::string pin = headerOr(req, "x-stepup-pin", "");
    if (!pin.empty()) evalReq["step_up_pin"] = pin;

    HttpResult evalResult = callPdp(L"/pdp/evaluate", evalReq);
    if (!evalResult.success) {
        sendError(client, 403, "pdp_unreachable", "The policy decision point is unreachable (fail closed).");
        return;
    }
    json d = json::parse(evalResult.body, nullptr, false);
    if (d.is_discarded() || !d.is_object()) {
        sendError(client, 403, "bad_pdp_response", "The policy decision point returned an unusable answer (fail closed).");
        return;
    }
    std::string action = d.value("decision", std::string("DENY"));

    if (action == "ALLOW" && d.contains("claims") && d["claims"].is_object()) {
        const json& c = d["claims"];
        std::string user = c.value("user_id", std::string()), role = c.value("role", std::string()), ward = c.value("ward", std::string());
        std::string basis = c.value("basis", std::string()), session = c.value("session_id", std::string());
        long long ts = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        std::string canonical = req.method + "|" + req.path + "|" + std::to_string(ts) + "|" + user + "|" + role + "|" + ward + "|" + basis + "|" + session;
        std::vector<std::wstring> hdrs = {
            L"X-PEP-Timestamp: " + std::to_wstring(ts),
            L"X-PEP-Signature: " + utf8ToWide(hmacSha256Hex(Config::PEP_APP_SHARED_SECRET, canonical)),
            L"X-ZT-User: " + utf8ToWide(user),
            L"X-ZT-Role: " + utf8ToWide(role),
            L"X-ZT-Ward: " + utf8ToWide(ward),
            L"X-ZT-Basis: " + utf8ToWide(basis),
            L"X-ZT-Session: " + utf8ToWide(session),
        };
        std::string target = req.path + (req.query.empty() ? std::string() : "?" + req.query);
        HttpResult appResult = WinHttpClient::request(Config::APP_HOST, Config::APP_PORT, utf8ToWide(req.method), utf8ToWide(target), req.body, hdrs, true);
        if (!appResult.success) {
            sendError(client, 502, "app_unreachable", "The protected application is unreachable.");
            return;
        }
        std::string contentType = appResult.contentType.empty() ? "application/json" : appResult.contentType;
        sendHttpResponse(client, appResult.statusCode, statusText(appResult.statusCode), contentType, appResult.body);
        return;
    }

    // STEP_UP, DENY, revoked session, or anything unrecognised: nothing is forwarded.
    int httpStatus = d.value("http_status", 403);
    if (httpStatus < 400 || httpStatus > 599) httpStatus = 403;
    std::string code = d.value("code", std::string("denied"));
    json body = {
        {"error", code},
        {"message", d.value("message", std::string("denied"))},
        {"decision", action},
        {"session_revoked", d.value("session_revoked", false)},
        {"step_up_required", code == "step_up_required"},
    };
    // Risk figures belong to a signed-in session: the PDP sends them only when there is one, and so does the PEP. A caller without a valid
    // session learns no threshold and no score from an error body.
    if (d.contains("session_risk")) {
        body["risk_score"] = d.value("risk_score", 0);
        body["session_risk"] = d.value("session_risk", 0);
        body["revoke_threshold"] = d.value("revoke_threshold", 0);
        body["detail"] = d.value("breakdown", std::string());
    }
    sendJson(client, httpStatus, body);
}

static void handleConnection(SOCKET client) {
    struct Guard {
        SOCKET s;
        ~Guard() { closesocket(s); g_active--; }
    } guard{client};
    try {
        DWORD timeoutMs = 10000;
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));

        HttpRequest req;
        std::string peerIp = getPeerIp(client);
        int rc = receiveHttpRequest(client, req);
        if (rc == -1) return;
        if (rc != 0) {
            sendError(client, rc, "bad_request", "The request could not be read.");
            return;
        }
        std::string clientIp = clientIpOf(req, peerIp);
        std::cout << "[PEP] " << clientIp << " " << req.method << " " << req.path << std::endl;

        if (req.method == "GET" && req.path == "/healthz") {
            sendJson(client, 200, json({{"status", "ok"}}));
        } else if (startsWith(req.path, "/ctl/") || startsWith(req.path, "/admin/")) {
            handleGateway(client, req, clientIp);
        } else if (startsWith(req.path, "/api/")) {
            handleDataRequest(client, req, clientIp);
        } else {
            sendError(client, 404, "not_found", "Unknown route.");
        }
    } catch (...) {
        try {
            sendError(client, 500, "internal_error", "The request could not be processed (fail closed).");
        } catch (...) {
        }
    }
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        return 1;
    }

    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        std::cerr << "socket() failed" << std::endl;
        return 1;
    }

    // Exclusive bind: another process cannot share or hijack this port.
    int opt = 1;
    setsockopt(listenSocket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, Config::LISTEN_HOST.c_str(), &addr.sin_addr) != 1) {
        std::cerr << "ZT_PEP_BIND is not an IPv4 address: " << Config::LISTEN_HOST << std::endl;
        return 1;
    }
    addr.sin_port = htons((u_short)Config::LISTEN_PORT);

    if (bind(listenSocket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "bind() failed, port " << Config::LISTEN_PORT << " in use?" << std::endl;
        return 1;
    }
    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "listen() failed" << std::endl;
        return 1;
    }

    std::cout << "[PEP] Listening on http://" << Config::LISTEN_HOST << ":" << Config::LISTEN_PORT << " (the TLS edge is the only intended client)" << std::endl;
    std::cout << "[PEP] PDP https://" << std::string(Config::PDP_HOST.begin(), Config::PDP_HOST.end()) << ":" << Config::PDP_PORT
              << "  Protected app https://" << std::string(Config::APP_HOST.begin(), Config::APP_HOST.end()) << ":" << Config::APP_PORT << std::endl;

    while (true) {
        sockaddr_in clientAddr{};
        int clientAddrLen = sizeof(clientAddr);
        SOCKET client = accept(listenSocket, (sockaddr*)&clientAddr, &clientAddrLen);
        if (client == INVALID_SOCKET) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }
        if (g_active.load() >= kMaxConcurrent) {
            try { sendError(client, 503, "busy", "Too many concurrent requests."); } catch (...) {}
            closesocket(client);
            continue;
        }
        g_active++;
        try {
            std::thread(handleConnection, client).detach();
        } catch (...) {
            g_active--;
            closesocket(client);
        }
    }
}
