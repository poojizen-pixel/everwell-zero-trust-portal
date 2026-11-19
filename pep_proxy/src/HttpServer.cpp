#include "HttpServer.h"
#include <ws2tcpip.h>
#include <algorithm>
#include <cctype>

static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

static std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// Digits only, at most maxDigits of them: no exceptions, no sign, no whitespace, no overflow.
static bool parseUnsigned(const std::string& s, size_t maxDigits, size_t& out) {
    if (s.empty() || s.size() > maxDigits) return false;
    size_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + (size_t)(c - '0');
    }
    out = v;
    return true;
}

int receiveHttpRequest(SOCKET sock, HttpRequest& req) {
    std::string buffer;
    char chunk[4096];

    size_t headerEnd;
    while ((headerEnd = buffer.find("\r\n\r\n")) == std::string::npos) {
        if (buffer.size() > kMaxHeaderBytes) return 431;
        int n = recv(sock, chunk, sizeof(chunk), 0);
        if (n <= 0) return -1;
        buffer.append(chunk, (size_t)n);
    }
    if (headerEnd > kMaxHeaderBytes) return 431;

    std::string headerBlock = buffer.substr(0, headerEnd);
    std::string leftover = buffer.substr(headerEnd + 4);

    // request line: METHOD SP target SP HTTP/1.x
    size_t eol = headerBlock.find("\r\n");
    std::string line = headerBlock.substr(0, eol == std::string::npos ? headerBlock.size() : eol);
    size_t sp1 = line.find(' ');
    size_t sp2 = sp1 == std::string::npos ? std::string::npos : line.find(' ', sp1 + 1);
    if (sp1 == std::string::npos || sp2 == std::string::npos) return 400;
    std::string method = line.substr(0, sp1);
    std::string target = line.substr(sp1 + 1, sp2 - sp1 - 1);
    std::string version = line.substr(sp2 + 1);
    if (method.empty() || method.size() > 8) return 400;
    for (char c : method) if (c < 'A' || c > 'Z') return 400;
    if (target.empty() || target.size() > 2048 || target[0] != '/') return 400;
    for (char c : target) if ((unsigned char)c <= 0x20 || (unsigned char)c == 0x7f) return 400;
    if (version.rfind("HTTP/1.", 0) != 0) return 400;
    req.method = method;
    size_t q = target.find('?');
    req.path = q == std::string::npos ? target : target.substr(0, q);
    req.query = q == std::string::npos ? "" : target.substr(q + 1);

    // header lines
    size_t pos = eol == std::string::npos ? headerBlock.size() : eol + 2;
    int count = 0;
    while (pos < headerBlock.size()) {
        size_t next = headerBlock.find("\r\n", pos);
        std::string h = headerBlock.substr(pos, next == std::string::npos ? std::string::npos : next - pos);
        pos = next == std::string::npos ? headerBlock.size() : next + 2;
        if (h.empty()) continue;
        if (++count > 100) return 431;
        size_t colon = h.find(':');
        if (colon == std::string::npos || colon == 0) return 400;
        std::string key = toLower(trim(h.substr(0, colon)));
        std::string value = trim(h.substr(colon + 1));
        auto dup = req.headers.find(key);
        if (dup != req.headers.end() && key == "content-length" && dup->second != value) return 400;  // conflicting lengths
        req.headers[key] = value;
    }
    if (req.headers.count("transfer-encoding")) return 400;  // chunked bodies are not supported

    size_t contentLength = 0;
    auto it = req.headers.find("content-length");
    if (it != req.headers.end()) {
        if (!parseUnsigned(it->second, 9, contentLength)) return 400;
        if (contentLength > kMaxBodyBytes) return 413;
    }

    req.body = leftover.size() > contentLength ? leftover.substr(0, contentLength) : leftover;
    while (req.body.size() < contentLength) {
        int n = recv(sock, chunk, sizeof(chunk), 0);
        if (n <= 0) return 400;  // body announced but not delivered
        size_t take = std::min((size_t)n, contentLength - req.body.size());
        req.body.append(chunk, take);
    }
    return 0;
}

void sendHttpResponse(SOCKET sock, int statusCode, const std::string& statusText,
        const std::string& contentType, const std::string& body,
        const std::vector<std::string>& extraHeaders) {
    // No CORS headers: the portal is same-origin (served by the same TLS edge that proxies the API), so no cross-origin read is ever allowed.
    std::string out = "HTTP/1.1 " + std::to_string(statusCode) + " " + statusText + "\r\n";
    out += "Content-Type: " + contentType + "\r\n";
    out += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    out += "Cache-Control: no-store\r\n";
    out += "X-Content-Type-Options: nosniff\r\n";
    out += "Connection: close\r\n";
    for (const auto& h : extraHeaders) out += h + "\r\n";
    out += "\r\n";
    out += body;
    size_t sent = 0;
    while (sent < out.size()) {
        int n = send(sock, out.data() + sent, (int)(out.size() - sent), 0);
        if (n <= 0) break;
        sent += (size_t)n;
    }
}

std::string getPeerIp(SOCKET sock) {
    sockaddr_in addr{};
    int addrLen = sizeof(addr);
    if (getpeername(sock, (sockaddr*)&addr, &addrLen) != 0) return "0.0.0.0";
    char buf[64];
    if (!inet_ntop(AF_INET, &addr.sin_addr, buf, sizeof(buf))) return "0.0.0.0";
    return std::string(buf);
}

std::string headerOr(const HttpRequest& req, const std::string& lowerKey, const std::string& fallback) {
    auto it = req.headers.find(lowerKey);
    return it != req.headers.end() ? it->second : fallback;
}
