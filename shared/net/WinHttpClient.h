#pragma once
#include <string>
#include <vector>

struct HttpResult {
    bool success = false;
    int statusCode = 0;
    std::string body;
    std::string contentType;
    std::string error;
};

// TLS client to the PDP / Protected App using WinHTTP - Windows' native
// Schannel stack handles the actual TLS handshake and record layer, so
// there is no OpenSSL (or any other third-party crypto library) dependency
// here at all.
//
// Certificate CHAIN validation is intentionally disabled for these calls
// (SECURITY_FLAG_IGNORE_UNKNOWN_CA etc.) because the PDP/App present a
// self-signed demo certificate that no root store trusts. The traffic is
// still genuinely encrypted over the wire - what's skipped is verifying
// *who* the cert belongs to, which for a production system would instead
// be solved by installing that trust relationship (a system security
// change, deliberately left for a human to do, not something this code
// does on its own) or by using a CA-issued certificate.
class WinHttpClient {
public:
    static HttpResult request(
        const std::wstring& host,
        int port,
        const std::wstring& method,
        const std::wstring& path,
        const std::string& body,
        const std::vector<std::wstring>& extraHeaders,
        bool useTls);
};
