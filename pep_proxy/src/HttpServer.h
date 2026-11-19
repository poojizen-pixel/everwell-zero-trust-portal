#pragma once
#include <string>
#include <map>
#include <vector>
#include <winsock2.h>

struct HttpRequest {
    std::string method;
    std::string path;    // request target without the query string
    std::string query;   // without the leading '?'
    std::map<std::string, std::string> headers; // lowercase keys
    std::string body;
};

// Minimal HTTP/1.1 request parsing/response writing over a raw socket - just enough for JSON requests relayed by the TLS edge.
// Not a general-purpose HTTP server: no chunked request bodies, no keep-alive reuse, each accepted connection handles exactly one request.
// Parsing never throws: every malformed or oversized input becomes a status code.
//   returns 0 when a request was read, -1 when the peer closed or timed out, otherwise the HTTP status to answer with (400, 413, 431).
int receiveHttpRequest(SOCKET sock, HttpRequest& req);

void sendHttpResponse(SOCKET sock, int statusCode, const std::string& statusText,
    const std::string& contentType, const std::string& body,
    const std::vector<std::string>& extraHeaders = {});

std::string getPeerIp(SOCKET sock);

std::string headerOr(const HttpRequest& req, const std::string& lowerKey, const std::string& fallback);

// Limits (see HttpServer.cpp)
constexpr size_t kMaxHeaderBytes = 32 * 1024;
constexpr size_t kMaxBodyBytes = 256 * 1024;
