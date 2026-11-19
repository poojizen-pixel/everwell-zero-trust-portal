#include "WinHttpClient.h"
#include <windows.h>
#include <winhttp.h>
#include <vector>

#pragma comment(lib, "winhttp.lib")

static std::string wideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string out(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &out[0], size, nullptr, nullptr);
    return out;
}

HttpResult WinHttpClient::request(
        const std::wstring& host,
        int port,
        const std::wstring& method,
        const std::wstring& path,
        const std::string& body,
        const std::vector<std::wstring>& extraHeaders,
        bool useTls) {
    HttpResult result;

    HINTERNET hSession = WinHttpOpen(L"ZeroTrustPEP/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        result.error = "WinHttpOpen failed";
        return result;
    }

    // A stuck peer must not hold a PEP thread forever: resolve, connect, send and receive timeouts (milliseconds).
    WinHttpSetTimeouts(hSession, 3000, 5000, 15000, 20000);

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), (INTERNET_PORT)port, 0);
    if (!hConnect) {
        result.error = "WinHttpConnect failed";
        WinHttpCloseHandle(hSession);
        return result;
    }

    DWORD flags = useTls ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, method.c_str(), path.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        result.error = "WinHttpOpenRequest failed";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    if (useTls) {
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
            | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
            | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
    }

    std::wstring headers = L"Content-Type: application/json\r\n";
    for (const auto& h : extraHeaders) headers += h + L"\r\n";

    BOOL sent = WinHttpSendRequest(hRequest,
        headers.c_str(), (DWORD)headers.size(),
        (LPVOID)body.data(), (DWORD)body.size(),
        (DWORD)body.size(), 0);

    if (!sent || !WinHttpReceiveResponse(hRequest, nullptr)) {
        result.error = "WinHttpSendRequest/ReceiveResponse failed, GetLastError=" + std::to_string(GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }

    DWORD statusCode = 0, statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_FLAG_NUMBER | WINHTTP_QUERY_STATUS_CODE,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);
    result.statusCode = (int)statusCode;

    wchar_t ctypeBuf[256];
    DWORD ctypeSize = sizeof(ctypeBuf);
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_TYPE,
            WINHTTP_HEADER_NAME_BY_INDEX, ctypeBuf, &ctypeSize, WINHTTP_NO_HEADER_INDEX)) {
        result.contentType = wideToUtf8(std::wstring(ctypeBuf));
    }

    std::string responseBody;
    DWORD available = 0;
    do {
        available = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &available)) break;
        if (available == 0) break;
        std::vector<char> buf(available);
        DWORD read = 0;
        if (!WinHttpReadData(hRequest, buf.data(), available, &read)) break;
        responseBody.append(buf.data(), read);
    } while (available > 0);

    result.body = responseBody;
    result.success = true;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}
