#pragma once
#include "sha256.h"
#include <sstream>
#include <iomanip>

// Standard HMAC construction (RFC 2104) built on the SHA-256 primitive
// above. Mirrors the PDP's pdp.crypto.HmacSigner exactly (same block size,
// same ipad/opad construction), so a signature produced here verifies
// correctly on the Java side and vice versa.
inline std::vector<uint8_t> hmacSha256(const std::string& key, const std::string& message) {
    constexpr size_t blockSize = 64;
    std::vector<uint8_t> keyBlock(blockSize, 0);

    if (key.size() > blockSize) {
        auto hashed = sha256(key);
        std::copy(hashed.begin(), hashed.end(), keyBlock.begin());
    } else {
        std::copy(key.begin(), key.end(), keyBlock.begin());
    }

    std::vector<uint8_t> ipad(blockSize), opad(blockSize);
    for (size_t i = 0; i < blockSize; ++i) {
        ipad[i] = keyBlock[i] ^ 0x36;
        opad[i] = keyBlock[i] ^ 0x5c;
    }

    std::vector<uint8_t> inner(ipad);
    inner.insert(inner.end(), message.begin(), message.end());
    auto innerHash = sha256(inner.data(), inner.size());

    std::vector<uint8_t> outer(opad);
    outer.insert(outer.end(), innerHash.begin(), innerHash.end());
    return sha256(outer.data(), outer.size());
}

inline std::string toHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (uint8_t b : bytes) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}

inline std::string hmacSha256Hex(const std::string& key, const std::string& message) {
    return toHex(hmacSha256(key, message));
}
