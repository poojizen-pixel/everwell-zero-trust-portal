// Known-answer tests for the project's existing SHA-256 / HMAC-SHA256 headers (shared/crypto).
//
// The expected values are public test vectors (FIPS 180-4 examples and RFC 4231 test cases 1, 2 and 6).
// Each one was also recomputed with OpenSSL 3.5.7 before it was written here.
// This test only READS the production headers; it changes nothing in them.
// Lines holding a 64-character hex vector carry a "secret-scan: allow" marker so the secret scanner does not treat
// a public test vector as a leaked key (the marker is honoured only for unnamed long hex literals).
#include <algorithm>
#include <string>

#include "mini_test.h"
#include "../../shared/crypto/hmac_sha256.h"

MT_TEST(sha256_of_empty_string) {
    MT_CHECK_EQ(toHex(sha256(std::string(""))),
                std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));  // secret-scan: allow public vector
}

MT_TEST(sha256_of_abc) {
    MT_CHECK_EQ(toHex(sha256(std::string("abc"))),
                std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));  // secret-scan: allow public vector
}

MT_TEST(sha256_of_448_bit_message) {
    MT_CHECK_EQ(toHex(sha256(std::string("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))),
                std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));  // secret-scan: allow public vector
}

MT_TEST(sha256_of_one_million_a) {
    MT_CHECK_EQ(toHex(sha256(std::string(1000000, 'a'))),
                std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));  // secret-scan: allow public vector
}

MT_TEST(hmac_rfc4231_case1) {
    MT_CHECK_EQ(hmacSha256Hex(std::string(20, '\x0b'), "Hi There"),
                std::string("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));  // secret-scan: allow public vector
}

MT_TEST(hmac_rfc4231_case2) {
    MT_CHECK_EQ(hmacSha256Hex("Jefe", "what do ya want for nothing?"),
                std::string("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));  // secret-scan: allow public vector
}

MT_TEST(hmac_rfc4231_case6_key_longer_than_one_block) {
    MT_CHECK_EQ(hmacSha256Hex(std::string(131, '\xaa'), "Test Using Larger Than Block-Size Key - Hash Key First"),
                std::string("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));  // secret-scan: allow public vector
}

MT_TEST(hmac_hex_output_is_64_lowercase_hex_characters) {
    const std::string h = hmacSha256Hex("k", "m");
    MT_CHECK_EQ(h.size(), static_cast<size_t>(64));
    bool hexOnly = true;
    for (char c : h) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) hexOnly = false;
    }
    MT_CHECK(hexOnly);
}

MT_TEST(hmac_changes_when_key_or_message_changes) {
    MT_CHECK(hmacSha256Hex("k1", "m") != hmacSha256Hex("k2", "m"));
    MT_CHECK(hmacSha256Hex("k", "m1") != hmacSha256Hex("k", "m2"));
}

MINITEST_MAIN()
