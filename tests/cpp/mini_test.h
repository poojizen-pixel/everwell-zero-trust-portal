// mini_test.h - a small, dependency-free unit-test header for this project's C++ code.
//
// Usage (one translation unit per test file):
//     #include "mini_test.h"
//     MT_TEST(addition_works) { MT_CHECK_EQ(1 + 1, 2); }
//     MINITEST_MAIN()
//
// Output is line based so scripts/run-tests.ps1 can read it:
//     RUN  <test>   /   PASS <test>   or   FAIL <test>   /   SUMMARY tests=N passed=P failed=F checks=C
// The process exit code is 0 when every test passed and 1 otherwise. A test that throws is reported as FAIL;
// a test that crashes the process is caught by the runner because there is no SUMMARY line and the exit code is non-zero.
#pragma once

#include <cstdio>
#include <exception>
#include <sstream>
#include <string>
#include <vector>

namespace minitest {

struct TestCase {
    const char* name;
    void (*fn)();
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> tests;
    return tests;
}

struct Registrar {
    Registrar(const char* name, void (*fn)()) { registry().push_back({name, fn}); }
};

struct State {
    int checks = 0;
    int failedChecks = 0;
};

inline State& state() {
    static State s;
    return s;
}

template <typename T>
inline std::string show(const T& value) {
    std::ostringstream out;
    out << value;
    return out.str();
}
inline std::string show(const std::string& value) { return "\"" + value + "\""; }
inline std::string show(const char* value) { return std::string("\"") + (value ? value : "(null)") + "\""; }
inline std::string show(bool value) { return value ? "true" : "false"; }

inline void checkFailed(const char* file, int line, const std::string& what) {
    ++state().failedChecks;
    std::printf("    CHECK FAILED at %s:%d: %s\n", file, line, what.c_str());
}

template <typename A, typename B>
inline void checkEq(const A& a, const B& b, const char* exprA, const char* exprB, const char* file, int line) {
    ++state().checks;
    if (!(a == b)) {
        checkFailed(file, line, std::string(exprA) + " == " + exprB + "   (left: " + show(a) + ", right: " + show(b) + ")");
    }
}

inline int runAll() {
    int passed = 0;
    int failed = 0;
    for (const TestCase& test : registry()) {
        const int failuresBefore = state().failedChecks;
        std::printf("RUN  %s\n", test.name);
        std::fflush(stdout);
        try {
            test.fn();
        } catch (const std::exception& e) {
            ++state().failedChecks;
            std::printf("    UNCAUGHT EXCEPTION: %s\n", e.what());
        } catch (...) {
            ++state().failedChecks;
            std::printf("    UNCAUGHT NON-STANDARD EXCEPTION\n");
        }
        if (state().failedChecks == failuresBefore) {
            ++passed;
            std::printf("PASS %s\n", test.name);
        } else {
            ++failed;
            std::printf("FAIL %s\n", test.name);
        }
    }
    std::printf("SUMMARY tests=%d passed=%d failed=%d checks=%d\n", passed + failed, passed, failed, state().checks);
    return failed == 0 ? 0 : 1;
}

}  // namespace minitest

#define MT_TEST(name)                                                       \
    static void name();                                                     \
    static minitest::Registrar mt_registrar_##name(#name, &name);           \
    static void name()

#define MT_CHECK(cond)                                                      \
    do {                                                                    \
        ++minitest::state().checks;                                         \
        if (!(cond)) minitest::checkFailed(__FILE__, __LINE__, #cond);      \
    } while (0)

#define MT_CHECK_EQ(a, b) minitest::checkEq((a), (b), #a, #b, __FILE__, __LINE__)

#define MINITEST_MAIN() \
    int main() { return minitest::runAll(); }
