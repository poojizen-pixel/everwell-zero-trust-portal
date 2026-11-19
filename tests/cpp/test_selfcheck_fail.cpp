// Deliberately failing test. It is compiled ONLY by `scripts\run-tests.ps1 -InjectFailure`, to prove that a failing
// test is reported as FAIL and makes the runner exit non-zero. It is never part of a normal run.
#include "mini_test.h"

MT_TEST(deliberately_failing_check) {
    MT_CHECK_EQ(1 + 1, 3);
}

MINITEST_MAIN()
