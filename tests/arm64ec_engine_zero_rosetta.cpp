// SPDX-License-Identifier: Apache-2.0
#include <cstdio>
#include <cstdlib>

#if defined(__APPLE__)
#include <cstring>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#endif

namespace {

[[noreturn]] void Fail(const char *message) {
    std::fprintf(stderr, "zero-Rosetta audit failed: %s\n", message);
    std::abort();
}

} // namespace

int main() {
#if defined(__APPLE__)
    utsname name{};
    if (uname(&name) != 0)
        Fail("uname failed");
    if (std::strcmp(name.machine, "arm64") != 0)
        Fail("process machine is not arm64");
#if !defined(__aarch64__)
    Fail("test binary was not compiled for AArch64");
#endif
    int translated = 0;
    std::size_t translated_size = sizeof(translated);
    if (sysctlbyname("sysctl.proc_translated", &translated, &translated_size, nullptr, 0) == 0 &&
        translated != 0)
        Fail("process is running under Rosetta");
#else
    Fail("zero-Rosetta audit is only meaningful on macOS ARM64");
#endif
    return 0;
}
