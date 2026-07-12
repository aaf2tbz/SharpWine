// SPDX-License-Identifier: Apache-2.0
//
// Portable 4 KiB guest-page isolation and concurrency test for issue #13.
//
// One 16 KiB-aligned, 16 KiB identity allocation is split into four 4 KiB
// logical pages.  On Apple ARM64 the host page size is required to be 16384 so
// the four logical pages share exactly one host page.  Independent protection,
// guard consumption, write-copy detachment, reserve/commit/decommit, aliasing,
// transactional cross-page failures with unchanged caller outputs, and
// deterministic synchronized concurrency are all exercised through GEM.  The
// identity backing is read directly only as an oracle and is never mutated
// directly except by GEM; it remains live until unmap.

#include "memory_internal.h" // internal gem_memory_peek for transactional-peek coverage
#include "metalsharp/gem/memory.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#if defined(_WIN32)
#include <malloc.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace {

constexpr std::uint64_t kGuestPage = GEM_GUEST_PAGE_SIZE;      // 4096
constexpr std::size_t kPagesPerHost = 4U;                      // 4 * 4096 == 16384
constexpr std::size_t kIsolationBytes = kPagesPerHost * 4096U; // 16384
constexpr std::uint64_t kMinIdentityAddress = UINT64_C(0x100000000);
constexpr unsigned int kGuardWorkers = 32U;
constexpr unsigned int kWriteCopyWorkers = 32U;
constexpr unsigned int kDeniedWorkers = 8U;
constexpr unsigned int kDeniedIterations = 1000U;

std::size_t host_page_size() {
#if defined(_WIN32)
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return static_cast<std::size_t>(info.dwPageSize);
#else
    const long s = ::sysconf(_SC_PAGESIZE);
    return s > 0 ? static_cast<std::size_t>(s) : 0U;
#endif
}

void *aligned_alloc_pages(std::size_t alignment, std::size_t size) {
#if defined(_WIN32)
    return ::_aligned_malloc(size, alignment);
#else
    void *p = nullptr;
    if (::posix_memalign(&p, alignment, size) != 0)
        return nullptr;
    return p;
#endif
}

void aligned_free_pages(void *p) {
#if defined(_WIN32)
    ::_aligned_free(p);
#else
    ::free(p);
#endif
}

// Allocate a 16 KiB-aligned, 16 KiB region whose numeric address is at least
// kMinIdentityAddress (identity requires address == host pointer >= 4 GiB).
// Deterministic bounded retry; no sleeps or RNG.
std::uint8_t *alloc_identity_storage() {
    for (int attempt = 0; attempt < 64; ++attempt) {
        std::uint8_t *p =
            static_cast<std::uint8_t *>(aligned_alloc_pages(kIsolationBytes, kIsolationBytes));
        if (p == nullptr)
            break;
        const std::uintptr_t up = reinterpret_cast<std::uintptr_t>(p);
        if (static_cast<std::uint64_t>(up) >= kMinIdentityAddress && up % kIsolationBytes == 0U)
            return p;
        aligned_free_pages(p);
    }
    return nullptr;
}

std::uint64_t page_base(std::uint64_t base, std::size_t index) {
    return base + static_cast<std::uint64_t>(index) * kGuestPage;
}

void fill_canary(std::uint8_t *buf, std::size_t n, std::uint8_t seed) {
    for (std::size_t i = 0; i < n; ++i)
        buf[i] = static_cast<std::uint8_t>(seed + static_cast<std::uint8_t>(i));
}

bool is_canary(const std::uint8_t *buf, std::size_t n, std::uint8_t seed) {
    for (std::size_t i = 0; i < n; ++i)
        if (buf[i] != static_cast<std::uint8_t>(seed + static_cast<std::uint8_t>(i)))
            return false;
    return true;
}

void check_eq(const char *label, gem_memory_error actual, gem_memory_error expected) {
    if (actual != expected) {
        std::fprintf(stderr, "%s: expected %s, got %s\n", label, gem_memory_error_name(expected),
                     gem_memory_error_name(actual));
        std::abort();
    }
}

// Obtain a free, aligned guest address that is not currently reserved.  GEM's
// alias helper creates its own reservation, so the caller must hand it an
// address that is not already occupied.  reserve auto-picks the first free
// slot; releasing it returns the slot to free for the subsequent alias.
std::uint64_t fresh_address(gem_memory *mem, std::uint64_t n) {
    std::uint64_t a = 0U;
    check_eq("fresh reserve", gem_memory_reserve(mem, &a, n), GEM_MEMORY_OK);
    check_eq("fresh release", gem_memory_release(mem, a, n), GEM_MEMORY_OK);
    return a;
}

// Deterministic start gate: no sleeps, no scheduling assumptions.  The gate
// counts arrivals under its mutex; release() waits until every expected worker
// has entered wait(), then sets go and notifies, so every concurrent test
// deterministically begins with all contenders waiting.  This avoids lost
// wakeups (workers call wait(), which registers arrival before sleeping) and
// guarantees no worker races ahead before the full set is parked.
struct StartGate {
    explicit StartGate(unsigned int expected) : expected_workers(expected) {
    }
    void wait() {
        std::unique_lock<std::mutex> lk(mu);
        ++arrived;
        arrived_cv.notify_one();
        go_cv.wait(lk, [this] { return go; });
    }
    void release() {
        std::unique_lock<std::mutex> lk(mu);
        arrived_cv.wait(lk, [this] { return arrived >= expected_workers; });
        go = true;
        go_cv.notify_all();
    }

  private:
    std::mutex mu;
    std::condition_variable arrived_cv;
    std::condition_variable go_cv;
    unsigned int expected_workers = 0U;
    unsigned int arrived = 0U;
    bool go = false;
};

void run_single_threaded(gem_memory *mem, std::uint64_t base, std::uint8_t *host) {
    assert(mem != nullptr);
    assert(host != nullptr);
    const std::uint64_t p0 = page_base(base, 0);
    const std::uint64_t p1 = page_base(base, 1);
    const std::uint64_t p2 = page_base(base, 2);
    const std::uint64_t p3 = page_base(base, 3);
    std::uint8_t out[16];
    std::uint8_t val = 0U;

    assert((reinterpret_cast<std::uintptr_t>(host) % kIsolationBytes) == 0U);
    assert(base == static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(host)));
    assert(base >= kMinIdentityAddress);

    // The four logical page bases each map to a 4 KiB slice of the same
    // allocation.  Write a per-page marker byte through GEM and confirm the
    // identity oracle sees it at the matching host offset.
    const std::array<std::uint8_t, 4> markers{{0xA0U, 0xB0U, 0xC0U, 0xD0U}};
    for (std::size_t i = 0; i < kPagesPerHost; ++i) {
        val = markers[i];
        check_eq("marker write", gem_memory_write(mem, page_base(base, i), &val, 1U),
                 GEM_MEMORY_OK);
        assert(host[i * 4096U] == markers[i]);
    }

    // Independent policies: RO / RW / EXECUTE_READ / NOACCESS.
    check_eq("protect ro", gem_memory_protect(mem, p0, kGuestPage, GEM_PAGE_READONLY, nullptr),
             GEM_MEMORY_OK);
    check_eq("protect rw", gem_memory_protect(mem, p1, kGuestPage, GEM_PAGE_READWRITE, nullptr),
             GEM_MEMORY_OK);
    check_eq("protect er", gem_memory_protect(mem, p2, kGuestPage, GEM_PAGE_EXECUTE_READ, nullptr),
             GEM_MEMORY_OK);
    check_eq("protect na", gem_memory_protect(mem, p3, kGuestPage, GEM_PAGE_NOACCESS, nullptr),
             GEM_MEMORY_OK);

    assert(gem_memory_read(mem, p0, out, 1U) == GEM_MEMORY_OK && out[0] == markers[0]);
    assert(gem_memory_write(mem, p0, &val, 1U) == GEM_MEMORY_ACCESS_DENIED);
    assert(gem_memory_fetch(mem, p0, out, 1U) == GEM_MEMORY_ACCESS_DENIED);
    assert(gem_memory_is_executable(mem, p0, 1U) == false);

    val = 0x77U;
    assert(gem_memory_write(mem, p1, &val, 1U) == GEM_MEMORY_OK);
    assert(gem_memory_read(mem, p1, out, 1U) == GEM_MEMORY_OK && out[0] == val);
    assert(gem_memory_is_executable(mem, p1, 1U) == false);

    assert(gem_memory_read(mem, p2, out, 1U) == GEM_MEMORY_OK);
    assert(gem_memory_fetch(mem, p2, out, 1U) == GEM_MEMORY_OK && out[0] == markers[2]);
    assert(gem_memory_write(mem, p2, &val, 1U) == GEM_MEMORY_ACCESS_DENIED);
    assert(gem_memory_is_executable(mem, p2, 1U) == true);

    assert(gem_memory_read(mem, p3, out, 1U) == GEM_MEMORY_ACCESS_DENIED);
    assert(gem_memory_write(mem, p3, &val, 1U) == GEM_MEMORY_ACCESS_DENIED);
    assert(gem_memory_fetch(mem, p3, out, 1U) == GEM_MEMORY_ACCESS_DENIED);
    assert(gem_memory_is_executable(mem, p3, 1U) == false);

    // Execute-only policy: fetch succeeds while read and write are denied.
    check_eq("protect execute-only",
             gem_memory_protect(mem, p1, kGuestPage, GEM_PAGE_EXECUTE, nullptr), GEM_MEMORY_OK);
    assert(gem_memory_fetch(mem, p1, out, 1U) == GEM_MEMORY_OK);
    assert(gem_memory_read(mem, p1, out, 1U) == GEM_MEMORY_ACCESS_DENIED);
    assert(gem_memory_write(mem, p1, &val, 1U) == GEM_MEMORY_ACCESS_DENIED);
    assert(gem_memory_is_executable(mem, p1, 1U) == true);

    // Invalid protection never mutates state.
    // An invalid protection never writes old_protection: the caller output stays
    // unchanged (the success path writes *old only after prot_ok succeeds).
    uint32_t oldp = 0xABCDEF01U;
    check_eq(
        "protect invalid-combined",
        gem_memory_protect(mem, p0, kGuestPage, GEM_PAGE_READWRITE | GEM_PAGE_WRITECOPY, &oldp),
        GEM_MEMORY_INVALID_ARGUMENT);
    assert(oldp == 0xABCDEF01U);
    // A valid protect reports the previous protection through old_protection.
    oldp = 0U;
    check_eq("protect valid ro->rw",
             gem_memory_protect(mem, p0, kGuestPage, GEM_PAGE_READWRITE, &oldp), GEM_MEMORY_OK);
    assert(oldp == GEM_PAGE_READONLY);
    check_eq("protect restore ro",
             gem_memory_protect(mem, p0, kGuestPage, GEM_PAGE_READONLY, nullptr), GEM_MEMORY_OK);
    check_eq("protect zero", gem_memory_protect(mem, p0, kGuestPage, 0U, nullptr),
             GEM_MEMORY_INVALID_ARGUMENT);
    check_eq("protect guard-only", gem_memory_protect(mem, p0, kGuestPage, GEM_PAGE_GUARD, nullptr),
             GEM_MEMORY_INVALID_ARGUMENT);
    check_eq("protect na-guard",
             gem_memory_protect(mem, p0, kGuestPage, GEM_PAGE_NOACCESS | GEM_PAGE_GUARD, nullptr),
             GEM_MEMORY_INVALID_ARGUMENT);
    assert(gem_memory_read(mem, p0, out, 1U) == GEM_MEMORY_OK && out[0] == markers[0]);

    // Guard page: query does not consume; first real access consumes and fails
    // without changing caller output; subsequent access succeeds.
    check_eq(
        "protect er-guard",
        gem_memory_protect(mem, p2, kGuestPage, GEM_PAGE_EXECUTE_READ | GEM_PAGE_GUARD, nullptr),
        GEM_MEMORY_OK);
    fill_canary(out, sizeof(out), 0x11U);
    assert(gem_memory_is_executable(mem, p2, 1U) == true);
    check_eq("first fetch guard", gem_memory_fetch(mem, p2, out, 1U), GEM_MEMORY_GUARD_PAGE);
    assert(is_canary(out, sizeof(out), 0x11U));
    fill_canary(out, sizeof(out), 0x22U);
    check_eq("second fetch", gem_memory_fetch(mem, p2, out, 1U), GEM_MEMORY_OK);
    assert(out[0] == markers[2]);
    assert(is_canary(out + 1, sizeof(out) - 1U, 0x23U));
    assert(gem_memory_is_executable(mem, p2, 1U) == true);

    // Guard on a read/write page: a write access consumes then retries cleanly.
    check_eq("protect rw-guard",
             gem_memory_protect(mem, p1, kGuestPage, GEM_PAGE_READWRITE | GEM_PAGE_GUARD, nullptr),
             GEM_MEMORY_OK);
    val = 0x9U;
    check_eq("first write guard", gem_memory_write(mem, p1, &val, 1U), GEM_MEMORY_GUARD_PAGE);
    check_eq("second write", gem_memory_write(mem, p1, &val, 1U), GEM_MEMORY_OK);
    assert(gem_memory_read(mem, p1, out, 1U) == GEM_MEMORY_OK && out[0] == val);

    // Decommit one subpage while neighbors remain usable; recommit is zeroed and
    // private, without disturbing the external identity storage.
    {
        std::array<std::uint8_t, kIsolationBytes> snapshot;
        std::memcpy(snapshot.data(), host, kIsolationBytes);
        check_eq("decommit p3", gem_memory_decommit(mem, p3, kGuestPage), GEM_MEMORY_OK);
        check_eq("read decommitted", gem_memory_read(mem, p3, out, 1U), GEM_MEMORY_NOT_COMMITTED);
        assert(gem_memory_read(mem, p2, out, 1U) == GEM_MEMORY_OK);
        check_eq("recommit p3", gem_memory_commit(mem, p3, kGuestPage, GEM_PAGE_READWRITE),
                 GEM_MEMORY_OK);
        assert(gem_memory_read(mem, p3, out, 1U) == GEM_MEMORY_OK && out[0] == 0U);
        assert(std::memcmp(host, snapshot.data(), kIsolationBytes) == 0);
    }

    // WRITECOPY detachment on an identity page: writing detaches into a private
    // 4 KiB copy; the corresponding host slice is no longer referenced and stays
    // unchanged.
    {
        check_eq("protect p0 wc",
                 gem_memory_protect(mem, p0, kGuestPage, GEM_PAGE_WRITECOPY, nullptr),
                 GEM_MEMORY_OK);
        const std::uint8_t before = host[0];
        val = 0x5AU;
        check_eq("writecopy write", gem_memory_write(mem, p0, &val, 1U), GEM_MEMORY_OK);
        assert(gem_memory_read(mem, p0, out, 1U) == GEM_MEMORY_OK && out[0] == val);
        assert(host[0] == before);
    }

    // EXECUTE_WRITECOPY detachment on an execute page.
    {
        check_eq("protect p2 ewc",
                 gem_memory_protect(mem, p2, kGuestPage, GEM_PAGE_EXECUTE_WRITECOPY, nullptr),
                 GEM_MEMORY_OK);
        const std::uint8_t before = host[2 * 4096U];
        val = 0xECU;
        check_eq("ewc write", gem_memory_write(mem, p2, &val, 1U), GEM_MEMORY_OK);
        assert(gem_memory_fetch(mem, p2, out, 1U) == GEM_MEMORY_OK && out[0] == val);
        assert(host[2 * 4096U] == before);
    }

    // Alias a separate region to p1 (READWRITE); changes are shared.  Then a
    // WRITECOPY alias write detaches without mutating the source.
    {
        const std::uint64_t alias_addr = fresh_address(mem, kGuestPage);
        check_eq("alias rw", gem_memory_alias(mem, alias_addr, p1, kGuestPage, GEM_PAGE_READWRITE),
                 GEM_MEMORY_OK);
        val = 0x31U;
        check_eq("alias rw write", gem_memory_write(mem, alias_addr, &val, 1U), GEM_MEMORY_OK);
        assert(gem_memory_read(mem, p1, out, 1U) == GEM_MEMORY_OK && out[0] == val);

        const std::uint64_t wcopy_addr = fresh_address(mem, kGuestPage);
        check_eq("alias wcopy",
                 gem_memory_alias(mem, wcopy_addr, p1, kGuestPage, GEM_PAGE_WRITECOPY),
                 GEM_MEMORY_OK);
        const std::uint8_t source_before = val;
        const std::uint8_t wval = 0x88U;
        check_eq("wcopy write", gem_memory_write(mem, wcopy_addr, &wval, 1U), GEM_MEMORY_OK);
        assert(gem_memory_read(mem, wcopy_addr, out, 1U) == GEM_MEMORY_OK && out[0] == wval);
        assert(gem_memory_read(mem, p1, out, 1U) == GEM_MEMORY_OK && out[0] == source_before);

        check_eq("unmap wcopy", gem_memory_unmap(mem, wcopy_addr, kGuestPage), GEM_MEMORY_OK);
        check_eq("unmap alias", gem_memory_unmap(mem, alias_addr, kGuestPage), GEM_MEMORY_OK);
    }

    // Transaction rollback must release every temporary WRITECOPY backing when
    // a later guarded page rejects the same staged commit. Repeating this path
    // makes the ownership regression visible to leak instrumentation while the
    // source-write propagation below proves the earlier COW page never detached.
    {
        constexpr unsigned int kRollbackIterations = 256U;
        const std::uint64_t wcopy_addr = fresh_address(mem, kGuestPage);
        const std::uint8_t source_seed = 0x41U;
        const std::uint8_t guarded_seed = 0x42U;
        check_eq("seed rollback source", gem_memory_write(mem, p1, &source_seed, 1U),
                 GEM_MEMORY_OK);
        check_eq("seed rollback guard", gem_memory_write(mem, p3, &guarded_seed, 1U),
                 GEM_MEMORY_OK);
        check_eq("alias rollback wcopy",
                 gem_memory_alias(mem, wcopy_addr, p1, kGuestPage, GEM_PAGE_WRITECOPY),
                 GEM_MEMORY_OK);
        std::array<std::uint8_t, 4096U> wcopy_data{};
        std::array<std::uint8_t, 4096U> guarded_data{};
        wcopy_data.fill(0xA1U);
        guarded_data.fill(0xA2U);
        const std::array<gem_memory_page_write, 2> writes{{
            {wcopy_addr, wcopy_data.data()},
            {p3, guarded_data.data()},
        }};
        for (unsigned int iteration = 0U; iteration < kRollbackIterations; ++iteration) {
            check_eq("protect rollback guard",
                     gem_memory_protect(mem, p3, kGuestPage, GEM_PAGE_READWRITE | GEM_PAGE_GUARD,
                                        nullptr),
                     GEM_MEMORY_OK);
            gem_memory_transaction *transaction = gem_memory_transaction_begin(mem);
            assert(transaction != nullptr);
            std::uint64_t fault_address = 0U;
            const gem_memory_error error = gem_memory_transaction_commit_pages(
                transaction, writes.data(), writes.size(), &fault_address);
            gem_memory_transaction_end(transaction);
            check_eq("rollback guarded COW transaction", error, GEM_MEMORY_GUARD_PAGE);
            assert(fault_address == p3);
            assert(gem_memory_read(mem, wcopy_addr, out, 1U) == GEM_MEMORY_OK &&
                   out[0] == source_seed);
            assert(gem_memory_read(mem, p3, out, 1U) == GEM_MEMORY_OK && out[0] == guarded_seed);
        }

        val = 0x5DU;
        check_eq("source write after rollback", gem_memory_write(mem, p1, &val, 1U), GEM_MEMORY_OK);
        assert(gem_memory_read(mem, wcopy_addr, out, 1U) == GEM_MEMORY_OK && out[0] == val);
        const std::uint8_t detached_value = 0x9EU;
        check_eq("COW write after rollback", gem_memory_write(mem, wcopy_addr, &detached_value, 1U),
                 GEM_MEMORY_OK);
        assert(gem_memory_read(mem, wcopy_addr, out, 1U) == GEM_MEMORY_OK &&
               out[0] == detached_value);
        assert(gem_memory_read(mem, p1, out, 1U) == GEM_MEMORY_OK && out[0] == val);
        check_eq("guarded page write after rollback",
                 gem_memory_write(mem, p3, &detached_value, 1U), GEM_MEMORY_OK);
        check_eq("unmap rollback wcopy", gem_memory_unmap(mem, wcopy_addr, kGuestPage),
                 GEM_MEMORY_OK);
    }

    // Operations that require 4 KiB alignment reject misalignment without
    // mutation.  (read/write/fetch/peek legally handle in-page misalignment; their
    // misaligned failure modes are the cross-page later-page denials below, which
    // start at the misaligned offset kGuestPage - 1.)
    {
        const std::uint64_t bad = p0 + 1U;
        check_eq("commit misaligned", gem_memory_commit(mem, bad, kGuestPage, GEM_PAGE_READWRITE),
                 GEM_MEMORY_INVALID_ARGUMENT);
        check_eq("decommit misaligned", gem_memory_decommit(mem, bad, kGuestPage),
                 GEM_MEMORY_INVALID_ARGUMENT);
        check_eq("protect misaligned",
                 gem_memory_protect(mem, bad, kGuestPage, GEM_PAGE_READONLY, nullptr),
                 GEM_MEMORY_INVALID_ARGUMENT);
        check_eq("alias misaligned", gem_memory_alias(mem, bad, p1, kGuestPage, GEM_PAGE_READWRITE),
                 GEM_MEMORY_INVALID_ARGUMENT);
        std::uint64_t a = 0U;
        check_eq("reserve misaligned-size", gem_memory_reserve(mem, &a, 1U),
                 GEM_MEMORY_INVALID_ARGUMENT);
        assert(gem_memory_read(mem, p0, out, 1U) == GEM_MEMORY_OK && out[0] == 0x5AU);
    }

    // Cross-page read/write where a later NOACCESS page denies access; the
    // writable first page is left unchanged (verified through GEM and the host
    // oracle).  p0 is made writable for both read and write snapshots.
    check_eq("protect p0 rw-2",
             gem_memory_protect(mem, p0, kGuestPage, GEM_PAGE_READWRITE, nullptr), GEM_MEMORY_OK);
    check_eq("protect p1 na-2", gem_memory_protect(mem, p1, kGuestPage, GEM_PAGE_NOACCESS, nullptr),
             GEM_MEMORY_OK);
    {
        const std::uint8_t stored = 0xC2U;
        assert(gem_memory_write(mem, p0 + kGuestPage - 1U, &stored, 1U) == GEM_MEMORY_OK);
        std::array<std::uint8_t, kIsolationBytes> snapshot;
        std::memcpy(snapshot.data(), host, kIsolationBytes);
        std::array<std::uint8_t, 2> payload{{0xFFU, 0xEEU}};
        fill_canary(out, sizeof(out), 0x05U);
        check_eq("cross read denied", gem_memory_read(mem, p0 + kGuestPage - 1U, out, 2U),
                 GEM_MEMORY_ACCESS_DENIED);
        assert(is_canary(out, sizeof(out), 0x05U));
        check_eq("cross write denied",
                 gem_memory_write(mem, p0 + kGuestPage - 1U, payload.data(), payload.size()),
                 GEM_MEMORY_ACCESS_DENIED);
        assert(gem_memory_read(mem, p0 + kGuestPage - 1U, out, 1U) == GEM_MEMORY_OK &&
               out[0] == stored);
        assert(std::memcmp(host, snapshot.data(), kIsolationBytes) == 0);
    }

    // Cross-page fetch where a later NOACCESS page denies access; caller output
    // unchanged.  p2 is made EXECUTE_READ for the fetch baseline.
    check_eq("protect p2 er-2",
             gem_memory_protect(mem, p2, kGuestPage, GEM_PAGE_EXECUTE_READ, nullptr),
             GEM_MEMORY_OK);
    check_eq("protect p3 na-2", gem_memory_protect(mem, p3, kGuestPage, GEM_PAGE_NOACCESS, nullptr),
             GEM_MEMORY_OK);
    {
        fill_canary(out, sizeof(out), 0x07U);
        check_eq("cross fetch denied", gem_memory_fetch(mem, p2 + kGuestPage - 1U, out, 2U),
                 GEM_MEMORY_ACCESS_DENIED);
        assert(is_canary(out, sizeof(out), 0x07U));
        std::uint8_t b = 0U;
        check_eq("baseline fetch", gem_memory_fetch(mem, p2, &b, 1U), GEM_MEMORY_OK);
        assert(b == 0xECU);
    }

    // Cross-page peek where a later page is reserved but uncommitted: peek
    // ignores protection, so the transactional failure must come from the
    // uncommitted later page and leave the caller output unchanged.
    {
        std::uint64_t r = 0U;
        check_eq("reserve peek-region", gem_memory_reserve(mem, &r, kGuestPage * 2U),
                 GEM_MEMORY_OK);
        check_eq("commit peek-first", gem_memory_commit(mem, r, kGuestPage, GEM_PAGE_READWRITE),
                 GEM_MEMORY_OK);
        const std::uint8_t sval = 0x6U;
        check_eq("seed peek-first", gem_memory_write(mem, r, &sval, 1U), GEM_MEMORY_OK);
        fill_canary(out, sizeof(out), 0x03U);
        check_eq("cross peek uncommitted", gem_memory_peek(mem, r + kGuestPage - 1U, out, 2U),
                 GEM_MEMORY_NOT_COMMITTED);
        assert(is_canary(out, sizeof(out), 0x03U));
        fill_canary(out, sizeof(out), 0x04U);
        check_eq("single peek", gem_memory_peek(mem, r, out, 1U), GEM_MEMORY_OK);
        assert(out[0] == sval);
        assert(is_canary(out + 1, sizeof(out) - 1U, 0x05U));
        check_eq("release peek-region", gem_memory_release(mem, r, kGuestPage * 2U), GEM_MEMORY_OK);
    }

    // Reset all four identity pages to a usable READWRITE state for concurrency.
    for (std::size_t i = 0; i < kPagesPerHost; ++i)
        check_eq(
            "reset rw",
            gem_memory_protect(mem, page_base(base, i), kGuestPage, GEM_PAGE_READWRITE, nullptr),
            GEM_MEMORY_OK);
}

// Synchronized guard fault: exactly one consumer across concurrent fetchers.
void run_concurrent_guard(gem_memory *mem, std::uint64_t guarded_page,
                          std::uint8_t sentinel_after) {
    check_eq("guard setup",
             gem_memory_protect(mem, guarded_page, kGuestPage,
                                GEM_PAGE_EXECUTE_READ | GEM_PAGE_GUARD, nullptr),
             GEM_MEMORY_OK);
    StartGate gate(kGuardWorkers);
    std::vector<std::thread> workers;
    workers.reserve(kGuardWorkers);
    std::vector<gem_memory_error> results(kGuardWorkers, GEM_MEMORY_OK);
    std::vector<std::uint8_t> outs(kGuardWorkers, 0U);
    for (unsigned int i = 0; i < kGuardWorkers; ++i) {
        workers.emplace_back([mem, guarded_page, i, &gate, &results, &outs]() {
            gate.wait();
            std::uint8_t b = 0U;
            results[i] = gem_memory_fetch(mem, guarded_page, &b, 1U);
            outs[i] = b;
        });
    }
    gate.release();
    for (auto &t : workers)
        t.join();

    unsigned int guard_count = 0U;
    unsigned int ok_count = 0U;
    for (unsigned int i = 0; i < kGuardWorkers; ++i) {
        if (results[i] == GEM_MEMORY_GUARD_PAGE) {
            ++guard_count;
            assert(outs[i] == 0U);
        } else if (results[i] == GEM_MEMORY_OK) {
            ++ok_count;
            assert(outs[i] == sentinel_after);
        } else {
            std::fprintf(stderr, "concurrent guard: unexpected result %s\n",
                         gem_memory_error_name(results[i]));
            std::abort();
        }
    }
    assert(guard_count == 1U);
    assert(ok_count == kGuardWorkers - 1U);
}

// Distinct-offset write-copy writers: every write is accepted and present in the
// detached alias; the source page remains unchanged.
void run_concurrent_write_copy(gem_memory *mem, std::uint64_t source_page,
                               std::uint8_t source_value) {
    const std::uint64_t alias_addr = fresh_address(mem, kGuestPage);
    check_eq("wc alias",
             gem_memory_alias(mem, alias_addr, source_page, kGuestPage, GEM_PAGE_WRITECOPY),
             GEM_MEMORY_OK);

    StartGate gate(kWriteCopyWorkers);
    std::vector<std::thread> workers;
    workers.reserve(kWriteCopyWorkers);
    std::vector<gem_memory_error> results(kWriteCopyWorkers, GEM_MEMORY_OK);
    for (unsigned int i = 0; i < kWriteCopyWorkers; ++i) {
        workers.emplace_back([mem, alias_addr, i, &gate, &results]() {
            gate.wait();
            const std::uint64_t offset = static_cast<std::uint64_t>(i);
            const std::uint8_t value = static_cast<std::uint8_t>(0x80U + static_cast<unsigned>(i));
            results[i] = gem_memory_write(mem, alias_addr + offset, &value, 1U);
        });
    }
    gate.release();
    for (auto &t : workers)
        t.join();

    for (unsigned int i = 0; i < kWriteCopyWorkers; ++i)
        check_eq("wc worker", results[i], GEM_MEMORY_OK);

    for (unsigned int i = 0; i < kWriteCopyWorkers; ++i) {
        const std::uint64_t offset = static_cast<std::uint64_t>(i);
        std::uint8_t b = 0U;
        check_eq("wc readback", gem_memory_read(mem, alias_addr + offset, &b, 1U), GEM_MEMORY_OK);
        assert(b == static_cast<std::uint8_t>(0x80U + static_cast<unsigned>(i)));
    }
    std::uint8_t b = 0U;
    check_eq("wc source read", gem_memory_read(mem, source_page, &b, 1U), GEM_MEMORY_OK);
    assert(b == source_value);

    check_eq("wc unmap", gem_memory_unmap(mem, alias_addr, kGuestPage), GEM_MEMORY_OK);
}

// Independent subpages: each worker writes and reads only its own page; final
// per-page content is the worker's deterministic pattern.
void run_concurrent_subpages(gem_memory *mem, std::uint64_t base) {
    StartGate gate(static_cast<unsigned int>(kPagesPerHost));
    std::vector<std::thread> workers;
    workers.reserve(kPagesPerHost);
    std::vector<gem_memory_error> fail(kPagesPerHost, GEM_MEMORY_OK);
    for (std::size_t i = 0; i < kPagesPerHost; ++i) {
        workers.emplace_back([mem, base, i, &gate, &fail]() {
            gate.wait();
            const std::uint64_t addr = page_base(base, i);
            for (std::size_t k = 0; k < 64U; ++k) {
                const std::uint8_t value = static_cast<std::uint8_t>(
                    0x40U * static_cast<unsigned>(i) + static_cast<unsigned>(k));
                fail[i] = gem_memory_write(mem, addr + k, &value, 1U);
                if (fail[i] != GEM_MEMORY_OK)
                    return;
                std::uint8_t b = 0U;
                fail[i] = gem_memory_read(mem, addr + k, &b, 1U);
                if (fail[i] != GEM_MEMORY_OK || b != value) {
                    fail[i] = GEM_MEMORY_ACCESS_DENIED;
                    return;
                }
            }
        });
    }
    gate.release();
    for (auto &t : workers)
        t.join();

    for (std::size_t i = 0; i < kPagesPerHost; ++i) {
        assert(fail[i] == GEM_MEMORY_OK);
        for (std::size_t k = 0; k < 64U; ++k) {
            std::uint8_t b = 0U;
            check_eq("subpage read", gem_memory_read(mem, page_base(base, i) + k, &b, 1U),
                     GEM_MEMORY_OK);
            assert(b == static_cast<std::uint8_t>(0x40U * static_cast<unsigned>(i) +
                                                  static_cast<unsigned>(k)));
        }
    }
}

// Repeated concurrent denied cross-page writes: every attempt is denied and no
// partial mutation reaches the writable page or its denied neighbor.  The
// denied neighbor is NOACCESS, so it is snapshotted via the identity host oracle
// (its backing is the external identity slice), not through GEM.
void run_concurrent_denied_cross_page(gem_memory *mem, std::uint64_t writable, std::uint8_t *host,
                                      std::size_t denied_host_off) {
    std::array<std::uint8_t, 4096> snapshot_w;
    check_eq("denied snapshot w", gem_memory_read(mem, writable, snapshot_w.data(), 4096U),
             GEM_MEMORY_OK);
    std::array<std::uint8_t, 4096> snapshot_d;
    std::memcpy(snapshot_d.data(), host + denied_host_off, 4096U);

    StartGate gate(kDeniedWorkers);
    std::vector<std::thread> workers;
    workers.reserve(kDeniedWorkers);
    std::atomic<unsigned int> denied_count{0U};
    std::atomic<unsigned int> other_count{0U};
    for (unsigned int i = 0; i < kDeniedWorkers; ++i) {
        workers.emplace_back([mem, writable, i, &gate, &denied_count, &other_count]() {
            gate.wait();
            std::array<std::uint8_t, 2> payload{
                {static_cast<std::uint8_t>(i), static_cast<std::uint8_t>(0xF0U + i)}};
            for (unsigned int k = 0; k < kDeniedIterations; ++k) {
                const gem_memory_error e = gem_memory_write(mem, writable + kGuestPage - 1U,
                                                            payload.data(), payload.size());
                if (e == GEM_MEMORY_ACCESS_DENIED)
                    denied_count.fetch_add(1U, std::memory_order_relaxed);
                else
                    other_count.fetch_add(1U, std::memory_order_relaxed);
            }
        });
    }
    gate.release();
    for (auto &t : workers)
        t.join();

    assert(other_count.load() == 0U);
    assert(denied_count.load() == kDeniedWorkers * kDeniedIterations);

    std::uint8_t b = 0U;
    check_eq("denied tail read", gem_memory_read(mem, writable + kGuestPage - 1U, &b, 1U),
             GEM_MEMORY_OK);
    assert(b == snapshot_w[4095]);
    std::array<std::uint8_t, 4096> after_d;
    std::memcpy(after_d.data(), host + denied_host_off, 4096U);
    assert(std::memcmp(after_d.data(), snapshot_d.data(), 4096U) == 0);
}

} // namespace

int main(void) {
    const std::size_t hps = host_page_size();
    assert(hps == 4096U || hps == 16384U);
#if defined(__APPLE__) && defined(__aarch64__)
    assert(hps == 16384U);
#endif

    std::uint8_t *host = alloc_identity_storage();
    assert(host != nullptr);

    for (std::size_t i = 0; i < kIsolationBytes; ++i)
        host[i] = static_cast<std::uint8_t>(i);

    gem_memory *mem = gem_memory_create();
    assert(mem != nullptr);

    const std::uint64_t base = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(host));
    check_eq("map identity",
             gem_memory_map_identity(mem, base, host, kIsolationBytes, GEM_PAGE_READWRITE),
             GEM_MEMORY_OK);

    run_single_threaded(mem, base, host);

    // The single-threaded phase permanently detaches p0/p2 via write-copy and
    // p3 via decommit/recommit, so the original identity backings for those
    // slices are no longer referenced.  Remap a fresh identity reservation over
    // the same 16 KiB host allocation so every concurrent test runs over four
    // 4 KiB slices of one identity backing, with no stale detached pages.
    check_eq("unmap identity (pre-concurrency)", gem_memory_unmap(mem, base, kIsolationBytes),
             GEM_MEMORY_OK);
    for (std::size_t i = 0; i < kIsolationBytes; ++i)
        host[i] = static_cast<std::uint8_t>(0U);
    check_eq("remap identity",
             gem_memory_map_identity(mem, base, host, kIsolationBytes, GEM_PAGE_READWRITE),
             GEM_MEMORY_OK);
    std::uint8_t sanity = 0xFFU;
    check_eq("remap readback", gem_memory_read(mem, base, &sanity, 1U), GEM_MEMORY_OK);
    assert(sanity == 0U);

    const std::uint64_t p0 = page_base(base, 0);
    const std::uint64_t p1 = page_base(base, 1);
    const std::uint64_t p2 = page_base(base, 2);

    // Seed all four identity pages deterministically through GEM.  p1 stays the
    // write-copy source; no identity page is permanently detached by these
    // concurrent tests (the write-copy test detaches only its separate alias).
    for (std::size_t i = 0; i < kPagesPerHost; ++i) {
        const std::uint8_t v = static_cast<std::uint8_t>(0x10U * static_cast<unsigned>(i) + 1U);
        check_eq("concurrency seed", gem_memory_write(mem, page_base(base, i), &v, 1U),
                 GEM_MEMORY_OK);
    }

    run_concurrent_guard(mem, p2, /*sentinel_after=*/static_cast<std::uint8_t>(0x21U));
    run_concurrent_write_copy(mem, p1, /*source_value=*/static_cast<std::uint8_t>(0x11U));

    for (std::size_t i = 0; i < kPagesPerHost; ++i) {
        check_eq(
            "subpages reset",
            gem_memory_protect(mem, page_base(base, i), kGuestPage, GEM_PAGE_READWRITE, nullptr),
            GEM_MEMORY_OK);
        const std::uint8_t v = static_cast<std::uint8_t>(0x30U * static_cast<unsigned>(i) + 7U);
        check_eq("subpages seed", gem_memory_write(mem, page_base(base, i), &v, 1U), GEM_MEMORY_OK);
    }
    run_concurrent_subpages(mem, base);

    check_eq("denied protect na",
             gem_memory_protect(mem, p1, kGuestPage, GEM_PAGE_NOACCESS, nullptr), GEM_MEMORY_OK);
    run_concurrent_denied_cross_page(mem, p0, host, static_cast<std::size_t>(p1 - base));
    check_eq("denied restore rw",
             gem_memory_protect(mem, p1, kGuestPage, GEM_PAGE_READWRITE, nullptr), GEM_MEMORY_OK);

    // Final unmap of the remapped identity reservation: exactly once.
    check_eq("unmap identity (final)", gem_memory_unmap(mem, base, kIsolationBytes), GEM_MEMORY_OK);
    assert(gem_memory_read(mem, base, host, 1U) == GEM_MEMORY_NOT_RESERVED);
    aligned_free_pages(host);
    gem_memory_destroy(mem);
    return 0;
}
