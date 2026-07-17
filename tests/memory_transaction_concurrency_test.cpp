// SPDX-License-Identifier: Apache-2.0
#include "memory_internal.h"

#include <array>
#include <atomic>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <chrono>
#include <cstdint>
#include <thread>

namespace {
constexpr std::uint64_t kPage = GEM_GUEST_PAGE_SIZE;

void wait_for(const std::atomic<unsigned> &value, unsigned target) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (value.load(std::memory_order_acquire) < target) {
        assert(std::chrono::steady_clock::now() < deadline);
        std::this_thread::yield();
    }
}

void snapshot(gem_memory_transaction *transaction, std::uint64_t address,
              std::array<std::uint8_t, 4096> &bytes) {
    std::uint32_t protection = 0U;
    assert(gem_memory_transaction_snapshot_page(transaction, address, bytes.data(), &protection) ==
           GEM_MEMORY_OK);
    assert(protection == GEM_PAGE_READWRITE);
}

void concurrent_readers(gem_memory *memory, std::uint64_t address) {
    std::atomic<unsigned> ready{0U};
    std::atomic<bool> release{false};
    auto reader = [&]() {
        std::array<std::uint8_t, 4096> bytes{};
        gem_memory_transaction *transaction = gem_memory_transaction_begin(memory);
        assert(transaction != nullptr);
        snapshot(transaction, address, bytes);
        ready.fetch_add(1U, std::memory_order_release);
        while (!release.load(std::memory_order_acquire))
            std::this_thread::yield();
        gem_memory_transaction_end(transaction);
    };
    std::thread first(reader);
    std::thread second(reader);
    wait_for(ready, 2U);
    release.store(true, std::memory_order_release);
    first.join();
    second.join();
}

void disjoint_writers(gem_memory *memory, std::uint64_t first_address,
                      std::uint64_t second_address) {
    std::atomic<unsigned> ready{0U};
    std::array<gem_memory_error, 2> results{GEM_MEMORY_INVALID_ARGUMENT,
                                            GEM_MEMORY_INVALID_ARGUMENT};
    auto writer = [&](unsigned index, std::uint64_t address) {
        std::array<std::uint8_t, 4096> bytes{};
        gem_memory_transaction *transaction = gem_memory_transaction_begin(memory);
        assert(transaction != nullptr);
        snapshot(transaction, address, bytes);
        bytes.fill(static_cast<std::uint8_t>(0x40U + index));
        ready.fetch_add(1U, std::memory_order_release);
        wait_for(ready, 2U);
        gem_memory_page_write write{address, bytes.data()};
        std::uint64_t fault = 0U;
        results[index] =
            gem_memory_transaction_commit_pages(transaction, &write, 1U, &fault, nullptr);
        gem_memory_transaction_end(transaction);
    };
    std::thread first(writer, 0U, first_address);
    std::thread second(writer, 1U, second_address);
    first.join();
    second.join();
    assert(results[0] == GEM_MEMORY_OK);
    assert(results[1] == GEM_MEMORY_OK);
}

void overlapping_writers(gem_memory *memory, std::uint64_t address) {
    std::atomic<unsigned> ready{0U};
    std::array<gem_memory_error, 2> results{GEM_MEMORY_INVALID_ARGUMENT,
                                            GEM_MEMORY_INVALID_ARGUMENT};
    auto writer = [&](unsigned index) {
        std::array<std::uint8_t, 4096> bytes{};
        gem_memory_transaction *transaction = gem_memory_transaction_begin(memory);
        assert(transaction != nullptr);
        snapshot(transaction, address, bytes);
        bytes.fill(static_cast<std::uint8_t>(0x80U + index));
        ready.fetch_add(1U, std::memory_order_release);
        wait_for(ready, 2U);
        gem_memory_page_write write{address, bytes.data()};
        std::uint64_t fault = 0U;
        results[index] =
            gem_memory_transaction_commit_pages(transaction, &write, 1U, &fault, nullptr);
        gem_memory_transaction_end(transaction);
    };
    std::thread first(writer, 0U);
    std::thread second(writer, 1U);
    first.join();
    second.join();
    assert((results[0] == GEM_MEMORY_OK && results[1] == GEM_MEMORY_CONFLICT) ||
           (results[1] == GEM_MEMORY_OK && results[0] == GEM_MEMORY_CONFLICT));
}

void alias_writers(gem_memory *memory, std::uint64_t source, std::uint64_t alias) {
    std::atomic<unsigned> ready{0U};
    std::array<gem_memory_error, 2> results{GEM_MEMORY_INVALID_ARGUMENT,
                                            GEM_MEMORY_INVALID_ARGUMENT};
    const std::array<std::uint64_t, 2> addresses{source, alias};
    auto writer = [&](unsigned index) {
        std::array<std::uint8_t, 4096> bytes{};
        gem_memory_transaction *transaction = gem_memory_transaction_begin(memory);
        assert(transaction != nullptr);
        snapshot(transaction, addresses[index], bytes);
        bytes.fill(static_cast<std::uint8_t>(0xa0U + index));
        ready.fetch_add(1U, std::memory_order_release);
        wait_for(ready, 2U);
        gem_memory_page_write write{addresses[index], bytes.data()};
        std::uint64_t fault = 0U;
        results[index] =
            gem_memory_transaction_commit_pages(transaction, &write, 1U, &fault, nullptr);
        gem_memory_transaction_end(transaction);
    };
    std::thread first(writer, 0U);
    std::thread second(writer, 1U);
    first.join();
    second.join();
    assert((results[0] == GEM_MEMORY_OK && results[1] == GEM_MEMORY_CONFLICT) ||
           (results[1] == GEM_MEMORY_OK && results[0] == GEM_MEMORY_CONFLICT));
}

void topology_conflict(gem_memory *memory, std::uint64_t address) {
    std::array<std::uint8_t, 4096> bytes{};
    gem_memory_transaction *transaction = gem_memory_transaction_begin(memory);
    assert(transaction != nullptr);
    snapshot(transaction, address, bytes);
    assert(gem_memory_protect(memory, address, kPage, GEM_PAGE_READONLY, nullptr) == GEM_MEMORY_OK);
    gem_memory_page_write write{address, bytes.data()};
    std::uint64_t fault = 0U;
    assert(gem_memory_transaction_commit_pages(transaction, &write, 1U, &fault, nullptr) ==
           GEM_MEMORY_CONFLICT);
    assert(fault == address);
    gem_memory_transaction_end(transaction);
}
} // namespace

int main() {
    gem_memory *memory = gem_memory_create();
    assert(memory != nullptr);
    std::uint64_t address = UINT64_C(0x24000000);
    assert(gem_memory_reserve(memory, &address, kPage * 2U) == GEM_MEMORY_OK);
    assert(gem_memory_commit(memory, address, kPage * 2U, GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
    concurrent_readers(memory, address);
    disjoint_writers(memory, address, address + kPage);
    overlapping_writers(memory, address);
    constexpr std::uint64_t alias = UINT64_C(0x25000000);
    assert(gem_memory_alias(memory, alias, address, kPage, GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
    alias_writers(memory, address, alias);
    assert(gem_memory_unmap(memory, alias, kPage) == GEM_MEMORY_OK);
    topology_conflict(memory, address + kPage);
    gem_memory_destroy(memory);
    return 0;
}
