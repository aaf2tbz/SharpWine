// SPDX-License-Identifier: Apache-2.0
#ifndef METALSHARP_GEM_MEMORY_INTERNAL_H
#define METALSHARP_GEM_MEMORY_INTERNAL_H

#include "metalsharp/gem/memory.h"

#ifdef __cplusplus
extern "C" {
#endif

enum gem_memory_error gem_memory_peek(struct gem_memory *memory, uint64_t address, void *buffer,
                                      size_t size);
/* Native translated blocks defer PAGE_GUARD consumption until precise replay
 * has validated the exact faulting instruction and context. */
enum gem_memory_error gem_memory_read_deferred_guard(struct gem_memory *memory, uint64_t address,
                                                     void *buffer, size_t size);
enum gem_memory_error gem_memory_write_deferred_guard(struct gem_memory *memory, uint64_t address,
                                                      const void *buffer, size_t size);

struct gem_memory_transaction;
struct gem_memory_page_write {
    uint64_t address;
    const uint8_t *data;
};
struct gem_memory_transaction *gem_memory_transaction_begin(struct gem_memory *memory);
void gem_memory_transaction_end(struct gem_memory_transaction *transaction);
enum gem_memory_error
gem_memory_transaction_snapshot_page(struct gem_memory_transaction *transaction, uint64_t address,
                                     uint8_t data[4096], uint32_t *protection);
enum gem_memory_error gem_memory_transaction_validate(struct gem_memory_transaction *transaction,
                                                      uint64_t address, size_t size, bool write,
                                                      bool execute);
enum gem_memory_error
gem_memory_transaction_commit_pages(struct gem_memory_transaction *transaction,
                                    const struct gem_memory_page_write *writes, size_t count,
                                    uint64_t *fault_address);

#ifdef __cplusplus
}
#endif

#endif
