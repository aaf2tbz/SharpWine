// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/memory.h"
#include "memory_internal.h"
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif
#define GEM_MEMORY_MAX_PAGES UINT64_C(1048576)
struct backing {
    uint8_t *data;
    size_t refs;
    bool external;
};
struct page {
    uint64_t address, reservation_base, reservation_size;
    struct backing *backing;
    uint32_t protection;
    struct page *next;
};

/*
 * Per-`gem_memory` exclusive lock.  Every public operation that observes or
 * mutates page-table state holds this lock for its complete validation and
 * commit so each operation is linearizable with respect to other concurrent
 * callers of the same `gem_memory`.  The lock is deliberately non-recursive:
 * compound operations (identity mapping and its rollback) call internal
 * `*_locked` helpers while the lock is already held and never re-enter a public
 * locking wrapper.  Lock acquisition or release failure is fatal (fail-stop)
 * so the implementation never silently runs unsynchronized.
 */
#if defined(_WIN32)
typedef SRWLOCK gem_lock;
static bool gem_lock_init(gem_lock *l) {
    InitializeSRWLock(l);
    return true;
}
static void gem_lock_destroy(gem_lock *l) {
    (void)l;
}
static void gem_lock_acquire(gem_lock *l) {
    AcquireSRWLockExclusive(l);
}
static void gem_lock_release(gem_lock *l) {
    ReleaseSRWLockExclusive(l);
}
#else
typedef pthread_mutex_t gem_lock;
static bool gem_lock_init(gem_lock *l) {
    return pthread_mutex_init(l, NULL) == 0;
}
static void gem_lock_destroy(gem_lock *l) {
    (void)pthread_mutex_destroy(l);
}
static void gem_lock_acquire(gem_lock *l) {
    if (pthread_mutex_lock(l) != 0)
        abort();
}
static void gem_lock_release(gem_lock *l) {
    if (pthread_mutex_unlock(l) != 0)
        abort();
}
#endif

struct gem_memory {
    struct page *pages;
    gem_lock lock;
};
struct gem_memory_transaction {
    struct gem_memory *memory;
};
static bool range_ok(uint64_t a, uint64_t n) {
    return n && !(a & 4095U) && !(n & 4095U) && a <= UINT64_MAX - n;
}
static bool prot_ok(uint32_t p) {
    const uint32_t b = p & ~(uint32_t)GEM_PAGE_GUARD;
    if ((p & ~((uint32_t)GEM_PAGE_GUARD | UINT32_C(0xff))) != 0U)
        return false;
    if ((p & GEM_PAGE_GUARD) != 0U && b == GEM_PAGE_NOACCESS)
        return false;
    switch (b) {
    case GEM_PAGE_NOACCESS:
    case GEM_PAGE_READONLY:
    case GEM_PAGE_READWRITE:
    case GEM_PAGE_WRITECOPY:
    case GEM_PAGE_EXECUTE:
    case GEM_PAGE_EXECUTE_READ:
    case GEM_PAGE_EXECUTE_READWRITE:
    case GEM_PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}
static struct page *at(struct gem_memory *m, uint64_t a) {
    struct page *p;
    for (p = m->pages; p; p = p->next)
        if (p->address == a)
            return p;
    return NULL;
}
static void drop(struct backing *b) {
    if (b && --b->refs == 0) {
        if (!b->external)
            free(b->data);
        free(b);
    }
}
static struct backing *new_backing(uint8_t *data, bool external) {
    struct backing *b = malloc(sizeof(*b));
    if (!b)
        return NULL;
    if (!external && !(data = calloc(1, 4096))) {
        free(b);
        return NULL;
    }
    b->data = data;
    b->refs = 1;
    b->external = external;
    return b;
}
static enum gem_memory_error check(struct gem_memory *m, uint64_t a, uint64_t n, bool committed) {
    uint64_t o;
    if (!m || !range_ok(a, n))
        return GEM_MEMORY_INVALID_ARGUMENT;
    for (o = 0; o < n; o += 4096) {
        struct page *p = at(m, a + o);
        if (!p)
            return GEM_MEMORY_NOT_RESERVED;
        if (committed && !p->backing)
            return GEM_MEMORY_NOT_COMMITTED;
    }
    return GEM_MEMORY_OK;
}
static void remove_pages(struct gem_memory *m, uint64_t a, uint64_t n) {
    struct page **l = &m->pages;
    while (*l) {
        struct page *p = *l;
        if (p->address >= a && p->address < a + n) {
            *l = p->next;
            drop(p->backing);
            free(p);
        } else
            l = &p->next;
    }
}
static enum gem_memory_error reserve_locked(struct gem_memory *m, uint64_t *a, uint64_t n) {
    uint64_t b, o;
    struct page *head = NULL;
    if (!m || !a || !n || n / 4096 > GEM_MEMORY_MAX_PAGES || n & 4095U)
        return GEM_MEMORY_INVALID_ARGUMENT;
    b = *a;
    if (!b) {
        b = UINT64_C(0x100000000);
        while (at(m, b) && b <= UINT64_MAX - n - 4096)
            b += 4096;
    }
    if (!range_ok(b, n))
        return GEM_MEMORY_OVERFLOW;
    for (o = 0; o < n; o += 4096)
        if (at(m, b + o))
            return GEM_MEMORY_CONFLICT;
    for (o = 0; o < n; o += 4096) {
        struct page *p = calloc(1, sizeof(*p));
        if (!p) {
            while (head) {
                p = head->next;
                free(head);
                head = p;
            }
            return GEM_MEMORY_NO_MEMORY;
        }
        p->address = b + o;
        p->reservation_base = b;
        p->reservation_size = n;
        p->next = head;
        head = p;
    }
    while (head) {
        struct page *p = head->next;
        head->next = m->pages;
        m->pages = head;
        head = p;
    }
    *a = b;
    return GEM_MEMORY_OK;
}
static enum gem_memory_error commit_locked(struct gem_memory *m, uint64_t a, uint64_t n,
                                           uint32_t prot) {
    uint64_t o;
    struct backing **bs;
    enum gem_memory_error e = check(m, a, n, false);
    if (e)
        return e;
    if (!prot_ok(prot))
        return GEM_MEMORY_INVALID_ARGUMENT;
    bs = calloc((size_t)(n / 4096), sizeof(*bs));
    if (!bs)
        return GEM_MEMORY_NO_MEMORY;
    for (o = 0; o < n; o += 4096)
        if (!at(m, a + o)->backing && !(bs[o / 4096] = new_backing(NULL, false)))
            goto nomem;
    for (o = 0; o < n; o += 4096) {
        struct page *p = at(m, a + o);
        if (!p->backing)
            p->backing = bs[o / 4096];
        p->protection = prot;
    }
    free(bs);
    return GEM_MEMORY_OK;
nomem:
    for (o = 0; o < n; o += 4096)
        drop(bs[o / 4096]);
    free(bs);
    return GEM_MEMORY_NO_MEMORY;
}
static enum gem_memory_error decommit_locked(struct gem_memory *m, uint64_t a, uint64_t n) {
    uint64_t o;
    enum gem_memory_error e = check(m, a, n, false);
    if (e)
        return e;
    for (o = 0; o < n; o += 4096) {
        struct page *p = at(m, a + o);
        drop(p->backing);
        p->backing = NULL;
        p->protection = GEM_PAGE_NOACCESS;
    }
    return GEM_MEMORY_OK;
}
static enum gem_memory_error release_locked(struct gem_memory *m, uint64_t a, uint64_t n) {
    struct page *p;
    enum gem_memory_error e = check(m, a, n, false);
    if (e)
        return e;
    p = at(m, a);
    if (a != p->reservation_base || n != p->reservation_size)
        return GEM_MEMORY_INVALID_ARGUMENT;
    remove_pages(m, a, n);
    return GEM_MEMORY_OK;
}
static enum gem_memory_error unmap_locked(struct gem_memory *m, uint64_t a, uint64_t n) {
    struct page *first;
    uint64_t base, end, reservation_end, o;
    enum gem_memory_error e = check(m, a, n, false);
    if (e)
        return e;
    first = at(m, a);
    base = first->reservation_base;
    reservation_end = base + first->reservation_size;
    end = a + n;
    if (a < base || end > reservation_end)
        return GEM_MEMORY_INVALID_ARGUMENT;
    for (o = 0; o < n; o += 4096U) {
        struct page *p = at(m, a + o);
        if (p->reservation_base != base || p->reservation_size != first->reservation_size)
            return GEM_MEMORY_INVALID_ARGUMENT;
    }
    for (o = base; o < a; o += 4096U) {
        struct page *p = at(m, o);
        p->reservation_base = base;
        p->reservation_size = a - base;
    }
    for (o = end; o < reservation_end; o += 4096U) {
        struct page *p = at(m, o);
        p->reservation_base = end;
        p->reservation_size = reservation_end - end;
    }
    remove_pages(m, a, n);
    return GEM_MEMORY_OK;
}
static enum gem_memory_error protect_locked(struct gem_memory *m, uint64_t a, uint64_t n,
                                            uint32_t prot, uint32_t *old) {
    uint64_t o;
    enum gem_memory_error e = check(m, a, n, true);
    if (e)
        return e;
    if (!prot_ok(prot))
        return GEM_MEMORY_INVALID_ARGUMENT;
    if (old)
        *old = at(m, a)->protection;
    for (o = 0; o < n; o += 4096)
        at(m, a + o)->protection = prot;
    return GEM_MEMORY_OK;
}
static enum gem_memory_error alias_locked(struct gem_memory *m, uint64_t a, uint64_t s, uint64_t n,
                                          uint32_t prot) {
    uint64_t o;
    struct page *head = NULL;
    enum gem_memory_error e;
    if (!range_ok(a, n) || !prot_ok(prot))
        return GEM_MEMORY_INVALID_ARGUMENT;
    if ((e = check(m, s, n, true)))
        return e;
    for (o = 0; o < n; o += 4096)
        if (at(m, a + o))
            return GEM_MEMORY_CONFLICT;
    for (o = 0; o < n; o += 4096) {
        struct page *p = calloc(1, sizeof(*p));
        if (!p) {
            while (head) {
                p = head->next;
                drop(head->backing);
                free(head);
                head = p;
            }
            return GEM_MEMORY_NO_MEMORY;
        }
        p->address = a + o;
        p->reservation_base = a;
        p->reservation_size = n;
        p->backing = at(m, s + o)->backing;
        ++p->backing->refs;
        p->protection = prot;
        p->next = head;
        head = p;
    }
    while (head) {
        struct page *p = head->next;
        head->next = m->pages;
        m->pages = head;
        head = p;
    }
    return GEM_MEMORY_OK;
}
static enum gem_memory_error map_identity_locked(struct gem_memory *m, uint64_t a, void *h,
                                                 uint64_t n, uint32_t prot) {
    uint64_t o;
    enum gem_memory_error e;
    if (!h || a < UINT64_C(0x100000000) || a != (uint64_t)(uintptr_t)h || !range_ok(a, n) ||
        !prot_ok(prot))
        return GEM_MEMORY_INVALID_ARGUMENT;
    if ((e = reserve_locked(m, &a, n)))
        return e;
    for (o = 0; o < n; o += 4096) {
        struct page *p = at(m, a + o);
        p->backing = new_backing((uint8_t *)h + o, true);
        if (!p->backing) {
            (void)release_locked(m, a, n);
            return GEM_MEMORY_NO_MEMORY;
        }
        p->protection = prot;
    }
    return GEM_MEMORY_OK;
}
static enum gem_memory_error commit_identity_locked(struct gem_memory *m, uint64_t a, void *h,
                                                    uint64_t n, uint32_t prot) {
    uint64_t o;
    struct backing **backings;
    enum gem_memory_error e;
    if (!h || a < UINT64_C(0x100000000) || a != (uint64_t)(uintptr_t)h || !range_ok(a, n) ||
        !prot_ok(prot))
        return GEM_MEMORY_INVALID_ARGUMENT;
    if ((e = check(m, a, n, false)))
        return e;
    backings = calloc((size_t)(n / 4096U), sizeof(*backings));
    if (!backings)
        return GEM_MEMORY_NO_MEMORY;
    for (o = 0; o < n; o += 4096U) {
        struct page *p = at(m, a + o);
        if (p->backing) {
            if (!p->backing->external || p->backing->data != (uint8_t *)h + o) {
                e = GEM_MEMORY_CONFLICT;
                goto rollback;
            }
        } else if (!(backings[o / 4096U] = new_backing((uint8_t *)h + o, true))) {
            e = GEM_MEMORY_NO_MEMORY;
            goto rollback;
        }
    }
    for (o = 0; o < n; o += 4096U) {
        struct page *p = at(m, a + o);
        if (!p->backing)
            p->backing = backings[o / 4096U];
        p->protection = prot;
    }
    free(backings);
    return GEM_MEMORY_OK;
rollback:
    for (o = 0; o < n; o += 4096U)
        drop(backings[o / 4096U]);
    free(backings);
    return e;
}
static enum gem_memory_error bind_kuser_locked(struct gem_memory *m, void *host_page) {
    struct page *canonical, *alias;
    struct backing *external, *old;

    if (!m || !host_page || ((uintptr_t)host_page & (GEM_GUEST_PAGE_SIZE - 1U)) != 0U)
        return GEM_MEMORY_INVALID_ARGUMENT;
    canonical = at(m, GEM_KUSER_CANONICAL_ADDRESS);
    alias = at(m, GEM_KUSER_SHARED_DATA_ADDRESS);
    if (!canonical || !alias || !canonical->backing || canonical->backing != alias->backing)
        return GEM_MEMORY_CONFLICT;
    external = new_backing((uint8_t *)host_page, true);
    if (!external)
        return GEM_MEMORY_NO_MEMORY;

    old = canonical->backing;
    external->refs = 2U;
    canonical->backing = external;
    alias->backing = external;
    drop(old);
    drop(old);
    return GEM_MEMORY_OK;
}
static bool allowed(uint32_t p, bool w, bool x) {
    uint32_t b = p & ~(uint32_t)GEM_PAGE_GUARD;
    if (x)
        return b == 16 || b == 32 || b == 64 || b == 128;
    if (w)
        return b == 4 || b == 8 || b == 64 || b == 128;
    return b != 1 && b != 16;
}
static enum gem_memory_error access_memory_locked(struct gem_memory *m, uint64_t a, void *b,
                                                  size_t n, bool w, bool x, bool query,
                                                  bool consume_guard) {
    size_t done = 0, i, pages;
    struct page **ps;
    struct backing **copies = NULL;
    if (!m || (n && !b && !x) || a > UINT64_MAX - n)
        return GEM_MEMORY_INVALID_ARGUMENT;
    if (!n)
        return GEM_MEMORY_OK;
    {
        const size_t first_offset = (size_t)(a & UINT64_C(4095));
        if (n > SIZE_MAX - first_offset - 4095U)
            return GEM_MEMORY_OVERFLOW;
        pages = (n + first_offset + 4095U) / 4096U;
    }
    ps = calloc(pages, sizeof(*ps));
    if (!ps)
        return GEM_MEMORY_NO_MEMORY;
    for (i = 0; i < pages; i++) {
        uint64_t q = (a + done) & ~UINT64_C(4095);
        size_t z = 4096 - ((a + done) & 4095U);
        if (z > n - done)
            z = n - done;
        ps[i] = at(m, q);
        if (!ps[i]) {
            free(ps);
            return GEM_MEMORY_NOT_RESERVED;
        }
        if (!ps[i]->backing) {
            free(ps);
            return GEM_MEMORY_NOT_COMMITTED;
        }
        if (!allowed(ps[i]->protection, w, x)) {
            free(ps);
            return GEM_MEMORY_ACCESS_DENIED;
        }
        done += z;
    }
    if (!query)
        for (i = 0; i < pages; i++)
            if (ps[i]->protection & GEM_PAGE_GUARD) {
                /* This is a real access: consume only its guard after all pages validated. */
                if (consume_guard)
                    ps[i]->protection &= ~(uint32_t)GEM_PAGE_GUARD;
                free(ps);
                return GEM_MEMORY_GUARD_PAGE;
            }
    if (w) {
        copies = calloc(pages, sizeof(*copies));
        if (!copies) {
            free(ps);
            return GEM_MEMORY_NO_MEMORY;
        }
        for (i = 0; i < pages; i++)
            if (((ps[i]->protection & ~(uint32_t)GEM_PAGE_GUARD) == GEM_PAGE_WRITECOPY ||
                 (ps[i]->protection & ~(uint32_t)GEM_PAGE_GUARD) == GEM_PAGE_EXECUTE_WRITECOPY) &&
                !ps[i]->backing->external) {
                if (!(copies[i] = new_backing(NULL, false))) {
                    while (i)
                        drop(copies[--i]);
                    free(copies);
                    free(ps);
                    return GEM_MEMORY_NO_MEMORY;
                }
                memcpy(copies[i]->data, ps[i]->backing->data, 4096);
            }
    }
    if (!query) {
        for (i = 0; i < pages; i++)
            ps[i]->protection &= ~(uint32_t)GEM_PAGE_GUARD;
        for (i = 0; i < pages; i++)
            if (copies && copies[i]) {
                drop(ps[i]->backing);
                ps[i]->backing = copies[i];
                ps[i]->protection =
                    (ps[i]->protection & ~(uint32_t)GEM_PAGE_GUARD) == GEM_PAGE_WRITECOPY
                        ? GEM_PAGE_READWRITE
                        : GEM_PAGE_EXECUTE_READWRITE;
            } else if (ps[i]->backing->external &&
                       ((ps[i]->protection & ~(uint32_t)GEM_PAGE_GUARD) == GEM_PAGE_WRITECOPY ||
                        (ps[i]->protection & ~(uint32_t)GEM_PAGE_GUARD) ==
                            GEM_PAGE_EXECUTE_WRITECOPY))
                ps[i]->protection =
                    (ps[i]->protection & ~(uint32_t)GEM_PAGE_GUARD) == GEM_PAGE_WRITECOPY
                        ? GEM_PAGE_READWRITE
                        : GEM_PAGE_EXECUTE_READWRITE;
    }
    done = 0;
    for (i = 0; i < pages; i++) {
        size_t z = 4096 - ((a + done) & 4095U);
        if (z > n - done)
            z = n - done;
        if (!query) {
            if (w)
                memcpy(ps[i]->backing->data + ((a + done) & 4095U), (uint8_t *)b + done, z);
            else if (b)
                memcpy((uint8_t *)b + done, ps[i]->backing->data + ((a + done) & 4095U), z);
        }
        done += z;
    }
    free(copies);
    free(ps);
    return GEM_MEMORY_OK;
}
static enum gem_memory_error peek_locked(struct gem_memory *m, uint64_t a, void *b, size_t n) {
    size_t done = 0;
    if (!m || (n && !b) || a > UINT64_MAX - n)
        return GEM_MEMORY_INVALID_ARGUMENT;
    if (!n)
        return GEM_MEMORY_OK;
    /* Validate the entire range before copying, so a later-page failure leaves
     * the caller output buffer unchanged. */
    while (done < n) {
        const uint64_t q = (a + done) & ~UINT64_C(4095);
        size_t z = 4096 - ((a + done) & 4095U);
        struct page *p;
        if (z > n - done)
            z = n - done;
        p = at(m, q);
        if (!p)
            return GEM_MEMORY_NOT_RESERVED;
        if (!p->backing)
            return GEM_MEMORY_NOT_COMMITTED;
        done += z;
    }
    done = 0;
    while (done < n) {
        const uint64_t q = (a + done) & ~UINT64_C(4095);
        size_t z = 4096 - ((a + done) & 4095U);
        if (z > n - done)
            z = n - done;
        memcpy((uint8_t *)b + done, at(m, q)->backing->data + ((a + done) & 4095U), z);
        done += z;
    }
    return GEM_MEMORY_OK;
}
struct gem_memory_transaction *gem_memory_transaction_begin(struct gem_memory *memory) {
    struct gem_memory_transaction *transaction;
    if (memory == NULL)
        return NULL;
    transaction = malloc(sizeof(*transaction));
    if (transaction == NULL)
        return NULL;
    gem_lock_acquire(&memory->lock);
    transaction->memory = memory;
    return transaction;
}

void gem_memory_transaction_end(struct gem_memory_transaction *transaction) {
    if (transaction != NULL) {
        gem_lock_release(&transaction->memory->lock);
        free(transaction);
    }
}

enum gem_memory_error
gem_memory_transaction_snapshot_page(struct gem_memory_transaction *transaction, uint64_t address,
                                     uint8_t data[4096], uint32_t *protection) {
    struct page *page;
    enum gem_memory_error error;
    if (transaction == NULL || data == NULL || protection == NULL ||
        (address & UINT64_C(4095)) != 0U)
        return GEM_MEMORY_INVALID_ARGUMENT;
    error = peek_locked(transaction->memory, address, data, 4096U);
    if (error != GEM_MEMORY_OK)
        return error;
    page = at(transaction->memory, address);
    *protection = page->protection;
    return GEM_MEMORY_OK;
}

enum gem_memory_error gem_memory_transaction_validate(struct gem_memory_transaction *transaction,
                                                      uint64_t address, size_t size, bool write,
                                                      bool execute) {
    enum gem_memory_error error;
    uint8_t *temporary;
    if (transaction == NULL || (write && execute))
        return GEM_MEMORY_INVALID_ARGUMENT;
    if (size == 0U)
        return GEM_MEMORY_OK;
    temporary = malloc(size);
    if (temporary == NULL)
        return GEM_MEMORY_NO_MEMORY;
    error = access_memory_locked(transaction->memory, address, temporary, size, write, execute,
                                 write, true);
    free(temporary);
    if (error == GEM_MEMORY_OK && write) {
        size_t done = 0U;
        while (done < size) {
            const uint64_t page_address = (address + done) & ~UINT64_C(4095);
            struct page *page = at(transaction->memory, page_address);
            size_t chunk = 4096U - (size_t)((address + done) & UINT64_C(4095));
            if ((page->protection & GEM_PAGE_GUARD) != 0U) {
                page->protection &= ~(uint32_t)GEM_PAGE_GUARD;
                return GEM_MEMORY_GUARD_PAGE;
            }
            if (chunk > size - done)
                chunk = size - done;
            done += chunk;
        }
    }
    return error;
}

enum gem_memory_error
gem_memory_transaction_commit_pages(struct gem_memory_transaction *transaction,
                                    const struct gem_memory_page_write *writes, size_t count,
                                    uint64_t *fault_address) {
    enum gem_memory_error error = GEM_MEMORY_OK;
    struct backing **copies;
    size_t i, j;
    if (transaction == NULL || (count != 0U && writes == NULL) || count > 64U)
        return GEM_MEMORY_INVALID_ARGUMENT;
    copies = count != 0U ? calloc(count, sizeof(*copies)) : NULL;
    if (count != 0U && copies == NULL)
        return GEM_MEMORY_NO_MEMORY;
    for (i = 0; i < count; ++i) {
        struct page *page;
        if (writes[i].data == NULL || (writes[i].address & UINT64_C(4095)) != 0U) {
            if (fault_address != NULL)
                *fault_address = writes[i].address;
            error = GEM_MEMORY_INVALID_ARGUMENT;
            goto Rollback;
        }
        for (j = 0; j < i; ++j)
            if (writes[j].address == writes[i].address) {
                error = GEM_MEMORY_INVALID_ARGUMENT;
                goto Rollback;
            }
        page = at(transaction->memory, writes[i].address);
        if (page == NULL || page->backing == NULL || !allowed(page->protection, true, false)) {
            if (fault_address != NULL)
                *fault_address = writes[i].address;
            error = page == NULL            ? GEM_MEMORY_NOT_RESERVED
                    : page->backing == NULL ? GEM_MEMORY_NOT_COMMITTED
                                            : GEM_MEMORY_ACCESS_DENIED;
            goto Rollback;
        }
    }
    for (i = 0; i < count; ++i) {
        struct page *page = at(transaction->memory, writes[i].address);
        if ((page->protection & GEM_PAGE_GUARD) != 0U) {
            page->protection &= ~(uint32_t)GEM_PAGE_GUARD;
            if (fault_address != NULL)
                *fault_address = writes[i].address;
            error = GEM_MEMORY_GUARD_PAGE;
            goto Rollback;
        }
        if ((page->protection & ~(uint32_t)GEM_PAGE_GUARD) == GEM_PAGE_WRITECOPY ||
            (page->protection & ~(uint32_t)GEM_PAGE_GUARD) == GEM_PAGE_EXECUTE_WRITECOPY) {
            copies[i] = new_backing(NULL, false);
            if (copies[i] == NULL) {
                error = GEM_MEMORY_NO_MEMORY;
                goto Rollback;
            }
            memcpy(copies[i]->data, page->backing->data, 4096U);
        }
    }
    for (i = 0; i < count; ++i) {
        struct page *page = at(transaction->memory, writes[i].address);
        if (copies[i] != NULL) {
            drop(page->backing);
            page->backing = copies[i];
            copies[i] = NULL;
            page->protection = (page->protection & ~(uint32_t)GEM_PAGE_GUARD) == GEM_PAGE_WRITECOPY
                                   ? GEM_PAGE_READWRITE
                                   : GEM_PAGE_EXECUTE_READWRITE;
        }
        memcpy(page->backing->data, writes[i].data, 4096U);
    }

Rollback:
    for (i = 0; i < count; ++i)
        if (copies[i] != NULL)
            drop(copies[i]);
    free(copies);
    return error;
}

struct gem_memory *gem_memory_create(void) {
    struct gem_memory *memory = calloc(1, sizeof(*memory));
    uint64_t canonical = GEM_KUSER_CANONICAL_ADDRESS;
    bool ok;
    if (memory == NULL)
        return NULL;
    if (!gem_lock_init(&memory->lock)) {
        free(memory);
        return NULL;
    }
    gem_lock_acquire(&memory->lock);
    ok = (reserve_locked(memory, &canonical, GEM_GUEST_PAGE_SIZE) == GEM_MEMORY_OK &&
          commit_locked(memory, canonical, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) ==
              GEM_MEMORY_OK &&
          alias_locked(memory, GEM_KUSER_SHARED_DATA_ADDRESS, canonical, GEM_GUEST_PAGE_SIZE,
                       GEM_PAGE_READWRITE) == GEM_MEMORY_OK);
    if (!ok)
        remove_pages(memory, 0, UINT64_MAX);
    gem_lock_release(&memory->lock);
    if (!ok) {
        gem_lock_destroy(&memory->lock);
        free(memory);
        return NULL;
    }
    return memory;
}
void gem_memory_destroy(struct gem_memory *m) {
    if (m) {
        gem_lock_acquire(&m->lock);
        remove_pages(m, 0, UINT64_MAX);
        gem_lock_release(&m->lock);
        gem_lock_destroy(&m->lock);
        free(m);
    }
}
enum gem_memory_error gem_memory_reserve(struct gem_memory *m, uint64_t *a, uint64_t n) {
    enum gem_memory_error e;
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    e = reserve_locked(m, a, n);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_commit(struct gem_memory *m, uint64_t a, uint64_t n,
                                        uint32_t prot) {
    enum gem_memory_error e;
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    e = commit_locked(m, a, n, prot);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_commit_identity(struct gem_memory *m, uint64_t a, void *h,
                                                 uint64_t n, uint32_t prot) {
    enum gem_memory_error e;
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    e = commit_identity_locked(m, a, h, n, prot);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_decommit(struct gem_memory *m, uint64_t a, uint64_t n) {
    enum gem_memory_error e;
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    e = decommit_locked(m, a, n);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_release(struct gem_memory *m, uint64_t a, uint64_t n) {
    enum gem_memory_error e;
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    e = release_locked(m, a, n);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_unmap(struct gem_memory *m, uint64_t a, uint64_t n) {
    enum gem_memory_error e;
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    e = unmap_locked(m, a, n);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_protect(struct gem_memory *m, uint64_t a, uint64_t n,
                                         uint32_t prot, uint32_t *old) {
    enum gem_memory_error e;
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    e = protect_locked(m, a, n, prot, old);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_alias(struct gem_memory *m, uint64_t a, uint64_t s, uint64_t n,
                                       uint32_t prot) {
    enum gem_memory_error e;
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    e = alias_locked(m, a, s, n, prot);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_map_identity(struct gem_memory *m, uint64_t a, void *h, uint64_t n,
                                              uint32_t prot) {
    enum gem_memory_error e;
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    e = map_identity_locked(m, a, h, n, prot);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_bind_kuser(struct gem_memory *m, void *host_page) {
    enum gem_memory_error e;
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    e = bind_kuser_locked(m, host_page);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_read(struct gem_memory *m, uint64_t a, void *b, size_t n) {
    enum gem_memory_error e;
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    e = access_memory_locked(m, a, b, n, false, false, false, true);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_write(struct gem_memory *m, uint64_t a, const void *b, size_t n) {
    enum gem_memory_error e;
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    e = access_memory_locked(m, a, (void *)b, n, true, false, false, true);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_fetch(struct gem_memory *m, uint64_t a, void *b, size_t n) {
    enum gem_memory_error e;
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    e = access_memory_locked(m, a, b, n, false, true, false, true);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_peek(struct gem_memory *m, uint64_t a, void *b, size_t n) {
    enum gem_memory_error e;
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    e = peek_locked(m, a, b, n);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_read_deferred_guard(struct gem_memory *m, uint64_t a, void *b,
                                                     size_t n) {
    enum gem_memory_error e;
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    e = access_memory_locked(m, a, b, n, false, false, false, false);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_write_deferred_guard(struct gem_memory *m, uint64_t a,
                                                      const void *b, size_t n) {
    enum gem_memory_error e;
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    e = access_memory_locked(m, a, (void *)b, n, true, false, false, false);
    gem_lock_release(&m->lock);
    return e;
}
bool gem_memory_is_executable(struct gem_memory *m, uint64_t a, size_t n) {
    enum gem_memory_error e;
    if (!m)
        return false;
    gem_lock_acquire(&m->lock);
    e = access_memory_locked(m, a, NULL, n, false, true, true, true);
    gem_lock_release(&m->lock);
    return e == GEM_MEMORY_OK;
}
const char *gem_memory_error_name(enum gem_memory_error e) {
    static const char *n[] = {"ok",         "invalid-argument", "overflow",      "no-memory",
                              "conflict",   "not-reserved",     "not-committed", "access-denied",
                              "guard-page", "not-found"};
    return (unsigned)e < 10 ? n[e] : "invalid";
}
