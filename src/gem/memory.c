// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/memory.h"
#include "memory_internal.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/mach_vm.h>
#endif
#if defined(_WIN32)
#include <windows.h>
#else
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#endif
#define GEM_MEMORY_MAX_PAGES UINT64_C(1048576)
#define GEM_MEMORY_HASH_BUCKETS UINT64_C(65536)
#define GEM_MEMORY_LOCK_STRIPES 256U
#define GEM_MEMORY_CACHE_LINE 64U
#define GEM_MEMORY_TRANSACTION_PAGES 256U
struct backing {
    uint8_t *data;
    size_t refs;
    uint64_t generation;
    bool external;
};
struct page {
    uint64_t address, reservation_base, reservation_size;
    struct backing *backing;
    uint32_t protection;
    uint64_t generation;
    struct page *next;
    struct page *hash_next;
};

#if defined(__APPLE__)
static bool external_range_accessible(const struct backing *backing, size_t offset, size_t size,
                                      bool write) {
    mach_vm_address_t address = (mach_vm_address_t)(uintptr_t)(backing->data + offset);
    mach_vm_address_t region = address;
    mach_vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t result =
        mach_vm_region(mach_task_self(), &region, &region_size, VM_REGION_BASIC_INFO_64,
                       (vm_region_info_t)&info, &count, &object);
    if (object != MACH_PORT_NULL)
        mach_port_deallocate(mach_task_self(), object);
    return result == KERN_SUCCESS && region <= address && address - region <= region_size &&
           size <= region_size - (address - region) && (info.protection & VM_PROT_READ) != 0 &&
           (!write || (info.protection & VM_PROT_WRITE) != 0);
}
#endif

/*
 * The recursive metadata lock protects mapping topology, reservations, and
 * backing lifetimes. Cache-line-aligned writer-preferring stripes protect page
 * content and serialize topology changes with in-flight content access. Every
 * operation takes metadata before sorted stripes; a transaction may release
 * metadata while retaining pinned backing references and its stripes. POSIX
 * metadata locking remains recursive for Wine's synchronous protection-fault
 * re-entry. Lock failures are fail-stop rather than silently unsynchronized.
 */
#if defined(_WIN32)
typedef SRWLOCK gem_lock;
typedef SRWLOCK gem_stripe_lock;
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
static bool gem_lock_try_acquire(gem_lock *l) {
    return TryAcquireSRWLockExclusive(l) != 0;
}
static void gem_lock_release(gem_lock *l) {
    ReleaseSRWLockExclusive(l);
}
static bool gem_stripe_init(gem_stripe_lock *l) {
    InitializeSRWLock(l);
    return true;
}
static void gem_stripe_destroy(gem_stripe_lock *l) {
    (void)l;
}
static void gem_stripe_read_acquire(gem_stripe_lock *l) {
    AcquireSRWLockShared(l);
}
static bool gem_stripe_read_try_acquire(gem_stripe_lock *l) {
    return TryAcquireSRWLockShared(l) != 0;
}
static void gem_stripe_read_release(gem_stripe_lock *l) {
    ReleaseSRWLockShared(l);
}
static void gem_stripe_write_acquire(gem_stripe_lock *l) {
    AcquireSRWLockExclusive(l);
}
static bool gem_stripe_write_try_acquire(gem_stripe_lock *l) {
    return TryAcquireSRWLockExclusive(l) != 0;
}
static void gem_stripe_write_release(gem_stripe_lock *l) {
    ReleaseSRWLockExclusive(l);
}
#else
typedef pthread_mutex_t gem_lock;
struct gem_stripe_lock {
    pthread_mutex_t mutex;
    pthread_cond_t readers_done;
    unsigned readers;
    unsigned waiting_writers;
    bool writer;
};
typedef struct gem_stripe_lock gem_stripe_lock;
static bool gem_lock_init(gem_lock *l) {
    pthread_mutexattr_t attr;
    bool ok;
    if (pthread_mutexattr_init(&attr) != 0)
        return false;
    ok = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) == 0 &&
         pthread_mutex_init(l, &attr) == 0;
    (void)pthread_mutexattr_destroy(&attr);
    return ok;
}
static void gem_lock_destroy(gem_lock *l) {
    (void)pthread_mutex_destroy(l);
}
static void gem_lock_acquire(gem_lock *l) {
    if (pthread_mutex_lock(l) != 0)
        abort();
}
static bool gem_lock_try_acquire(gem_lock *l) {
    const int error = pthread_mutex_trylock(l);
    if (error == 0)
        return true;
    if (error != EBUSY)
        abort();
    return false;
}
static void gem_lock_release(gem_lock *l) {
    if (pthread_mutex_unlock(l) != 0)
        abort();
}
static bool gem_stripe_init(struct gem_stripe_lock *l) {
    if (pthread_mutex_init(&l->mutex, NULL) != 0)
        return false;
    if (pthread_cond_init(&l->readers_done, NULL) != 0) {
        (void)pthread_mutex_destroy(&l->mutex);
        return false;
    }
    return true;
}
static void gem_stripe_destroy(struct gem_stripe_lock *l) {
    (void)pthread_cond_destroy(&l->readers_done);
    (void)pthread_mutex_destroy(&l->mutex);
}
static void gem_stripe_read_acquire(struct gem_stripe_lock *l) {
    if (pthread_mutex_lock(&l->mutex) != 0)
        abort();
    while (l->writer || l->waiting_writers != 0U)
        if (pthread_cond_wait(&l->readers_done, &l->mutex) != 0)
            abort();
    ++l->readers;
    if (pthread_mutex_unlock(&l->mutex) != 0)
        abort();
}
static bool gem_stripe_read_try_acquire(struct gem_stripe_lock *l) {
    const int error = pthread_mutex_trylock(&l->mutex);
    bool acquired = false;
    if (error == EBUSY)
        return false;
    if (error != 0)
        abort();
    if (!l->writer && l->waiting_writers == 0U) {
        ++l->readers;
        acquired = true;
    }
    if (pthread_mutex_unlock(&l->mutex) != 0)
        abort();
    return acquired;
}
static void gem_stripe_read_release(struct gem_stripe_lock *l) {
    if (pthread_mutex_lock(&l->mutex) != 0)
        abort();
    if (--l->readers == 0U && pthread_cond_broadcast(&l->readers_done) != 0)
        abort();
    if (pthread_mutex_unlock(&l->mutex) != 0)
        abort();
}
static void gem_stripe_write_acquire(struct gem_stripe_lock *l) {
    if (pthread_mutex_lock(&l->mutex) != 0)
        abort();
    ++l->waiting_writers;
    while (l->writer || l->readers != 0U)
        if (pthread_cond_wait(&l->readers_done, &l->mutex) != 0)
            abort();
    --l->waiting_writers;
    l->writer = true;
    if (pthread_mutex_unlock(&l->mutex) != 0)
        abort();
}
static bool gem_stripe_write_try_acquire(struct gem_stripe_lock *l) {
    const int error = pthread_mutex_trylock(&l->mutex);
    bool acquired = false;
    if (error == EBUSY)
        return false;
    if (error != 0)
        abort();
    if (!l->writer && l->readers == 0U && l->waiting_writers == 0U) {
        l->writer = true;
        acquired = true;
    }
    if (pthread_mutex_unlock(&l->mutex) != 0)
        abort();
    return acquired;
}
static void gem_stripe_write_release(struct gem_stripe_lock *l) {
    if (pthread_mutex_lock(&l->mutex) != 0)
        abort();
    l->writer = false;
    if (pthread_cond_broadcast(&l->readers_done) != 0)
        abort();
    if (pthread_mutex_unlock(&l->mutex) != 0)
        abort();
}
#endif

#if defined(_MSC_VER)
#define GEM_CACHE_ALIGNED __declspec(align(64))
#else
#define GEM_CACHE_ALIGNED __attribute__((aligned(64)))
#endif
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4324)
#endif
struct GEM_CACHE_ALIGNED gem_page_stripe {
    gem_stripe_lock lock;
};

struct gem_memory {
    struct page *pages;
    struct page **page_buckets;
    gem_lock lock;
    struct gem_page_stripe stripes[GEM_MEMORY_LOCK_STRIPES];
    uint64_t next_generation;
};
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
struct transaction_page {
    uint64_t address;
    uint64_t generation;
    uint64_t content_generation;
    uint64_t content_hash;
    struct backing *backing;
    uint32_t protection;
    bool external;
};
struct gem_memory_transaction {
    struct gem_memory *memory;
    struct transaction_page pages[GEM_MEMORY_TRANSACTION_PAGES];
    size_t page_count;
    uint64_t lock_wait_nanoseconds;
};
static struct page *at(struct gem_memory *memory, uint64_t address);
static uint64_t monotonic_nanoseconds(void) {
#if defined(_WIN32)
    LARGE_INTEGER counter, frequency;
    QueryPerformanceCounter(&counter);
    QueryPerformanceFrequency(&frequency);
    return (uint64_t)((counter.QuadPart * UINT64_C(1000000000)) / frequency.QuadPart);
#else
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        return 0U;
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
#endif
}
static size_t address_stripe_index(uint64_t address) {
    return (size_t)((address >> 12U) & (GEM_MEMORY_LOCK_STRIPES - 1U));
}
static size_t backing_stripe_index(const struct backing *backing) {
    return (size_t)(((uintptr_t)backing >> 6U) & (GEM_MEMORY_LOCK_STRIPES - 1U));
}
static void transaction_metadata_acquire(struct gem_memory_transaction *transaction) {
    uint64_t started;
    if (gem_lock_try_acquire(&transaction->memory->lock))
        return;
    started = monotonic_nanoseconds();
    gem_lock_acquire(&transaction->memory->lock);
    transaction->lock_wait_nanoseconds += monotonic_nanoseconds() - started;
}
static void transaction_stripe_read_acquire(struct gem_memory_transaction *transaction,
                                            size_t index) {
    uint64_t started;
    if (gem_stripe_read_try_acquire(&transaction->memory->stripes[index].lock))
        return;
    started = monotonic_nanoseconds();
    gem_stripe_read_acquire(&transaction->memory->stripes[index].lock);
    transaction->lock_wait_nanoseconds += monotonic_nanoseconds() - started;
}
static void transaction_stripe_write_acquire(struct gem_memory_transaction *transaction,
                                             size_t index) {
    uint64_t started;
    if (gem_stripe_write_try_acquire(&transaction->memory->stripes[index].lock))
        return;
    started = monotonic_nanoseconds();
    gem_stripe_write_acquire(&transaction->memory->stripes[index].lock);
    transaction->lock_wait_nanoseconds += monotonic_nanoseconds() - started;
}
static size_t insert_stripe(size_t stripes[GEM_MEMORY_LOCK_STRIPES], size_t count, size_t stripe) {
    size_t i = 0U;
    while (i < count && stripes[i] < stripe)
        ++i;
    if (i < count && stripes[i] == stripe)
        return count;
    memmove(stripes + i + 1U, stripes + i, (count - i) * sizeof(*stripes));
    stripes[i] = stripe;
    return count + 1U;
}
static size_t page_stripes(uint64_t address, const struct backing *backing, size_t *stripes,
                           size_t count) {
    count = insert_stripe(stripes, count, address_stripe_index(address));
    if (backing != NULL)
        count = insert_stripe(stripes, count, backing_stripe_index(backing));
    return count;
}
static void transaction_stripes_acquire(struct gem_memory_transaction *transaction,
                                        const size_t stripes[GEM_MEMORY_LOCK_STRIPES], size_t count,
                                        bool write) {
    size_t i;
    for (i = 0U; i < count; ++i) {
        if (write)
            transaction_stripe_write_acquire(transaction, stripes[i]);
        else
            transaction_stripe_read_acquire(transaction, stripes[i]);
    }
}
static void transaction_stripes_release(struct gem_memory_transaction *transaction,
                                        const size_t stripes[GEM_MEMORY_LOCK_STRIPES], size_t count,
                                        bool write) {
    while (count != 0U) {
        --count;
        if (write)
            gem_stripe_write_release(&transaction->memory->stripes[stripes[count]].lock);
        else
            gem_stripe_read_release(&transaction->memory->stripes[stripes[count]].lock);
    }
}
static size_t dependency_stripes(const struct gem_memory_transaction *transaction,
                                 size_t stripes[GEM_MEMORY_LOCK_STRIPES]) {
    size_t count = 0U, i;
    for (i = 0U; i < transaction->page_count; ++i)
        count = page_stripes(transaction->pages[i].address, transaction->pages[i].backing, stripes,
                             count);
    return count;
}
static void range_stripes_acquire(struct gem_memory *memory, uint64_t address, uint64_t size,
                                  bool write, bool locked[GEM_MEMORY_LOCK_STRIPES]) {
    uint64_t page, last;
    size_t i;
    memset(locked, 0, GEM_MEMORY_LOCK_STRIPES * sizeof(*locked));
    if (size == 0U || address > UINT64_MAX - (size - 1U))
        return;
    page = address & ~UINT64_C(4095);
    last = (address + size - 1U) & ~UINT64_C(4095);
    if ((last - page) / GEM_GUEST_PAGE_SIZE + 1U >= GEM_MEMORY_LOCK_STRIPES) {
        memset(locked, 1, GEM_MEMORY_LOCK_STRIPES * sizeof(*locked));
        page = last;
    }
    for (;;) {
        struct page *mapped;
        locked[address_stripe_index(page)] = true;
        mapped = at(memory, page);
        if (mapped != NULL && mapped->backing != NULL)
            locked[backing_stripe_index(mapped->backing)] = true;
        if (page == last)
            break;
        page += GEM_GUEST_PAGE_SIZE;
    }
    for (i = 0U; i < GEM_MEMORY_LOCK_STRIPES; ++i)
        if (locked[i]) {
            if (write)
                gem_stripe_write_acquire(&memory->stripes[i].lock);
            else
                gem_stripe_read_acquire(&memory->stripes[i].lock);
        }
}
static void range_stripes_release(struct gem_memory *memory, bool write,
                                  const bool locked[GEM_MEMORY_LOCK_STRIPES]) {
    size_t i;
    for (i = GEM_MEMORY_LOCK_STRIPES; i != 0U; --i)
        if (locked[i - 1U]) {
            if (write)
                gem_stripe_write_release(&memory->stripes[i - 1U].lock);
            else
                gem_stripe_read_release(&memory->stripes[i - 1U].lock);
        }
}
static uint64_t content_hash(const uint8_t *data) {
    uint64_t hash = UINT64_C(1469598103934665603);
    size_t i;
    for (i = 0; i < GEM_GUEST_PAGE_SIZE; i += sizeof(uint64_t)) {
        uint64_t word;
        memcpy(&word, data + i, sizeof(word));
        hash ^= word;
        hash *= UINT64_C(1099511628211);
        hash ^= hash >> 32U;
    }
    return hash;
}
static void touch_page(struct gem_memory *memory, struct page *page) {
    page->generation = ++memory->next_generation;
    if (memory->next_generation == 0U)
        abort();
}
static void touch_backing(struct gem_memory *memory, struct backing *backing) {
    backing->generation = ++memory->next_generation;
    if (memory->next_generation == 0U)
        abort();
}
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
static size_t page_bucket(uint64_t address) {
    uint64_t key = address >> 12U;
    key ^= key >> 33U;
    key *= UINT64_C(0xff51afd7ed558ccd);
    key ^= key >> 33U;
    key *= UINT64_C(0xc4ceb9fe1a85ec53);
    key ^= key >> 33U;
    return (size_t)(key & (GEM_MEMORY_HASH_BUCKETS - 1U));
}
static struct page *at(struct gem_memory *m, uint64_t a) {
    struct page *p;
    for (p = m->page_buckets[page_bucket(a)]; p; p = p->hash_next)
        if (p->address == a)
            return p;
    return NULL;
}
static void index_page(struct gem_memory *m, struct page *p) {
    const size_t bucket = page_bucket(p->address);
    p->hash_next = m->page_buckets[bucket];
    m->page_buckets[bucket] = p;
}
static void unindex_page(struct gem_memory *m, struct page *p) {
    struct page **link = &m->page_buckets[page_bucket(p->address)];
    while (*link != NULL && *link != p)
        link = &(*link)->hash_next;
    if (*link == NULL)
        abort();
    *link = p->hash_next;
    p->hash_next = NULL;
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
            unindex_page(m, p);
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
        touch_page(m, p);
        p->next = head;
        head = p;
    }
    while (head) {
        struct page *p = head->next;
        head->next = m->pages;
        m->pages = head;
        index_page(m, head);
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
        touch_page(m, p);
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
        touch_page(m, p);
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
    for (o = 0; o < n; o += 4096)
        touch_page(m, at(m, a + o));
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
        touch_page(m, p);
        p->next = head;
        head = p;
    }
    while (head) {
        struct page *p = head->next;
        head->next = m->pages;
        m->pages = head;
        index_page(m, head);
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
        touch_page(m, p);
    }
    return GEM_MEMORY_OK;
}
static enum gem_memory_error commit_external_locked(struct gem_memory *m, uint64_t a, void *h,
                                                    uint64_t n, uint32_t prot,
                                                    bool require_identity) {
    uint64_t o;
    struct backing **backings;
    enum gem_memory_error e;
    if (!h || ((uintptr_t)h & (GEM_GUEST_PAGE_SIZE - 1U)) != 0U ||
        (require_identity && (a < UINT64_C(0x100000000) || a != (uint64_t)(uintptr_t)h)) ||
        !range_ok(a, n) || !prot_ok(prot))
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
        touch_page(m, p);
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
    touch_page(m, canonical);
    touch_page(m, alias);
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
                if (consume_guard)
                    touch_page(m, ps[i]);
                free(ps);
                return GEM_MEMORY_GUARD_PAGE;
            }
    if (w && !query) {
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
                touch_page(m, ps[i]);
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
        if (w && !query) {
            touch_backing(m, ps[i]->backing);
            touch_page(m, ps[i]);
        }
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
#if defined(__APPLE__)
        if (p->backing->external &&
            !external_range_accessible(p->backing, (size_t)((a + done) & UINT64_C(4095)), z, false))
            return GEM_MEMORY_NOT_COMMITTED;
#endif
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
    transaction = calloc(1U, sizeof(*transaction));
    if (transaction == NULL)
        return NULL;
    transaction->memory = memory;
    return transaction;
}

void gem_memory_transaction_end(struct gem_memory_transaction *transaction) {
    if (transaction != NULL) {
        size_t i;
        transaction_metadata_acquire(transaction);
        for (i = 0U; i < transaction->page_count; ++i)
            drop(transaction->pages[i].backing);
        gem_lock_release(&transaction->memory->lock);
        free(transaction);
    }
}

enum gem_memory_error
gem_memory_transaction_snapshot_page(struct gem_memory_transaction *transaction, uint64_t address,
                                     uint8_t data[4096], uint32_t *protection) {
    struct page *page;
    enum gem_memory_error error = GEM_MEMORY_OK;
    size_t stripes[GEM_MEMORY_LOCK_STRIPES];
    size_t stripe_count;
    size_t i;
    if (transaction == NULL || data == NULL || protection == NULL ||
        (address & UINT64_C(4095)) != 0U)
        return GEM_MEMORY_INVALID_ARGUMENT;
    transaction_metadata_acquire(transaction);
    page = at(transaction->memory, address);
    if (page == NULL) {
        error = GEM_MEMORY_NOT_RESERVED;
        goto Done;
    }
    if (page->backing == NULL) {
        error = GEM_MEMORY_NOT_COMMITTED;
        goto Done;
    }
    stripe_count = page_stripes(address, page->backing, stripes, 0U);
    transaction_stripes_acquire(transaction, stripes, stripe_count, false);
#if defined(__APPLE__)
    if (page->backing->external &&
        !external_range_accessible(page->backing, 0U, GEM_GUEST_PAGE_SIZE, false)) {
        error = GEM_MEMORY_NOT_COMMITTED;
        transaction_stripes_release(transaction, stripes, stripe_count, false);
        goto Done;
    }
#endif
    memcpy(data, page->backing->data, GEM_GUEST_PAGE_SIZE);
    *protection = page->protection;
    for (i = 0U; i < transaction->page_count; ++i)
        if (transaction->pages[i].address == address)
            break;
    if (i == transaction->page_count) {
        struct transaction_page *dependency;
        if (i == GEM_MEMORY_TRANSACTION_PAGES) {
            error = GEM_MEMORY_NO_MEMORY;
        } else {
            dependency = &transaction->pages[transaction->page_count++];
            dependency->address = address;
            dependency->generation = page->generation;
            dependency->content_generation = page->backing->generation;
            dependency->content_hash = page->backing->external ? content_hash(data) : 0U;
            dependency->backing = page->backing;
            dependency->protection = page->protection;
            dependency->external = page->backing->external;
            ++dependency->backing->refs;
        }
    } else if (transaction->pages[i].backing != page->backing ||
               transaction->pages[i].generation != page->generation ||
               transaction->pages[i].content_generation != page->backing->generation ||
               transaction->pages[i].protection != page->protection ||
               (transaction->pages[i].external &&
                transaction->pages[i].content_hash != content_hash(data))) {
        error = GEM_MEMORY_CONFLICT;
    }
    transaction_stripes_release(transaction, stripes, stripe_count, false);
Done:
    gem_lock_release(&transaction->memory->lock);
    return error;
}

enum gem_memory_error gem_memory_transaction_validate(struct gem_memory_transaction *transaction,
                                                      uint64_t address, size_t size, bool write,
                                                      bool execute) {
    enum gem_memory_error error = GEM_MEMORY_OK;
    size_t done = 0U;
    if (transaction == NULL || (write && execute))
        return GEM_MEMORY_INVALID_ARGUMENT;
    if (size == 0U)
        return GEM_MEMORY_OK;
    if (address > UINT64_MAX - size)
        return GEM_MEMORY_OVERFLOW;
    while (done < size) {
        const uint64_t current = address + done;
        const uint64_t page_address = current & ~UINT64_C(4095);
        struct transaction_page *dependency = NULL;
        size_t i;
        size_t chunk = 4096U - (size_t)(current & UINT64_C(4095));
        for (i = 0U; i < transaction->page_count; ++i)
            if (transaction->pages[i].address == page_address) {
                dependency = &transaction->pages[i];
                break;
            }
        if (dependency == NULL) {
            struct page *page;
            size_t stripes[GEM_MEMORY_LOCK_STRIPES];
            size_t stripe_count;
            if (transaction->page_count == GEM_MEMORY_TRANSACTION_PAGES)
                return GEM_MEMORY_NO_MEMORY;
            transaction_metadata_acquire(transaction);
            page = at(transaction->memory, page_address);
            if (page == NULL || page->backing == NULL) {
                gem_lock_release(&transaction->memory->lock);
                return page == NULL ? GEM_MEMORY_NOT_RESERVED : GEM_MEMORY_NOT_COMMITTED;
            }
            dependency = &transaction->pages[transaction->page_count++];
            dependency->address = page_address;
            dependency->generation = page->generation;
            dependency->content_generation = page->backing->generation;
            dependency->backing = page->backing;
            dependency->protection = page->protection;
            dependency->external = page->backing->external;
            stripe_count = page_stripes(page_address, page->backing, stripes, 0U);
            transaction_stripes_acquire(transaction, stripes, stripe_count, false);
            dependency->content_hash =
                page->backing->external ? content_hash(page->backing->data) : 0U;
            ++dependency->backing->refs;
            transaction_stripes_release(transaction, stripes, stripe_count, false);
            gem_lock_release(&transaction->memory->lock);
        }
        if (!allowed(dependency->protection, write, execute)) {
            error = GEM_MEMORY_ACCESS_DENIED;
            break;
        }
        if ((dependency->protection & GEM_PAGE_GUARD) != 0U) {
            struct page *page;
            size_t stripes[GEM_MEMORY_LOCK_STRIPES];
            size_t stripe_count = page_stripes(page_address, dependency->backing, stripes, 0U);
            transaction_metadata_acquire(transaction);
            transaction_stripes_acquire(transaction, stripes, stripe_count, true);
            page = at(transaction->memory, page_address);
            if (page == NULL || page->backing != dependency->backing ||
                page->generation != dependency->generation ||
                page->protection != dependency->protection)
                error = GEM_MEMORY_CONFLICT;
            else {
                page->protection &= ~(uint32_t)GEM_PAGE_GUARD;
                touch_page(transaction->memory, page);
                dependency->generation = page->generation;
                dependency->protection = page->protection;
                dependency->content_hash =
                    page->backing->external ? content_hash(page->backing->data) : 0U;
                error = GEM_MEMORY_GUARD_PAGE;
            }
            transaction_stripes_release(transaction, stripes, stripe_count, true);
            gem_lock_release(&transaction->memory->lock);
            return error;
        }
        if (chunk > size - done)
            chunk = size - done;
        done += chunk;
    }
    return error;
}

enum gem_memory_error gem_memory_transaction_finish(struct gem_memory_transaction *transaction,
                                                    uint64_t *fault_address) {
    size_t i, stripe_count, stripes[GEM_MEMORY_LOCK_STRIPES];
    if (transaction == NULL)
        return GEM_MEMORY_INVALID_ARGUMENT;
    transaction_metadata_acquire(transaction);
    stripe_count = dependency_stripes(transaction, stripes);
    for (i = 0U; i < stripe_count; ++i)
        transaction_stripe_read_acquire(transaction, stripes[i]);
    for (i = 0U; i < transaction->page_count; ++i) {
        const struct transaction_page *dependency = &transaction->pages[i];
        const struct page *current = at(transaction->memory, dependency->address);
        if (current == NULL || current->backing != dependency->backing ||
            current->generation != dependency->generation ||
            current->backing->generation != dependency->content_generation ||
            current->protection != dependency->protection ||
            (dependency->external &&
             content_hash(current->backing->data) != dependency->content_hash)) {
            if (fault_address != NULL)
                *fault_address = dependency->address;
            size_t stripe;
            for (stripe = stripe_count; stripe != 0U; --stripe)
                gem_stripe_read_release(&transaction->memory->stripes[stripes[stripe - 1U]].lock);
            gem_lock_release(&transaction->memory->lock);
            return GEM_MEMORY_CONFLICT;
        }
    }
    for (i = stripe_count; i != 0U; --i)
        gem_stripe_read_release(&transaction->memory->stripes[stripes[i - 1U]].lock);
    gem_lock_release(&transaction->memory->lock);
    return GEM_MEMORY_OK;
}

enum gem_memory_error
gem_memory_transaction_commit_pages(struct gem_memory_transaction *transaction,
                                    const struct gem_memory_page_write *writes, size_t count,
                                    uint64_t *fault_address, size_t *bytes_committed) {
    enum gem_memory_error error = GEM_MEMORY_OK;
    struct backing *copies[64];
    struct backing *commit_backings[64];
    bool copied[64];
    unsigned char stripe_modes[GEM_MEMORY_LOCK_STRIPES];
    size_t stripes[GEM_MEMORY_LOCK_STRIPES], stripe_count, i, j;
    size_t changed_bytes = 0U;
    if (transaction == NULL || (count != 0U && writes == NULL) || count > 64U)
        return GEM_MEMORY_INVALID_ARGUMENT;
    if (bytes_committed != NULL)
        *bytes_committed = 0U;
    for (i = 0U; i < count; ++i) {
        copies[i] = NULL;
        commit_backings[i] = NULL;
        copied[i] = false;
    }
    transaction_metadata_acquire(transaction);
    stripe_count = dependency_stripes(transaction, stripes);
    for (i = 0U; i < stripe_count; ++i)
        stripe_modes[stripes[i]] = 1U;
    for (i = 0U; i < count; ++i) {
        struct page *page = at(transaction->memory, writes[i].address);
        size_t write_stripes[2];
        size_t write_count =
            page_stripes(writes[i].address, page != NULL ? page->backing : NULL, write_stripes, 0U);
        for (j = 0U; j < write_count; ++j) {
            stripe_count = insert_stripe(stripes, stripe_count, write_stripes[j]);
            stripe_modes[write_stripes[j]] = 2U;
        }
    }
    for (i = 0U; i < stripe_count; ++i) {
        if (stripe_modes[stripes[i]] == 2U)
            transaction_stripe_write_acquire(transaction, stripes[i]);
        else
            transaction_stripe_read_acquire(transaction, stripes[i]);
    }
    for (i = 0U; i < transaction->page_count; ++i) {
        struct transaction_page *dependency = &transaction->pages[i];
        struct page *current = at(transaction->memory, dependency->address);
        if (current == NULL || current->backing != dependency->backing ||
            current->generation != dependency->generation ||
            current->backing->generation != dependency->content_generation ||
            current->protection != dependency->protection ||
            (dependency->external &&
             content_hash(current->backing->data) != dependency->content_hash)) {
            if (fault_address != NULL)
                *fault_address = dependency->address;
            error = GEM_MEMORY_CONFLICT;
            goto Rollback;
        }
    }
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
            touch_page(transaction->memory, page);
            for (j = 0U; j < transaction->page_count; ++j)
                if (transaction->pages[j].address == writes[i].address) {
                    transaction->pages[j].generation = page->generation;
                    transaction->pages[j].protection = page->protection;
                }
            if (fault_address != NULL)
                *fault_address = writes[i].address;
            error = GEM_MEMORY_GUARD_PAGE;
            goto Rollback;
        }
        if ((page->protection & ~(uint32_t)GEM_PAGE_GUARD) == GEM_PAGE_WRITECOPY ||
            (page->protection & ~(uint32_t)GEM_PAGE_GUARD) == GEM_PAGE_EXECUTE_WRITECOPY) {
            if (!page->backing->external) {
                copies[i] = new_backing(NULL, false);
                if (copies[i] == NULL) {
                    error = GEM_MEMORY_NO_MEMORY;
                    goto Rollback;
                }
                memcpy(copies[i]->data, page->backing->data, 4096U);
            }
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
        } else if (page->backing->external &&
                   ((page->protection & ~(uint32_t)GEM_PAGE_GUARD) == GEM_PAGE_WRITECOPY ||
                    (page->protection & ~(uint32_t)GEM_PAGE_GUARD) == GEM_PAGE_EXECUTE_WRITECOPY)) {
            page->protection = (page->protection & ~(uint32_t)GEM_PAGE_GUARD) == GEM_PAGE_WRITECOPY
                                   ? GEM_PAGE_READWRITE
                                   : GEM_PAGE_EXECUTE_READWRITE;
        }
        commit_backings[i] = page->backing;
        ++commit_backings[i]->refs;
        touch_backing(transaction->memory, page->backing);
        touch_page(transaction->memory, page);
        for (j = 0U; j < transaction->page_count; ++j)
            if (transaction->pages[j].address == writes[i].address) {
                struct transaction_page *dependency = &transaction->pages[j];
                if (dependency->backing != page->backing) {
                    drop(dependency->backing);
                    dependency->backing = page->backing;
                    ++dependency->backing->refs;
                }
                dependency->generation = page->generation;
                dependency->content_generation = page->backing->generation;
                dependency->protection = page->protection;
                dependency->external = page->backing->external;
                dependency->content_hash =
                    page->backing->external ? content_hash(writes[i].data) : 0U;
            }
        if (page->backing->external) {
            size_t line;
            for (line = 0U; line < GEM_GUEST_PAGE_SIZE; line += GEM_MEMORY_CACHE_LINE)
                if (memcmp(page->backing->data + line, writes[i].data + line,
                           GEM_MEMORY_CACHE_LINE) != 0) {
                    memcpy(page->backing->data + line, writes[i].data + line,
                           GEM_MEMORY_CACHE_LINE);
                    changed_bytes += GEM_MEMORY_CACHE_LINE;
                }
            copied[i] = true;
        }
    }

    gem_lock_release(&transaction->memory->lock);
    for (i = 0U; i < count; ++i) {
        size_t line;
        if (copied[i])
            continue;
        for (line = 0U; line < GEM_GUEST_PAGE_SIZE; line += GEM_MEMORY_CACHE_LINE)
            if (memcmp(commit_backings[i]->data + line, writes[i].data + line,
                       GEM_MEMORY_CACHE_LINE) != 0) {
                memcpy(commit_backings[i]->data + line, writes[i].data + line,
                       GEM_MEMORY_CACHE_LINE);
                changed_bytes += GEM_MEMORY_CACHE_LINE;
            }
    }
    for (i = stripe_count; i != 0U; --i) {
        if (stripe_modes[stripes[i - 1U]] == 2U)
            gem_stripe_write_release(&transaction->memory->stripes[stripes[i - 1U]].lock);
        else
            gem_stripe_read_release(&transaction->memory->stripes[stripes[i - 1U]].lock);
    }
    transaction_metadata_acquire(transaction);
    for (i = 0U; i < count; ++i)
        drop(commit_backings[i]);
    gem_lock_release(&transaction->memory->lock);
    if (bytes_committed != NULL)
        *bytes_committed = changed_bytes;
    return GEM_MEMORY_OK;

Rollback:
    for (i = 0; i < count; ++i)
        if (copies[i] != NULL)
            drop(copies[i]);
    for (i = 0U; i < count; ++i)
        if (commit_backings[i] != NULL)
            drop(commit_backings[i]);
    for (i = stripe_count; i != 0U; --i) {
        if (stripe_modes[stripes[i - 1U]] == 2U)
            gem_stripe_write_release(&transaction->memory->stripes[stripes[i - 1U]].lock);
        else
            gem_stripe_read_release(&transaction->memory->stripes[stripes[i - 1U]].lock);
    }
    gem_lock_release(&transaction->memory->lock);
    return error;
}

uint64_t
gem_memory_transaction_lock_wait_nanoseconds(const struct gem_memory_transaction *transaction) {
    return transaction != NULL ? transaction->lock_wait_nanoseconds : 0U;
}

bool gem_memory_transaction_page_is_external(const struct gem_memory_transaction *transaction,
                                             uint64_t address) {
    size_t i;
    if (transaction == NULL)
        return false;
    address &= ~UINT64_C(4095);
    for (i = 0U; i < transaction->page_count; ++i)
        if (transaction->pages[i].address == address)
            return transaction->pages[i].external;
    return false;
}

struct gem_memory *gem_memory_create(void) {
    struct gem_memory *memory = calloc(1, sizeof(*memory));
    uint64_t canonical = GEM_KUSER_CANONICAL_ADDRESS;
    bool ok;
    size_t initialized_stripes = 0U;
    if (memory == NULL)
        return NULL;
    memory->page_buckets = calloc((size_t)GEM_MEMORY_HASH_BUCKETS, sizeof(*memory->page_buckets));
    if (memory->page_buckets == NULL) {
        free(memory);
        return NULL;
    }
    if (!gem_lock_init(&memory->lock)) {
        free(memory->page_buckets);
        free(memory);
        return NULL;
    }
    while (initialized_stripes < GEM_MEMORY_LOCK_STRIPES &&
           gem_stripe_init(&memory->stripes[initialized_stripes].lock))
        ++initialized_stripes;
    if (initialized_stripes != GEM_MEMORY_LOCK_STRIPES) {
        while (initialized_stripes != 0U)
            gem_stripe_destroy(&memory->stripes[--initialized_stripes].lock);
        gem_lock_destroy(&memory->lock);
        free(memory->page_buckets);
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
        while (initialized_stripes != 0U)
            gem_stripe_destroy(&memory->stripes[--initialized_stripes].lock);
        gem_lock_destroy(&memory->lock);
        free(memory->page_buckets);
        free(memory);
        return NULL;
    }
    return memory;
}
void gem_memory_destroy(struct gem_memory *m) {
    if (m) {
        size_t i;
        bool stripes[GEM_MEMORY_LOCK_STRIPES];
        gem_lock_acquire(&m->lock);
        range_stripes_acquire(m, 0U, UINT64_MAX, true, stripes);
        remove_pages(m, 0, UINT64_MAX);
        range_stripes_release(m, true, stripes);
        gem_lock_release(&m->lock);
        gem_lock_destroy(&m->lock);
        for (i = 0U; i < GEM_MEMORY_LOCK_STRIPES; ++i)
            gem_stripe_destroy(&m->stripes[i].lock);
        free(m->page_buckets);
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
    bool stripes[GEM_MEMORY_LOCK_STRIPES];
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    range_stripes_acquire(m, a, n, true, stripes);
    e = commit_locked(m, a, n, prot);
    range_stripes_release(m, true, stripes);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_commit_identity(struct gem_memory *m, uint64_t a, void *h,
                                                 uint64_t n, uint32_t prot) {
    enum gem_memory_error e;
    bool stripes[GEM_MEMORY_LOCK_STRIPES];
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    range_stripes_acquire(m, a, n, true, stripes);
    e = commit_external_locked(m, a, h, n, prot, true);
    range_stripes_release(m, true, stripes);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_commit_external(struct gem_memory *m, uint64_t a, void *h,
                                                 uint64_t n, uint32_t prot) {
    enum gem_memory_error e;
    bool stripes[GEM_MEMORY_LOCK_STRIPES];
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    range_stripes_acquire(m, a, n, true, stripes);
    e = commit_external_locked(m, a, h, n, prot, false);
    range_stripes_release(m, true, stripes);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_decommit(struct gem_memory *m, uint64_t a, uint64_t n) {
    enum gem_memory_error e;
    bool stripes[GEM_MEMORY_LOCK_STRIPES];
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    range_stripes_acquire(m, a, n, true, stripes);
    e = decommit_locked(m, a, n);
    range_stripes_release(m, true, stripes);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_release(struct gem_memory *m, uint64_t a, uint64_t n) {
    enum gem_memory_error e;
    bool stripes[GEM_MEMORY_LOCK_STRIPES];
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    range_stripes_acquire(m, a, n, true, stripes);
    e = release_locked(m, a, n);
    range_stripes_release(m, true, stripes);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_unmap(struct gem_memory *m, uint64_t a, uint64_t n) {
    enum gem_memory_error e;
    bool stripes[GEM_MEMORY_LOCK_STRIPES];
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    range_stripes_acquire(m, a, n, true, stripes);
    e = unmap_locked(m, a, n);
    range_stripes_release(m, true, stripes);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_protect(struct gem_memory *m, uint64_t a, uint64_t n,
                                         uint32_t prot, uint32_t *old) {
    enum gem_memory_error e;
    bool stripes[GEM_MEMORY_LOCK_STRIPES];
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    range_stripes_acquire(m, a, n, true, stripes);
    e = protect_locked(m, a, n, prot, old);
    range_stripes_release(m, true, stripes);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_alias(struct gem_memory *m, uint64_t a, uint64_t s, uint64_t n,
                                       uint32_t prot) {
    enum gem_memory_error e;
    bool stripes[GEM_MEMORY_LOCK_STRIPES];
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    range_stripes_acquire(m, a, n, true, stripes);
    e = alias_locked(m, a, s, n, prot);
    range_stripes_release(m, true, stripes);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_map_identity(struct gem_memory *m, uint64_t a, void *h, uint64_t n,
                                              uint32_t prot) {
    enum gem_memory_error e;
    bool stripes[GEM_MEMORY_LOCK_STRIPES];
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    range_stripes_acquire(m, a, n, true, stripes);
    e = map_identity_locked(m, a, h, n, prot);
    range_stripes_release(m, true, stripes);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_bind_kuser(struct gem_memory *m, void *host_page) {
    enum gem_memory_error e;
    bool stripes[GEM_MEMORY_LOCK_STRIPES];
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    range_stripes_acquire(m, 0U, UINT64_MAX, true, stripes);
    e = bind_kuser_locked(m, host_page);
    range_stripes_release(m, true, stripes);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_read(struct gem_memory *m, uint64_t a, void *b, size_t n) {
    enum gem_memory_error e;
    bool stripes[GEM_MEMORY_LOCK_STRIPES];
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    range_stripes_acquire(m, a, n, false, stripes);
    e = access_memory_locked(m, a, b, n, false, false, false, true);
    range_stripes_release(m, false, stripes);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_write(struct gem_memory *m, uint64_t a, const void *b, size_t n) {
    enum gem_memory_error e;
    bool stripes[GEM_MEMORY_LOCK_STRIPES];
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    range_stripes_acquire(m, a, n, true, stripes);
    e = access_memory_locked(m, a, (void *)b, n, true, false, false, true);
    range_stripes_release(m, true, stripes);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_fetch(struct gem_memory *m, uint64_t a, void *b, size_t n) {
    enum gem_memory_error e;
    bool stripes[GEM_MEMORY_LOCK_STRIPES];
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    range_stripes_acquire(m, a, n, false, stripes);
    e = access_memory_locked(m, a, b, n, false, true, false, true);
    range_stripes_release(m, false, stripes);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_peek(struct gem_memory *m, uint64_t a, void *b, size_t n) {
    enum gem_memory_error e;
    bool stripes[GEM_MEMORY_LOCK_STRIPES];
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    range_stripes_acquire(m, a, n, false, stripes);
    e = peek_locked(m, a, b, n);
    range_stripes_release(m, false, stripes);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_read_deferred_guard(struct gem_memory *m, uint64_t a, void *b,
                                                     size_t n) {
    enum gem_memory_error e;
    bool stripes[GEM_MEMORY_LOCK_STRIPES];
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    range_stripes_acquire(m, a, n, false, stripes);
    e = access_memory_locked(m, a, b, n, false, false, false, false);
    range_stripes_release(m, false, stripes);
    gem_lock_release(&m->lock);
    return e;
}
enum gem_memory_error gem_memory_write_deferred_guard(struct gem_memory *m, uint64_t a,
                                                      const void *b, size_t n) {
    enum gem_memory_error e;
    bool stripes[GEM_MEMORY_LOCK_STRIPES];
    if (!m)
        return GEM_MEMORY_INVALID_ARGUMENT;
    gem_lock_acquire(&m->lock);
    range_stripes_acquire(m, a, n, true, stripes);
    e = access_memory_locked(m, a, (void *)b, n, true, false, false, false);
    range_stripes_release(m, true, stripes);
    gem_lock_release(&m->lock);
    return e;
}
bool gem_memory_is_executable(struct gem_memory *m, uint64_t a, size_t n) {
    enum gem_memory_error e;
    bool stripes[GEM_MEMORY_LOCK_STRIPES];
    if (!m)
        return false;
    gem_lock_acquire(&m->lock);
    range_stripes_acquire(m, a, n, false, stripes);
    e = access_memory_locked(m, a, NULL, n, false, true, true, true);
    range_stripes_release(m, false, stripes);
    gem_lock_release(&m->lock);
    return e == GEM_MEMORY_OK;
}
const char *gem_memory_error_name(enum gem_memory_error e) {
    static const char *n[] = {"ok",         "invalid-argument", "overflow",      "no-memory",
                              "conflict",   "not-reserved",     "not-committed", "access-denied",
                              "guard-page", "not-found"};
    return (unsigned)e < 10 ? n[e] : "invalid";
}
