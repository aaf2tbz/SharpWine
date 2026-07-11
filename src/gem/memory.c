// SPDX-License-Identifier: Apache-2.0
#include "metalsharp/gem/memory.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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
struct gem_memory {
    struct page *pages;
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
struct gem_memory *gem_memory_create(void) {
    struct gem_memory *memory = calloc(1, sizeof(*memory));
    uint64_t canonical = GEM_KUSER_CANONICAL_ADDRESS;
    if (memory == NULL)
        return NULL;
    if (gem_memory_reserve(memory, &canonical, GEM_GUEST_PAGE_SIZE) != GEM_MEMORY_OK ||
        gem_memory_commit(memory, canonical, GEM_GUEST_PAGE_SIZE, GEM_PAGE_READWRITE) !=
            GEM_MEMORY_OK ||
        gem_memory_alias(memory, GEM_KUSER_SHARED_DATA_ADDRESS, canonical, GEM_GUEST_PAGE_SIZE,
                         GEM_PAGE_READWRITE) != GEM_MEMORY_OK) {
        gem_memory_destroy(memory);
        return NULL;
    }
    return memory;
}
void gem_memory_destroy(struct gem_memory *m) {
    if (m) {
        remove_pages(m, 0, UINT64_MAX);
        free(m);
    }
}
enum gem_memory_error gem_memory_reserve(struct gem_memory *m, uint64_t *a, uint64_t n) {
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
enum gem_memory_error gem_memory_commit(struct gem_memory *m, uint64_t a, uint64_t n,
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
enum gem_memory_error gem_memory_decommit(struct gem_memory *m, uint64_t a, uint64_t n) {
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
enum gem_memory_error gem_memory_release(struct gem_memory *m, uint64_t a, uint64_t n) {
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
enum gem_memory_error gem_memory_unmap(struct gem_memory *m, uint64_t a, uint64_t n) {
    return gem_memory_release(m, a, n);
}
enum gem_memory_error gem_memory_protect(struct gem_memory *m, uint64_t a, uint64_t n,
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
enum gem_memory_error gem_memory_alias(struct gem_memory *m, uint64_t a, uint64_t s, uint64_t n,
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
enum gem_memory_error gem_memory_map_identity(struct gem_memory *m, uint64_t a, void *h, uint64_t n,
                                              uint32_t prot) {
    uint64_t o, hs = (uint64_t)sysconf(_SC_PAGESIZE);
    enum gem_memory_error e;
    if (!h || a < UINT64_C(0x100000000) || a != (uint64_t)(uintptr_t)h || !range_ok(a, n) ||
        !prot_ok(prot) || a % hs || n % hs)
        return GEM_MEMORY_INVALID_ARGUMENT;
    if ((e = gem_memory_reserve(m, &a, n)))
        return e;
    for (o = 0; o < n; o += 4096) {
        struct page *p = at(m, a + o);
        p->backing = new_backing((uint8_t *)h + o, true);
        if (!p->backing) {
            (void)gem_memory_release(m, a, n);
            return GEM_MEMORY_NO_MEMORY;
        }
        p->protection = prot;
    }
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
static enum gem_memory_error access_memory(struct gem_memory *m, uint64_t a, void *b, size_t n,
                                           bool w, bool x, bool query) {
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
            if ((ps[i]->protection & ~(uint32_t)GEM_PAGE_GUARD) == GEM_PAGE_WRITECOPY ||
                (ps[i]->protection & ~(uint32_t)GEM_PAGE_GUARD) == GEM_PAGE_EXECUTE_WRITECOPY) {
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
            }
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
enum gem_memory_error gem_memory_read(struct gem_memory *m, uint64_t a, void *b, size_t n) {
    return access_memory(m, a, b, n, false, false, false);
}
enum gem_memory_error gem_memory_write(struct gem_memory *m, uint64_t a, const void *b, size_t n) {
    return access_memory(m, a, (void *)b, n, true, false, false);
}
enum gem_memory_error gem_memory_fetch(struct gem_memory *m, uint64_t a, void *b, size_t n) {
    return access_memory(m, a, b, n, false, true, false);
}
enum gem_memory_error gem_memory_peek(struct gem_memory *m, uint64_t a, void *b, size_t n) {
    size_t done = 0;
    if (!m || (n && !b) || a > UINT64_MAX - n)
        return GEM_MEMORY_INVALID_ARGUMENT;
    if (!n)
        return GEM_MEMORY_OK;
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
        memcpy((uint8_t *)b + done, p->backing->data + ((a + done) & 4095U), z);
        done += z;
    }
    return GEM_MEMORY_OK;
}
bool gem_memory_is_executable(struct gem_memory *m, uint64_t a, size_t n) {
    return access_memory(m, a, NULL, n, false, true, true) == GEM_MEMORY_OK;
}
const char *gem_memory_error_name(enum gem_memory_error e) {
    static const char *n[] = {"ok",         "invalid-argument", "overflow",      "no-memory",
                              "conflict",   "not-reserved",     "not-committed", "access-denied",
                              "guard-page", "not-found"};
    return (unsigned)e < 10 ? n[e] : "invalid";
}
