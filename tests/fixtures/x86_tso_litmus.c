// SPDX-License-Identifier: Apache-2.0
// Freestanding x86_64 Linux guest; generated binaries remain build-tree-only.

typedef unsigned long u64;
typedef unsigned int u32;

#define SYS_write 1
#define SYS_sched_yield 24
#define SYS_exit 60
#define SYS_clone 56
#define CLONE_VM 0x100
#define CLONE_FS 0x200
#define CLONE_FILES 0x400
#define CLONE_SIGHAND 0x800
#define CLONE_THREAD 0x10000
#define CLONE_PARENT_SETTID 0x100000
#define CLONE_CHILD_CLEARTID 0x200000
#define WORKERS 4
#ifndef MSWR_TSO_ROUNDS
#define MSWR_TSO_ROUNDS 20000
#endif
#ifndef MSWR_TSO_LOCK_ITERS
#define MSWR_TSO_LOCK_ITERS 10000
#endif

static _Alignas(128) volatile u32 g_round;
static _Alignas(128) volatile u32 g_done;
static _Alignas(128) volatile u32 g_test;
static _Alignas(128) volatile u32 g_x;
static _Alignas(128) volatile u32 g_y;
static _Alignas(128) volatile u32 g_result[WORKERS][2];
static _Alignas(128) volatile u32 g_locked;
static _Alignas(16) unsigned char g_code[16] = {0xb8, 1, 0, 0, 0, 0xc3};
static unsigned char g_stacks[WORKERS][65536];
static volatile u32 g_tids[WORKERS];

static inline long syscall0(long n) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n) : "rcx", "r11", "memory");
    return r;
}
static inline long syscall1(long n, long a) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a) : "rcx", "r11", "memory");
    return r;
}
static inline long syscall3(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}
static void die(int n) {
    syscall1(SYS_exit, n);
    for (;;) {
    }
}
static void out(const char *p, u64 n) {
    if (syscall3(SYS_write, 1, (long)p, n) != (long)n)
        die(90);
}
static u64 slen(const char *p) {
    u64 n = 0;
    while (p[n])
        ++n;
    return n;
}
static void outs(const char *p) {
    out(p, slen(p));
}
static void outu(u64 x) {
    char b[32];
    u64 n = 0;
    if (!x)
        b[n++] = '0';
    while (x) {
        b[n++] = (char)('0' + x % 10);
        x /= 10;
    }
    for (u64 i = 0; i < n / 2; ++i) {
        char c = b[i];
        b[i] = b[n - 1 - i];
        b[n - 1 - i] = c;
    }
    out(b, n);
}
static inline void yield_cpu(void) {
    __asm__ volatile("pause" ::: "memory");
    (void)syscall0(SYS_sched_yield);
}
static inline void full_fence(void) {
    __asm__ volatile("mfence" ::: "memory");
}
static inline void lock_inc(volatile u32 *p) {
    __asm__ volatile("lock; incl %0" : "+m"(*p)::"cc", "memory");
}
static inline void serialize_cpu(void) {
    u32 a = 0, b, c = 0, d;
    __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d)::"memory");
}
static int call_generated_code(void) {
    int (*code)(void) = (int (*)(void))g_code;
    return code();
}

__attribute__((used, noinline)) void worker(long id) {
    u32 seen = 0;
    for (;;) {
        u32 round;
        while ((round = g_round) == seen)
            yield_cpu();
        seen = round;
        switch (g_test) {
        case 1:
            if (id == 0) {
                g_x = 1;
                g_result[0][0] = g_y;
            } else if (id == 1) {
                g_y = 1;
                g_result[1][0] = g_x;
            }
            break;
        case 2:
            if (id == 0) {
                g_result[0][0] = g_x;
                g_y = 1;
            } else if (id == 1) {
                g_result[1][0] = g_y;
                g_x = 1;
            }
            break;
        case 3:
            if (id == 0) {
                g_x = 1;
                g_y = 1;
            } else if (id == 1) {
                g_result[1][0] = g_y;
                g_result[1][1] = g_x;
            }
            break;
        case 4:
            if (id == 0)
                g_x = 1;
            else if (id == 1)
                g_y = 1;
            else if (id == 2) {
                g_result[2][0] = g_x;
                g_result[2][1] = g_y;
            } else {
                g_result[3][0] = g_y;
                g_result[3][1] = g_x;
            }
            break;
        case 5:
            for (u32 i = 0; i < MSWR_TSO_LOCK_ITERS; ++i)
                lock_inc(&g_locked);
            break;
        case 6:
            if (id == 0) {
                g_x = 1;
                full_fence();
                g_result[0][0] = g_y;
            } else if (id == 1) {
                g_y = 1;
                full_fence();
                g_result[1][0] = g_x;
            }
            break;
        case 7:
            if (id == 0) {
                g_code[1] = 2;
                full_fence();
                g_x = 1;
            } else if (id == 1) {
                while (!g_x)
                    yield_cpu();
                serialize_cpu();
                g_result[1][0] = (u32)call_generated_code();
            }
            break;
        case 99:
            die(0);
        }
        lock_inc(&g_done);
    }
}

static long spawn(void *stack, long id) {
    long result;
    u64 *child_stack = (u64 *)stack;
    volatile u32 *tidptr = &g_tids[id];
    register long r10 __asm__("r10") = (long)tidptr;
    register long r8 __asm__("r8") = 0;
    *--child_stack = (u64)id;
    __asm__ volatile("syscall\n"
                     "test %%rax,%%rax\n"
                     "jnz 1f\n"
                     "pop %%rdi\n"
                     "call worker\n"
                     "mov $60,%%eax\n"
                     "xor %%edi,%%edi\n"
                     "syscall\n"
                     "ud2\n"
                     "1:"
                     : "=a"(result)
                     : "a"(SYS_clone),
                       "D"(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
                           CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID),
                       "S"(child_stack), "d"(tidptr), "r"(r10), "r"(r8)
                     : "rcx", "r11", "memory");
    return result;
}

static void begin(u32 test) {
    g_x = g_y = g_done = g_locked = 0;
    for (u32 i = 0; i < WORKERS; ++i)
        g_result[i][0] = g_result[i][1] = 0;
    g_test = test;
    ++g_round;
    while (g_done != WORKERS)
        yield_cpu();
}

void _start(void) {
    u64 sb00 = 0, lb11 = 0, mp10 = 0, iriw = 0, fence00 = 0;
    for (long i = 0; i < WORKERS; ++i) {
        void *top = g_stacks[i] + sizeof(g_stacks[i]);
        if (spawn(top, i) <= 0)
            die(80 + (int)i);
    }
    outs("stage=workers\n");
    for (u32 i = 0; i < MSWR_TSO_ROUNDS; ++i) {
        begin(1);
        if (!g_result[0][0] && !g_result[1][0])
            ++sb00;
    }
    outs("stage=sb\n");
    for (u32 i = 0; i < MSWR_TSO_ROUNDS; ++i) {
        begin(2);
        if (g_result[0][0] && g_result[1][0])
            ++lb11;
    }
    outs("stage=lb\n");
    for (u32 i = 0; i < MSWR_TSO_ROUNDS; ++i) {
        begin(3);
        if (g_result[1][0] && !g_result[1][1])
            ++mp10;
    }
    outs("stage=mp\n");
    for (u32 i = 0; i < MSWR_TSO_ROUNDS; ++i) {
        begin(4);
        if (g_result[2][0] && !g_result[2][1] && g_result[3][0] && !g_result[3][1])
            ++iriw;
    }
    outs("stage=iriw\n");
    begin(5);
    u64 locked = g_locked;
    for (u32 i = 0; i < MSWR_TSO_ROUNDS; ++i) {
        begin(6);
        if (!g_result[0][0] && !g_result[1][0])
            ++fence00;
    }
    outs("stage=locked-fence\n");
    u64 smc = 0;
    for (u32 i = 0; i < 10000; ++i)
        if (call_generated_code() != 1)
            ++smc;
    begin(7);
    if (g_result[1][0] != 2)
        ++smc;
    for (u32 i = 0; i < 10000; ++i)
        if (call_generated_code() != 2)
            ++smc;
    outs("stage=smc\n");
    g_test = 99;
    ++g_round;
    for (int i = 0; i < WORKERS; ++i)
        while (g_tids[i])
            yield_cpu();
    outs("MSWR_TSO_V1 sb00=");
    outu(sb00);
    outs(" lb11=");
    outu(lb11);
    outs(" mp10=");
    outu(mp10);
    outs(" iriw=");
    outu(iriw);
    outs(" locked=");
    outu(locked);
    outs(" fence00=");
    outu(fence00);
    outs(" smc=");
    outu(smc);
    outs("\n");
    if (lb11 || mp10 || iriw || locked != (u64)WORKERS * MSWR_TSO_LOCK_ITERS || fence00 || smc)
        die(1);
    die(0);
}
