// SPDX-License-Identifier: Apache-2.0
// These position-independent bodies are copied to anonymous executable memory
// so Rosetta must take its indirect-branch JIT path.

.text
.p2align 4
.globl _rosetta_x64_add_start
.globl _rosetta_x64_add_end
_rosetta_x64_add_start:
    movl $1, 0(%rdi)
    movl $0x7fffffff, %eax
    addl $1, %eax
    pushfq
    popq %rcx
    andl $0x8d5, %ecx
    movq %rax, 8(%rdi)
    movq %rcx, 32(%rdi)
    retq
_rosetta_x64_add_end:

.p2align 4
.globl _rosetta_x64_shift_start
.globl _rosetta_x64_shift_end
_rosetta_x64_shift_start:
    movl $2, 0(%rdi)
    movl $0x80000001, %eax
    movl $33, %ecx
    roll %cl, %eax
    pushfq
    popq %rdx
    andl $0x8d5, %edx
    movq %rax, 8(%rdi)
    movq %rcx, 16(%rdi)
    movq %rdx, 32(%rdi)
    retq
_rosetta_x64_shift_end:

.p2align 4
.globl _rosetta_x64_memory_start
.globl _rosetta_x64_memory_end
_rosetta_x64_memory_start:
    movl $3, 0(%rdi)
    movl $0x11223344, 40(%rdi)
    movl $0xaabbccdd, 44(%rdi)
    movl 40(%rdi), %eax
    xchgl %eax, 44(%rdi)
    movq %rax, 8(%rdi)
    retq
_rosetta_x64_memory_end:

.p2align 4
.globl _rosetta_x64_sse2_start
.globl _rosetta_x64_sse2_end
_rosetta_x64_sse2_start:
    movl $4, 0(%rdi)
    movl $0x3f800000, %eax
    movd %eax, %xmm0
    pshufd $0, %xmm0, %xmm0
    addps %xmm0, %xmm0
    movdqu %xmm0, 48(%rdi)
    retq
_rosetta_x64_sse2_end:

.p2align 4
.globl _rosetta_x64_avx2_start
.globl _rosetta_x64_avx2_end
_rosetta_x64_avx2_start:
    movl $5, 0(%rdi)
    vpcmpeqd %ymm0, %ymm0, %ymm0
    vpsrld $31, %ymm0, %ymm0
    vmovdqu %ymm0, 64(%rdi)
    vzeroupper
    retq
_rosetta_x64_avx2_end:
