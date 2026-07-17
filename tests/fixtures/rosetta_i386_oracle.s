// SPDX-License-Identifier: Apache-2.0
// PE32 architectural probes. Each routine preserves the i386 ABI's nonvolatile
// registers and writes only normalized architectural results to oracle_record.

.text
.p2align 4
.globl _run_add32
_run_add32:
    pushl %ebp
    movl %esp, %ebp
    pushl %ebx
    pushl %esi
    pushl %edi
    movl 8(%ebp), %edi
    movl $1, 0(%edi)
    movl $0x7fffffff, %eax
    movl $1, %ebx
    addl %ebx, %eax
    pushfl
    popl %edx
    movl %eax, 4(%edi)
    movl %ebx, 8(%edi)
    movl %edx, 36(%edi)
    popl %edi
    popl %esi
    popl %ebx
    popl %ebp
    retl

.p2align 4
.globl _run_shift32
_run_shift32:
    pushl %ebp
    movl %esp, %ebp
    pushl %ebx
    pushl %esi
    pushl %edi
    movl 8(%ebp), %edi
    movl $2, 0(%edi)
    movl $0x80000001, %eax
    movl $33, %ecx
    roll %cl, %eax
    pushfl
    popl %edx
    movl %eax, 4(%edi)
    movl %ecx, 12(%edi)
    movl %edx, 36(%edi)
    popl %edi
    popl %esi
    popl %ebx
    popl %ebp
    retl

.p2align 4
.globl _run_memory32
_run_memory32:
    pushl %ebp
    movl %esp, %ebp
    pushl %ebx
    pushl %esi
    pushl %edi
    movl 8(%ebp), %edi
    movl $3, 0(%edi)
    leal 40(%edi), %esi
    movl $0x11223344, (%esi)
    movl $0xaabbccdd, 4(%esi)
    movl (%esi), %eax
    xchgl %eax, 4(%esi)
    pushfl
    popl %edx
    movl %eax, 4(%edi)
    movl %esi, 20(%edi)
    movl %edx, 36(%edi)
    popl %edi
    popl %esi
    popl %ebx
    popl %ebp
    retl

.p2align 4
.globl _run_sse2
_run_sse2:
    pushl %ebp
    movl %esp, %ebp
    pushl %ebx
    pushl %esi
    pushl %edi
    movl 8(%ebp), %edi
    movl $4, 0(%edi)
    movl $0x3f800000, %eax
    movd %eax, %xmm0
    pshufd $0, %xmm0, %xmm0
    addps %xmm0, %xmm0
    movdqu %xmm0, 48(%edi)
    pushfl
    popl %edx
    movl %edx, 36(%edi)
    popl %edi
    popl %esi
    popl %ebx
    popl %ebp
    retl

.p2align 4
.globl _run_x87
_run_x87:
    pushl %ebp
    movl %esp, %ebp
    pushl %ebx
    pushl %esi
    pushl %edi
    movl 8(%ebp), %edi
    movl $5, 0(%edi)
    fninit
    fld1
    fld1
    faddp %st, %st(1)
    fstpl 64(%edi)
    fnstsw %ax
    movzwl %ax, %eax
    movl %eax, 4(%edi)
    pushfl
    popl %edx
    movl %edx, 36(%edi)
    popl %edi
    popl %esi
    popl %ebx
    popl %ebp
    retl
