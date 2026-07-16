// SPDX-License-Identifier: Apache-2.0
.text
.p2align 4
.globl _i386_phase4_run_raw
_i386_phase4_run_raw:
    pushl %ebp
    movl %esp, %ebp
    pushl %ebx
    pushl %esi
    pushl %edi
    movl 12(%ebp), %eax
    fxrstor 48(%eax)
    pushl 32(%eax)
    popfl
    movl 12(%eax), %ebx
    movl 4(%eax), %ecx
    movl 8(%eax), %edx
    movl 24(%eax), %esi
    movl 28(%eax), %edi
    movl 0(%eax), %eax
    calll *8(%ebp)
    pushfl
    pushal
    movl 16(%ebp), %eax
    movl 28(%esp), %edx
    movl %edx, 0(%eax)
    movl 24(%esp), %edx
    movl %edx, 4(%eax)
    movl 20(%esp), %edx
    movl %edx, 8(%eax)
    movl 16(%esp), %edx
    movl %edx, 12(%eax)
    movl 4(%esp), %edx
    movl %edx, 24(%eax)
    movl 0(%esp), %edx
    movl %edx, 28(%eax)
    movl 32(%esp), %edx
    movl %edx, 32(%eax)
    fxsave 48(%eax)
    addl $36, %esp
    popl %edi
    popl %esi
    popl %ebx
    popl %ebp
    retl
