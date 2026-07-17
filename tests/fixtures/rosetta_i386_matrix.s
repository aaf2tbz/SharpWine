// SPDX-License-Identifier: Apache-2.0
.text
.p2align 4
.globl _run_raw_i386_case
_run_raw_i386_case:
    pushl %ebp
    movl %esp, %ebp
    pushl %ebx
    pushl %esi
    pushl %edi
    movl 12(%ebp), %eax
    movdqu 28(%eax), %xmm0
    pushl 24(%eax)
    popfl
    movl 4(%eax), %ebx
    movl 8(%eax), %ecx
    movl 12(%eax), %edx
    movl 16(%eax), %esi
    movl 20(%eax), %edi
    movl 0(%eax), %eax
    calll *8(%ebp)
    pushfl
    pushal
    movl 16(%ebp), %eax
    movl 28(%esp), %edx
    movl %edx, 4(%eax)
    movl 16(%esp), %edx
    movl %edx, 8(%eax)
    movl 24(%esp), %edx
    movl %edx, 12(%eax)
    movl 20(%esp), %edx
    movl %edx, 16(%eax)
    movl 4(%esp), %edx
    movl %edx, 20(%eax)
    movl 0(%esp), %edx
    movl %edx, 24(%eax)
    movl 32(%esp), %edx
    andl $0x8d5, %edx
    movl %edx, 28(%eax)
    movdqu %xmm0, 64(%eax)
    addl $36, %esp
    popl %edi
    popl %esi
    popl %ebx
    popl %ebp
    retl
