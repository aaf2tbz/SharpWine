#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time

CLANG = Path("/opt/homebrew/opt/llvm/bin/clang")
OBJCOPY = Path("/opt/homebrew/opt/llvm/bin/llvm-objcopy")
LINK = Path("/opt/homebrew/bin/lld-link")


def case(name, asm, *, eax=0, ebx=0, ecx=0, edx=0, esi=0, edi=0,
         eflags=0x202, memory=None, xmm=None, use_memory=False):
    return {"name": name, "asm": asm, "regs": [eax, ebx, ecx, edx, esi, edi, eflags],
            "memory": memory or [0] * 8, "xmm": xmm or [0] * 4,
            "use_memory": use_memory, "defined_flags_mask": 0x8d5}


CASES = [
    case("nop", "nop"),
    case("add_overflow", "addl %ebx, %eax", eax=0x7fffffff, ebx=1),
    case("add_carry", "addl %ebx, %eax", eax=0xffffffff, ebx=1),
    case("adc_carry_in", "stc\nadcl %ebx, %eax", eax=0xffffffff, ebx=0),
    case("sub_borrow", "subl %ebx, %eax", eax=0, ebx=1),
    case("sbb_borrow_in", "stc\nsbbl %ebx, %eax", eax=0, ebx=0),
    case("and", "andl %ebx, %eax", eax=0xf0f0aa55, ebx=0x0ff00ff0),
    case("or", "orl %ebx, %eax", eax=0xf000000f, ebx=0x0ff00ff0),
    case("xor", "xorl %ebx, %eax", eax=0xaaaaaaaa, ebx=0x5555ffff),
    case("cmp_equal", "cmpl %ebx, %eax", eax=0x12345678, ebx=0x12345678),
    case("test_sign", "testl %ebx, %eax", eax=0xffffffff, ebx=0x80000000),
    case("inc_overflow", "incl %eax", eax=0x7fffffff),
    case("dec_overflow", "decl %eax", eax=0x80000000),
    case("neg_min", "negl %eax", eax=0x80000000),
    case("not", "notl %eax", eax=0x12345678),
    case("imul_low", "imull %ebx, %eax", eax=0x10001, ebx=0x10001),
    case("imul_wide", "imull %ebx", eax=0x7fffffff, ebx=3),
    case("mul_wide", "mull %ebx", eax=0xffffffff, ebx=2),
    case("div", "divl %ebx", eax=100, edx=0, ebx=7),
    case("idiv", "idivl %ebx", eax=0xffffff9c, edx=0xffffffff, ebx=7),
    case("rol_1", "roll $1, %eax", eax=0x80000001),
    case("rol_33", "movb $33, %cl\nroll %cl, %eax", eax=0x80000001),
    case("ror_31", "rorl $31, %eax", eax=0x80000001),
    case("shl_1", "shll $1, %eax", eax=0x80000001),
    case("shr_31", "shrl $31, %eax", eax=0x80000001),
    case("sar_31", "sarl $31, %eax", eax=0x80000001),
    case("shld", "shldl $4, %ebx, %eax", eax=0x12345678, ebx=0xabcdef01),
    case("shrd", "shrdl $4, %ebx, %eax", eax=0x12345678, ebx=0xabcdef01),
    case("bsf", "bsfl %ebx, %eax", eax=0xaaaaaaaa, ebx=0x00100000),
    case("bsr", "bsrl %ebx, %eax", eax=0xaaaaaaaa, ebx=0x00100000),
    case("bt", "btl $31, %ebx", ebx=0x80000000),
    case("bts", "btsl $7, %ebx", ebx=0),
    case("btr", "btrl $7, %ebx", ebx=0xffffffff),
    case("btc", "btcl $7, %ebx", ebx=0),
    case("bswap", "bswapl %eax", eax=0x12345678),
    case("cmovz_taken", "cmpl %eax, %eax\ncmovzl %ebx, %eax", eax=1, ebx=0xabcdef01),
    case("setl_taken", "cmpl %ebx, %eax\nsetl %al", eax=0xffffffff, ebx=1),
    case("movzx", "movzbl %bl, %eax", eax=0xffffffff, ebx=0x12345680),
    case("movsx", "movsbl %bl, %eax", eax=0, ebx=0x12345680),
    case("xchg_memory", "xchgl %eax, 4(%esi)", eax=0xaabbccdd,
         memory=[0x11223344, 0x55667788, 0, 0, 0, 0, 0, 0], use_memory=True),
    case("xadd_memory", "xaddl %eax, (%esi)", eax=5,
         memory=[7, 0, 0, 0, 0, 0, 0, 0], use_memory=True),
    case("cmpxchg_success", "lock cmpxchgl %ebx, (%esi)", eax=7, ebx=9,
         memory=[7, 0, 0, 0, 0, 0, 0, 0], use_memory=True),
    case("cmpxchg_fail", "lock cmpxchgl %ebx, (%esi)", eax=8, ebx=9,
         memory=[7, 0, 0, 0, 0, 0, 0, 0], use_memory=True),
    case("sse2_addps", "addps %xmm0, %xmm0", xmm=[0x3f800000] * 4),
    case("sse2_pshufd", "pshufd $0x1b, %xmm0, %xmm0",
         xmm=[0x11111111, 0x22222222, 0x33333333, 0x44444444]),
    case("ssse3_pabsb", "pabsb %xmm0, %xmm0",
         xmm=[0x80ff7f01, 0x817e02fe, 0x01020304, 0xf0e0d0c0]),
    case("sse41_pminsd", "pminsd (%esi), %xmm0", memory=[0xffffffff, 5, 3, 9, 0, 0, 0, 0],
         xmm=[1, 0xffffffff, 7, 2], use_memory=True),
    case("popcnt", "popcntl %ebx, %eax", ebx=0xf0f0f00f),
    case("lzcnt", "lzcntl %ebx, %eax", ebx=0x00100000),
    case("tzcnt", "tzcntl %ebx, %eax", ebx=0x00100000),
]

for test in CASES:
    if test["name"] in {"and", "or", "xor", "test_sign"}:
        test["defined_flags_mask"] = 0x8c5
    elif test["name"] in {"imul_low", "imul_wide", "mul_wide"}:
        test["defined_flags_mask"] = 0x801
    elif test["name"] in {"div", "idiv"}:
        test["defined_flags_mask"] = 0
    elif test["name"] in {"rol_1", "shl_1"}:
        test["defined_flags_mask"] = 0x801 if test["name"] == "rol_1" else 0x8c5
    elif test["name"] in {"rol_33", "ror_31"}:
        test["defined_flags_mask"] = 0x001
    elif test["name"] in {"shr_31", "sar_31", "shld", "shrd"}:
        test["defined_flags_mask"] = 0x0c5
    elif test["name"] in {"bsf", "bsr"}:
        test["defined_flags_mask"] = 0x040
    elif test["name"] in {"bt", "bts", "btr", "btc"}:
        test["defined_flags_mask"] = 0x001
    elif test["name"] in {"lzcnt", "tzcnt"}:
        test["defined_flags_mask"] = 0x041


def add_matrix_case(name, asm, flags_mask=0x8d5, **kwargs):
    test = case(name, asm, **kwargs)
    test["defined_flags_mask"] = flags_mask
    CASES.append(test)


# Broad deterministic edge corpus. These are deliberately generated from a
# small set of architecturally interesting values so the JSON remains easy to
# minimize when Rosetta and Blink disagree.
EDGE32 = (0, 1, 0xf, 0x10, 0x7fffffff, 0x80000000, 0xffffffff,
          0x55555555, 0xaaaaaaaa, 0x12345678)
PAIRS32 = tuple(zip(EDGE32, reversed(EDGE32)))
for opname, instruction, mask in (
        ("add", "addl", 0x8d5), ("adc", "adcl", 0x8d5),
        ("sub", "subl", 0x8d5), ("sbb", "sbbl", 0x8d5),
        ("cmp", "cmpl", 0x8d5), ("and", "andl", 0x8c5),
        ("or", "orl", 0x8c5), ("xor", "xorl", 0x8c5)):
    for index, (left, right) in enumerate(PAIRS32):
        prefix = "stc\n" if opname in {"adc", "sbb"} and index & 1 else "clc\n"
        add_matrix_case(f"edge32_{opname}_{index}", f"{prefix}{instruction} %ebx, %eax",
                        mask, eax=left, ebx=right)

for opname, instruction, mask in (
        ("inc", "incl", 0x8d4), ("dec", "decl", 0x8d4),
        ("neg", "negl", 0x8d5), ("not", "notl", 0)):
    for index, value in enumerate(EDGE32):
        add_matrix_case(f"edge32_{opname}_{index}", f"{instruction} %eax", mask,
                        eax=value, eflags=0x203 if index & 1 else 0x202)

for width, suffix, register, values in (
        (8, "b", "%al", (0, 1, 0x0f, 0x10, 0x7f, 0x80, 0xff)),
        (16, "w", "%ax", (0, 1, 0x0f, 0x10, 0x7fff, 0x8000, 0xffff))):
    for opname, mask in (("add", 0x8d5), ("sub", 0x8d5), ("cmp", 0x8d5),
                         ("and", 0x8c5), ("xor", 0x8c5)):
        for index, value in enumerate(values):
            other = values[-1 - index]
            add_matrix_case(f"edge{width}_{opname}_{index}",
                            f"{opname}{suffix} {'%bl' if width == 8 else '%bx'}, {register}",
                            mask, eax=0xa5a50000 | value, ebx=0x5a5a0000 | other)
    for opname, mask in (("inc", 0x8d4), ("dec", 0x8d4), ("neg", 0x8d5)):
        for index, value in enumerate(values):
            add_matrix_case(f"edge{width}_{opname}_{index}",
                            f"{opname}{suffix} {register}", mask,
                            eax=0xa5a50000 | value, eflags=0x203 if index & 1 else 0x202)

for opname, instruction in (("rol", "roll"), ("ror", "rorl"),
                            ("rcl", "rcll"), ("rcr", "rcrl"),
                            ("shl", "shll"), ("shr", "shrl"),
                            ("sar", "sarl")):
    for count in (0, 1, 2, 7, 15, 16, 31, 32, 33):
        if count == 0 or count == 32:
            mask = 0x8d5
        elif opname in {"rol", "ror", "rcl", "rcr"}:
            mask = 0x801 if count == 1 else 0x001
        else:
            mask = 0x8c5 if count == 1 else 0x0c5
        add_matrix_case(f"shift32_{opname}_{count}",
                        f"movb ${count}, %cl\n{instruction} %cl, %eax", mask,
                        eax=0x80010081, eflags=0x203)

for opname, instruction in (("shld", "shldl"), ("shrd", "shrdl")):
    for count in (0, 1, 4, 16, 31, 32, 33):
        mask = 0x8d5 if count in {0, 32} else (0x8c5 if count == 1 else 0x0c5)
        add_matrix_case(f"double_shift_{opname}_{count}",
                        f"movb ${count}, %cl\n{instruction} %cl, %ebx, %eax", mask,
                        eax=0x12345678, ebx=0xabcdef01)

for index, value in enumerate(EDGE32):
    # A zero source defines ZF but leaves the destination undefined, so it is
    # unsuitable for exact cross-runtime state comparison.
    if value:
        add_matrix_case(f"bits_bsf_{index}", "bsfl %ebx, %eax", 0x040,
                        eax=0xdeadbeef, ebx=value)
        add_matrix_case(f"bits_bsr_{index}", "bsrl %ebx, %eax", 0x040,
                        eax=0xdeadbeef, ebx=value)
    add_matrix_case(f"bits_popcnt_{index}", "popcntl %ebx, %eax", 0x041, ebx=value)
    add_matrix_case(f"bits_lzcnt_{index}", "lzcntl %ebx, %eax", 0x041, ebx=value)
    add_matrix_case(f"bits_tzcnt_{index}", "tzcntl %ebx, %eax", 0x041, ebx=value)

for bit in (0, 1, 7, 15, 16, 31, 32, 33, 63):
    for opname in ("bt", "bts", "btr", "btc"):
        add_matrix_case(f"bitmem_{opname}_{bit}", f"{opname}l ${bit}, (%esi)", 0x001,
                        memory=[0x80000001, 0x7ffffffe, 0, 0, 0, 0, 0, 0], use_memory=True)

for offset in (0, 1, 2, 3, 4, 7, 12):
    add_matrix_case(f"atomic_xadd32_off{offset}", f"lock xaddl %eax, {offset}(%esi)",
                    0x8d5, eax=5, memory=[7, 0x11223344, 0x55667788, 0, 0, 0, 0, 0],
                    use_memory=True)
    add_matrix_case(f"atomic_cmpxchg32_fail_off{offset}",
                    f"lock cmpxchgl %ebx, {offset}(%esi)", 0x8d5, eax=8, ebx=9,
                    memory=[7, 0x11223344, 0x55667788, 0, 0, 0, 0, 0], use_memory=True)

for width, suffix, accumulator, source in ((8, "b", 7, 9), (16, "w", 7, 9)):
    for offset in (0, 1, 2, 3, 7):
        add_matrix_case(f"atomic_cmpxchg{width}_ok_off{offset}",
                        f"lock cmpxchg{suffix} {'%bl' if width == 8 else '%bx'}, {offset}(%esi)",
                        0x8d5, eax=accumulator, ebx=source,
                        memory=[0x00070007, 0x11223344, 0, 0, 0, 0, 0, 0], use_memory=True)

# Phase 1 broadens the scalar corpus across encodings and operand forms. Keep
# each program short, deterministic, and free of architecturally undefined
# output so that a mismatch is actionable without additional filtering.
for width, suffix, accumulator, source, values in (
        (8, "b", "%al", "%bl", (0, 1, 0x7f, 0x80, 0xff)),
        (16, "w", "%ax", "%bx", (0, 1, 0x7fff, 0x8000, 0xffff)),
        (32, "l", "%eax", "%ebx", (0, 1, 0x7fffffff, 0x80000000, 0xffffffff))):
    high = 0xa5a50000 if width != 32 else 0
    for opname, mask in (("add", 0x8d5), ("adc", 0x8d5), ("sub", 0x8d5),
                         ("sbb", 0x8d5), ("cmp", 0x8d5), ("test", 0x8c5),
                         ("and", 0x8c5), ("or", 0x8c5), ("xor", 0x8c5)):
        for index, value in enumerate(values):
            other = values[-1 - index]
            prefix = "stc\n" if opname in {"adc", "sbb"} and index & 1 else "clc\n"
            add_matrix_case(f"phase1_reg{width}_{opname}_{index}",
                            f"{prefix}{opname}{suffix} {source}, {accumulator}", mask,
                            eax=high | value, ebx=high | other)
    for immediate in (-128, -1, 0, 1, 7, 127, 128, 0x1234):
        if width == 8 and not -128 <= immediate <= 0xff:
            continue
        immediate_name = f"neg{-immediate}" if immediate < 0 else f"pos{immediate}"
        for opname, mask in (("add", 0x8d5), ("sub", 0x8d5), ("cmp", 0x8d5),
                             ("and", 0x8c5), ("or", 0x8c5), ("xor", 0x8c5)):
            add_matrix_case(f"phase1_imm{width}_{opname}_{immediate_name}",
                            f"{opname}{suffix} ${immediate}, {accumulator}", mask,
                            eax=high | values[3])

MEMORY_WORDS = [0x807fff01, 0x12345678, 0x80000001, 0x7fffffff,
                0xaaaaaaaa, 0x55555555, 0x01020304, 0xfefdfcfb]
for width, suffix, source in ((8, "b", "%al"), (16, "w", "%ax"), (32, "l", "%eax")):
    for offset in (0, 1, 2, 3, 4, 7, 12, 16, 23):
        if offset + width // 8 > 32:
            continue
        for opname, mask in (("add", 0x8d5), ("sub", 0x8d5), ("cmp", 0x8d5),
                             ("and", 0x8c5), ("or", 0x8c5), ("xor", 0x8c5)):
            add_matrix_case(f"phase1_mem{width}_{opname}_off{offset}",
                            f"{opname}{suffix} {source}, {offset}(%esi)", mask,
                            eax=0x87654321, memory=MEMORY_WORDS, use_memory=True)
        add_matrix_case(f"phase1_mem{width}_load_off{offset}",
                        f"mov{suffix} {offset}(%esi), {source}", 0,
                        eax=0xa5a5a5a5, memory=MEMORY_WORDS, use_memory=True)

# Exercise ModR/M displacement and SIB encodings independently of arithmetic
# semantics. ECX is deliberately retained in the observed state.
for scale in (1, 2, 4, 8):
    for index in (0, 1, 2):
        for displacement in (0, 1, 4, 7):
            address = index * scale + displacement
            if address + 4 > 32:
                continue
            add_matrix_case(f"phase1_sib_load_s{scale}_i{index}_d{displacement}",
                            f"movl {displacement}(%esi,%ecx,{scale}), %eax", 0,
                            eax=0, ecx=index, memory=MEMORY_WORDS, use_memory=True)
            add_matrix_case(f"phase1_sib_store_s{scale}_i{index}_d{displacement}",
                            f"movl %eax, {displacement}(%esi,%ecx,{scale})", 0,
                            eax=0x6a5b4c3d, ecx=index, memory=MEMORY_WORDS, use_memory=True)

for relation, left, right in (
        ("eq", 7, 7), ("ne", 7, 8), ("signed_lt", 0xffffffff, 1),
        ("signed_ge", 1, 0xffffffff), ("unsigned_below", 1, 0xffffffff),
        ("unsigned_above", 0xffffffff, 1)):
    for branch in ("je", "jne", "jl", "jge", "jb", "ja"):
        add_matrix_case(f"phase1_branch_{relation}_{branch}",
                        f"cmpl %ebx, %eax\n{branch} 1f\n"
                        "movl $0x11111111, %edx\njmp 2f\n"
                        "1:\nmovl $0x22222222, %edx\n2:", 0x8d5,
                        eax=left, ebx=right)

for count in (0, 1, 2, 5):
    add_matrix_case(f"phase1_loop_{count}",
                    "xorl %eax, %eax\njecxz 2f\n1:\nincl %eax\nloop 1b\n2:",
                    0x8c5 if count == 0 else 0x8d5,
                    ecx=count)

add_matrix_case("phase1_call_ret", "call 1f\nmovl $0x2468ace0, %edx\njmp 2f\n"
                "1:\naddl $7, %eax\nretl\n2:", 0x8d5, eax=5)
add_matrix_case("phase1_nested_call_ret", "call 1f\njmp 3f\n1:\ncall 2f\nretl\n"
                "2:\nxorl $0x55aa55aa, %eax\nretl\n3:", 0x8c5, eax=0x12345678)
add_matrix_case("phase1_stack_push_pop", "pushl %eax\npushl %ebx\npopl %eax\npopl %ebx",
                0, eax=0x11223344, ebx=0xaabbccdd)
add_matrix_case("phase1_stack_flags", "pushfl\npopl %eax\npushl %eax\npopfl", 0x8d5,
                eax=0, eflags=0x8d7)
add_matrix_case("phase1_stack_pushad", "pushal\nxorl %eax, %eax\nxorl %ebx, %ebx\n"
                "xorl %ecx, %ecx\nxorl %edx, %edx\npopal", 0x8c5,
                eax=1, ebx=2, ecx=3, edx=4, esi=5, edi=6)

for width, suffix, values in (
        (8, "b", ((0x00ff, 2), (0x7f00, 0x7f), (0x8000, 0xff))),
        (16, "w", ((0x0000ffff, 2), (0x00007fff, 0x7fff), (0x00008000, 0xffff))),
        (32, "l", ((0xffffffff, 2), (0x7fffffff, 3), (0x80000000, 0xffffffff)))):
    for index, (value, multiplier) in enumerate(values):
        add_matrix_case(f"phase1_mul{width}_{index}", f"mul{suffix} "
                        f"{'%bl' if width == 8 else '%bx' if width == 16 else '%ebx'}",
                        0x801, eax=value, ebx=multiplier)
        add_matrix_case(f"phase1_imul{width}_{index}", f"imul{suffix} "
                        f"{'%bl' if width == 8 else '%bx' if width == 16 else '%ebx'}",
                        0x801, eax=value, ebx=multiplier)

for index, (eax, edx, divisor) in enumerate(((100, 0, 7), (0xffffffff, 0, 255),
                                              (0x80000000, 0, 65535))):
    add_matrix_case(f"phase1_div32_{index}", "divl %ebx", 0,
                    eax=eax, edx=edx, ebx=divisor)
for index, (eax, edx, divisor) in enumerate(((0xffffff9c, 0xffffffff, 7),
                                              (0x80000001, 0xffffffff, 0xffffffff),
                                              (0x7fffffff, 0, 0xffff))):
    add_matrix_case(f"phase1_idiv32_{index}", "idivl %ebx", 0,
                    eax=eax, edx=edx, ebx=divisor)
for immediate in (-128, -7, -1, 0, 1, 7, 127, 128, 0x1234):
    add_matrix_case(f"phase1_imul3_{immediate & 0xffff:x}",
                    f"imull ${immediate}, %ebx, %eax", 0x801,
                    eax=0xaaaaaaaa, ebx=0x13579bdf)

for width, suffix, register in ((8, "b", "%al"), (16, "w", "%ax")):
    for opname in ("rol", "ror", "rcl", "rcr", "shl", "shr", "sar"):
        for count in (0, 1, 2, 7, 8, 15, 16, 17, 31, 32, 33):
            normalized = count & 0x1f
            if normalized == 0:
                mask = 0x8d5
            elif opname in {"rol", "ror", "rcl", "rcr"}:
                mask = 0x801 if normalized == 1 else 0x001
            else:
                mask = 0x8c5 if normalized == 1 else 0x0c5
            add_matrix_case(f"phase1_shift{width}_{opname}_{count}",
                            f"movb ${count}, %cl\n{opname}{suffix} %cl, {register}", mask,
                            eax=0xa5a58081, eflags=0x203)
    for offset in (0, 1, 3, 7):
        add_matrix_case(f"phase1_shiftmem{width}_shl_off{offset}",
                        f"shl{suffix} $1, {offset}(%esi)", 0x8c5,
                        memory=MEMORY_WORDS, use_memory=True)
        add_matrix_case(f"phase1_shiftmem{width}_ror_off{offset}",
                        f"ror{suffix} $1, {offset}(%esi)", 0x801,
                        memory=MEMORY_WORDS, use_memory=True)

for opname in ("bt", "bts", "btr", "btc"):
    for bit in (0, 1, 7, 15, 16, 31, 32, 63):
        add_matrix_case(f"phase1_bitreg_{opname}_{bit}", f"{opname}l %ecx, %eax", 0x001,
                        eax=0x80000001, ecx=bit)
        add_matrix_case(f"phase1_bitmemreg_{opname}_{bit}",
                        f"{opname}l %ecx, (%esi)", 0x001, ecx=bit,
                        memory=MEMORY_WORDS, use_memory=True)

for width, suffix, source in ((8, "b", "%al"), (16, "w", "%ax"), (32, "l", "%eax")):
    for offset in (0, 1, 2, 3, 4, 7, 12, 15):
        add_matrix_case(f"phase1_atomic_xchg{width}_off{offset}",
                        f"xchg{suffix} {source}, {offset}(%esi)", 0,
                        eax=0x12345678, memory=MEMORY_WORDS, use_memory=True)
        add_matrix_case(f"phase1_atomic_xadd{width}_off{offset}",
                        f"lock xadd{suffix} {source}, {offset}(%esi)", 0x8d5,
                        eax=5, memory=MEMORY_WORDS, use_memory=True)
        add_matrix_case(f"phase1_atomic_cmpxchg{width}_off{offset}",
                        f"lock cmpxchg{suffix} "
                        f"{'%bl' if width == 8 else '%bx' if width == 16 else '%ebx'}, "
                        f"{offset}(%esi)", 0x8d5, eax=MEMORY_WORDS[0], ebx=9,
                        memory=MEMORY_WORDS, use_memory=True)

add_matrix_case("phase1_cmpxchg8b_success", "lock cmpxchg8b (%esi)", 0x040,
                eax=0x807fff01, edx=0x12345678, ebx=0x89abcdef, ecx=0x01234567,
                memory=MEMORY_WORDS, use_memory=True)
add_matrix_case("phase1_cmpxchg8b_failure", "lock cmpxchg8b 1(%esi)", 0x040,
                eax=0, edx=0, ebx=0x89abcdef, ecx=0x01234567,
                memory=MEMORY_WORDS, use_memory=True)

SIMD_CASES = (
    ("paddb", "paddb"), ("paddw", "paddw"), ("paddd", "paddd"),
    ("psubb", "psubb"), ("psubw", "psubw"), ("psubd", "psubd"),
    ("paddusb", "paddusb"), ("paddusw", "paddusw"),
    ("paddsb", "paddsb"), ("paddsw", "paddsw"),
    ("psubusb", "psubusb"), ("psubusw", "psubusw"),
    ("psubsb", "psubsb"), ("psubsw", "psubsw"),
    ("pand", "pand"), ("pandn", "pandn"), ("por", "por"), ("pxor", "pxor"),
    ("pcmpeqb", "pcmpeqb"), ("pcmpeqw", "pcmpeqw"), ("pcmpeqd", "pcmpeqd"),
    ("pcmpgtb", "pcmpgtb"), ("pcmpgtw", "pcmpgtw"), ("pcmpgtd", "pcmpgtd"),
    ("pminub", "pminub"), ("pmaxub", "pmaxub"),
    ("pminsw", "pminsw"), ("pmaxsw", "pmaxsw"),
    ("pavgb", "pavgb"), ("pavgw", "pavgw"),
    ("pmullw", "pmullw"), ("pmulhw", "pmulhw"), ("pmulhuw", "pmulhuw"),
    ("pmuludq", "pmuludq"), ("psadbw", "psadbw"),
    ("pabsb", "pabsb"), ("pabsw", "pabsw"), ("pabsd", "pabsd"),
    ("pminsb", "pminsb"), ("pmaxsb", "pmaxsb"),
    ("pminuw", "pminuw"), ("pmaxuw", "pmaxuw"),
    ("pminsd", "pminsd"), ("pmaxsd", "pmaxsd"),
    ("pminud", "pminud"), ("pmaxud", "pmaxud"),
    ("pmulld", "pmulld"),
)
for index, (name, instruction) in enumerate(SIMD_CASES):
    add_matrix_case(f"simd_{name}", f"{instruction} (%esi), %xmm0", 0,
                    memory=[0x80ff7f01, 0x7fff8001, 0xffffffff, 0x12345678,
                            0, 0, 0, 0],
                    xmm=[0x01ff807f, 0x80017fff, 0x00000002, 0x87654321], use_memory=True)


def assemble_cases(work):
    arrays = []
    for index, test in enumerate(CASES):
        source = work / f"case-{index}.s"
        obj = work / f"case-{index}.obj"
        raw = work / f"case-{index}.bin"
        source.write_text(".text\n.globl _probe\n_probe:\n" + test["asm"] + "\n", encoding="utf-8")
        subprocess.run([str(CLANG), "-target", "i686-w64-windows-gnu", "-c", str(source),
                        "-o", str(obj)], check=True)
        subprocess.run([str(OBJCOPY), "--dump-section", f".text={raw}", str(obj)], check=True)
        arrays.append(raw.read_bytes())
    header = work / "rosetta_i386_matrix_cases.h"
    lines = []
    for index, data in enumerate(arrays):
        lines.append(f"static const u8 matrix_code_{index}[] = {{{','.join(f'0x{x:02x}' for x in data)}}};")
    lines.append(f"#define MATRIX_CASE_COUNT {len(CASES)}U")
    lines.append("static const struct matrix_case matrix_cases[MATRIX_CASE_COUNT] = {")
    for index, test in enumerate(CASES):
        values = test["regs"] + test["xmm"]
        init = ",".join(f"0x{x & 0xffffffff:08x}U" for x in values)
        memory = ",".join(f"0x{x & 0xffffffff:08x}U" for x in test["memory"])
        lines.append(f'{{"{test["name"]}",matrix_code_{index},sizeof(matrix_code_{index}),'
                     f'{{{init}}},{{{memory}}},{1 if test["use_memory"] else 0}U}},')
    lines.append("};")
    header.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build(root, runtime, work):
    assemble_cases(work)
    fixture = root / "tests/fixtures"
    objects = []
    for name in ("rosetta_i386_matrix.c", "rosetta_i386_matrix.s"):
        obj = work / (name + ".obj")
        flags = ["-I", str(work)]
        if name.endswith(".c"):
            flags += ["-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-O2"]
        subprocess.run([str(CLANG), "-target", "i686-w64-windows-gnu", "-c",
                        str(fixture / name), *flags, "-o", str(obj)], check=True)
        objects.append(obj)
    exe = work / "rosetta-i386-matrix.exe"
    subprocess.run([str(LINK), "/machine:x86", "/subsystem:console", "/entry:start",
                    "/nodefaultlib", "/brepro", "/dynamicbase:no", "/nxcompat", "/safeseh:no",
                    f"/out:{exe}", *(str(x) for x in objects),
                    str(runtime / "lib/wine/i386-windows/libkernel32.a")], check=True)
    return exe


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--prefix", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--case-timeout", type=int, default=5)
    parser.add_argument("--isolated", action="store_true")
    parser.add_argument("--resume-evidence", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    work = args.work.resolve()
    resume_by_name = {}
    if args.resume_evidence:
        resume = json.loads(args.resume_evidence.read_text(encoding="utf-8"))
        resume_by_name = {row["name"]: row for row in resume["results"]
                          if row.get("record") is not None}
    if work.exists(): shutil.rmtree(work)
    work.mkdir(parents=True)
    runtime = args.runtime.resolve()
    exe = build(root, runtime, work)
    env = os.environ.copy()
    env.update({"WINEARCH": "win64", "WINEPREFIX": str(args.prefix.resolve()),
                "WINEDEBUG": "-all", "WINEDLLOVERRIDES": "winedbg.exe,winemenubuilder.exe,winevulkan=d;mscoree,mshtml=",
                "MVK_CONFIG_LOG_LEVEL": "0"})
    results = []
    started = time.monotonic()
    try:
        if not args.isolated:
            run = subprocess.run(["/usr/bin/arch", "-x86_64", str(runtime / "bin/wine"),
                                  str(exe), str(len(CASES))], env=env, capture_output=True,
                                 text=True, timeout=max(args.case_timeout, 30))
            records = [json.loads(x) for x in run.stdout.splitlines()
                       if x.startswith('{"schemaVersion"')]
            by_name = {record["name"]: record for record in records}
            for test in CASES:
                record = by_name.get(test["name"])
                results.append({"name": test["name"],
                                "definedFlagsMask": f'0x{test["defined_flags_mask"]:08x}',
                                "input": {"eax": test["regs"][0], "ebx": test["regs"][1],
                                          "ecx": test["regs"][2], "edx": test["regs"][3],
                                          "esi": test["regs"][4], "edi": test["regs"][5],
                                          "eflags": test["regs"][6], "memory": test["memory"],
                                          "xmm0": test["xmm"], "useMemoryEsi": test["use_memory"]},
                                "status": "ok" if record else "failed",
                                "exitCode": run.returncode, "record": record,
                                "stderr": run.stderr[-1000:] if not record else ""})
        else:
            for index, test in enumerate(CASES):
                if test["name"] in resume_by_name:
                    result = resume_by_name[test["name"]]
                    result["status"] = "ok"
                    results.append(result)
                    continue
                try:
                    run = subprocess.Popen(["/usr/bin/arch", "-x86_64", str(runtime / "bin/wine"),
                                            str(exe), str(index)], env=env, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, text=True, start_new_session=True)
                    stdout, stderr = run.communicate(timeout=args.case_timeout)
                    records = [json.loads(x) for x in stdout.splitlines()
                               if x.startswith('{"schemaVersion"')]
                    results.append({"name": test["name"],
                                    "definedFlagsMask": f'0x{test["defined_flags_mask"]:08x}',
                                    "input": {"eax": test["regs"][0], "ebx": test["regs"][1],
                                              "ecx": test["regs"][2], "edx": test["regs"][3],
                                              "esi": test["regs"][4], "edi": test["regs"][5],
                                              "eflags": test["regs"][6], "memory": test["memory"],
                                              "xmm0": test["xmm"], "useMemoryEsi": test["use_memory"]},
                                    "status": "ok" if run.returncode == 0 and len(records) == 1 else "failed",
                                    "exitCode": run.returncode,
                                    "record": records[0] if len(records) == 1 else None,
                                    "stderr": stderr[-1000:]})
                except subprocess.TimeoutExpired:
                    os.killpg(run.pid, signal.SIGKILL)
                    run.communicate()
                    subprocess.run(["/usr/bin/arch", "-x86_64", str(runtime / "bin/wineserver"), "-k"],
                                   env=env, timeout=10, check=False)
                    results.append({"name": test["name"], "status": "timeout"})
    finally:
        subprocess.run(["/usr/bin/arch", "-x86_64", str(runtime / "bin/wineserver"), "-k"],
                       env=env, timeout=10, check=False)
    evidence = {"schemaVersion": 1, "oracle": "Apple Rosetta 2 via MetalSharp Wine i386/WoW64",
                "fixtureSha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
                "elapsedMilliseconds": int((time.monotonic() - started) * 1000), "results": results}
    output = work / "rosetta-i386-matrix.json"
    output.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(output)


if __name__ == "__main__": main()
