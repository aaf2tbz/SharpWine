; SPDX-License-Identifier: Apache-2.0
; Deliberately constrained to Blink handlers already reviewed for Issue #14.
; The linked decoder evidence, not these source mnemonics, is authoritative.

        EXTERN fixture_roundtrip_arm_finish:PROC
        PUBLIC fixture_x64_roundtrip

_TEXT   SEGMENT
fixture_x64_roundtrip PROC
        mov     rax, rcx
        add     rax, 7
        mov     rcx, rax
        jmp     fixture_roundtrip_arm_finish
fixture_x64_roundtrip ENDP
_TEXT   ENDS
        END
