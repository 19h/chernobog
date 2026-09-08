/*
 * ARM64 macOS fixture.  Descriptor layout is four pointer-width slots:
 *   class-reference pointer; uint32 flags + uint32 padding; bytes; int64 length.
 * Store labels stay assembler-local to preserve one linker function extent.
 * cf_projection_store_offsets exports their uint32 function-relative offsets;
 * only L_cf_projection_store_alt_entry has an actual incoming branch.
 */

.section __TEXT,__text,regular,pure_instructions
.p2align 2
.globl _numeric_cfstring_fixture
_numeric_cfstring_fixture:
.cfi_startproc
    adrp x5, _cf_projection_key@PAGE
    add x5, x5, _cf_projection_key@PAGEOFF
    adrp x6, _cf_projection_encoded_one@PAGE
    add x6, x6, _cf_projection_encoded_one@PAGEOFF
    adrp x7, _cf_projection_output_one@PAGE
    add x7, x7, _cf_projection_output_one@PAGEOFF
    mov x8, #0
L_cf_projection_decode_one:
    ldrb w9, [x6, x8]
    ldrb w10, [x5]
    eor w9, w9, w10
    strb w9, [x7, x8]
    add x8, x8, #1
    cmp x8, #15
    b.ne L_cf_projection_decode_one

    adrp x6, _cf_projection_encoded_two@PAGE
    add x6, x6, _cf_projection_encoded_two@PAGEOFF
    adrp x7, _cf_projection_output_two@PAGE
    add x7, x7, _cf_projection_output_two@PAGEOFF
    mov x8, #0
L_cf_projection_decode_two:
    ldrb w9, [x6, x8]
    ldrb w10, [x5]
    eor w9, w9, w10
    strb w9, [x7, x8]
    add x8, x8, #1
    cmp x8, #15
    b.ne L_cf_projection_decode_two

    /* Writable pointer indirection keeps the ctree destination a memory lvalue. */
    adrp x11, _cf_projection_stores_ptr@PAGE
    ldr x11, [x11, _cf_projection_stores_ptr@PAGEOFF]

    adrp x8, _cf_projection_good_one@PAGE
    add x8, x8, _cf_projection_good_one@PAGEOFF
L_cf_projection_store_good_one:
    str x8, [x11, #0]

    adrp x8, _cf_projection_good_two@PAGE
    add x8, x8, _cf_projection_good_two@PAGEOFF
L_cf_projection_store_good_two:
    str x8, [x11, #8]

    adrp x8, _cf_projection_bad_flags@PAGE
    add x8, x8, _cf_projection_bad_flags@PAGEOFF
L_cf_projection_store_bad_flags:
    str x8, [x11, #16]

    adrp x8, _cf_projection_bad_length@PAGE
    add x8, x8, _cf_projection_bad_length@PAGEOFF
L_cf_projection_store_bad_length:
    str x8, [x11, #24]

    adrp x8, _cf_projection_bad_class@PAGE
    add x8, x8, _cf_projection_bad_class@PAGEOFF
L_cf_projection_store_bad_class:
    str x8, [x11, #32]

    adrp x8, _cf_projection_no_fact@PAGE
    add x8, x8, _cf_projection_no_fact@PAGEOFF
L_cf_projection_store_no_fact:
    str x8, [x11, #40]

    /* The MOV breaks the exact ADRP/ADD/STR native-origin sequence. */
    adrp x9, _cf_projection_good_one@PAGE
    add x9, x9, _cf_projection_good_one@PAGEOFF
    mov x8, x9
L_cf_projection_store_mov_only:
    str x8, [x11, #48]

    /* An address participates in arithmetic with a runtime memory value. */
    adrp x9, _cf_projection_delta@PAGE
    ldr x9, [x9, _cf_projection_delta@PAGEOFF]
    adrp x8, _cf_projection_good_one@PAGE
    add x8, x8, _cf_projection_good_one@PAGEOFF
    add x8, x8, x9
L_cf_projection_store_arithmetic:
    str x8, [x11, #56]

    /* Both paths retain the same address; the STR has a nonfallthrough xref. */
    adrp x9, _cf_projection_selector@PAGE
    ldr w0, [x9, _cf_projection_selector@PAGEOFF]
    adrp x8, _cf_projection_good_one@PAGE
    add x8, x8, _cf_projection_good_one@PAGEOFF
    cbnz w0, L_cf_projection_store_alt_entry
    adrp x8, _cf_projection_good_one@PAGE
    add x8, x8, _cf_projection_good_one@PAGEOFF
L_cf_projection_store_alt_entry:
    str x8, [x11, #64]

    /* Full-width address construction, explicitly narrowed memory store. */
    adrp x8, _cf_projection_good_one@PAGE
    add x8, x8, _cf_projection_good_one@PAGEOFF
L_cf_projection_store_narrow:
    str w8, [x11, #72]
    mov w0, #0
    ret
.cfi_endproc

.section __TEXT,__const
.p2align 3
.globl _cf_projection_encoded_one
_cf_projection_encoded_one:
    .byte 0x2a, 0x28, 0x35, 0x30, 0x3f, 0x39, 0x2e, 0x33
    .byte 0x35, 0x34, 0x77, 0x35, 0x34, 0x3f, 0x5a
.globl _cf_projection_encoded_two
_cf_projection_encoded_two:
    .byte 0x2a, 0x28, 0x35, 0x30, 0x3f, 0x39, 0x2e, 0x33
    .byte 0x35, 0x34, 0x77, 0x2e, 0x2d, 0x35, 0x5a
.globl _cf_projection_no_fact_bytes
_cf_projection_no_fact_bytes:
    .asciz "no-fact-string"

.section __DATA,__data
.p2align 3
.globl _cf_projection_key
_cf_projection_key:
    .byte 0x5a
.p2align 3
.globl _cf_projection_delta
_cf_projection_delta:
    .quad 0
.globl _cf_projection_selector
_cf_projection_selector:
    .long 0
.p2align 6
.globl _cf_projection_output_one
_cf_projection_output_one:
    .space 15, 0
.p2align 6
.globl _cf_projection_output_two
_cf_projection_output_two:
    .space 15, 0
.p2align 6
.globl _cf_projection_stores
_cf_projection_stores:
    .space 80, 0
.p2align 3
.globl _cf_projection_not_class
_cf_projection_not_class:
    .quad 0
.globl _cf_projection_stores_ptr
_cf_projection_stores_ptr:
    .quad _cf_projection_stores

/* Same ABI layout as a compiler-emitted ASCII constant-string header. */
.section __DATA,__const
.p2align 3
.globl _cf_projection_good_one
_cf_projection_good_one:
    .quad ___CFConstantStringClassReference
    .long 0x7c8
    .long 0
    .quad _cf_projection_output_one
    .quad 14
.globl _cf_projection_good_two
_cf_projection_good_two:
    .quad ___CFConstantStringClassReference
    .long 0x7c8
    .long 0
    .quad _cf_projection_output_two
    .quad 14
.globl _cf_projection_bad_flags
_cf_projection_bad_flags:
    .quad ___CFConstantStringClassReference
    .long 0x7d0
    .long 0
    .quad _cf_projection_output_one
    .quad 14
.globl _cf_projection_bad_length
_cf_projection_bad_length:
    .quad ___CFConstantStringClassReference
    .long 0x7c8
    .long 0
    .quad _cf_projection_output_one
    .quad 13
.globl _cf_projection_bad_class
_cf_projection_bad_class:
    .quad _cf_projection_not_class
    .long 0x7c8
    .long 0
    .quad _cf_projection_output_one
    .quad 14
.globl _cf_projection_no_fact
_cf_projection_no_fact:
    .quad ___CFConstantStringClassReference
    .long 0x7c8
    .long 0
    .quad _cf_projection_no_fact_bytes
    .quad 14

/* uint32 offsets into numeric_cfstring_fixture, in output-slot order. */
.p2align 2
.globl _cf_projection_store_offsets
_cf_projection_store_offsets:
    .long L_cf_projection_store_good_one - _numeric_cfstring_fixture
    .long L_cf_projection_store_good_two - _numeric_cfstring_fixture
    .long L_cf_projection_store_bad_flags - _numeric_cfstring_fixture
    .long L_cf_projection_store_bad_length - _numeric_cfstring_fixture
    .long L_cf_projection_store_bad_class - _numeric_cfstring_fixture
    .long L_cf_projection_store_no_fact - _numeric_cfstring_fixture
    .long L_cf_projection_store_mov_only - _numeric_cfstring_fixture
    .long L_cf_projection_store_arithmetic - _numeric_cfstring_fixture
    .long L_cf_projection_store_alt_entry - _numeric_cfstring_fixture
    .long L_cf_projection_store_narrow - _numeric_cfstring_fixture

.subsections_via_symbols
