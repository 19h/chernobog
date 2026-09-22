# AthenaTUBerlin → Chernobog mapping

This document records how the AthenaTUBerlin protector generates code, what
Chernobog already recovers, and which identities to implement next. It is a
working catalog for Chernobog handlers. It is not a license to copy protector
source into this tree.

AthenaTUBerlin is treated as a generator of exact transforms. Chernobog should
re-implement those identities in its own native analysis, MBA catalog, string
recovery, and (later) VM recognition. Do not import Athena headers, cryptor
classes, the loader, or the VM interpreter.

Status as of 2026-09-20: mapping only. No Athena-specific handler is in
Chernobog yet.

Implementation status below describes that baseline. Subsequent verified
changes and remaining work are tracked in `VMP_IMPLEMENTATION.md`; corrected
identities and instruction widths in this document supersede the original
mapping's erroneous examples.

---

## 1. Two products

AthenaTUBerlin is a native/.NET software protector. It mutates x86/x64
instructions, virtualizes selected functions onto an embedded stack RISC
machine, encrypts imports and strings, packs the image, and optionally binds
code to a serial number. Compilation is per object: mutation, virtualization,
or Ultra (mutate, then virtualize). Multiple virtual machines with different
register assignments and opcode cryptors can protect different fragments of the
same binary.

Chernobog is a Hex-Rays plugin that defeats Hikari LLVM obfuscation. Its
pipeline is:

1. Native IDA analysis (`src/ida_analysis/`) before lifting: redundant
   prefixes, call/pop get-PC, `push imm; ret`, locally known CF/ZF, entry
   predicates, opposite branch pairs.
2. Opt-in AArch64 native opaque-predicate patching
   (`src/deobf/handlers/native_opaque.cpp`).
3. Hex-Rays microcode handlers (`src/deobf/handlers/`) keyed by `obf_type_t`.
4. A Z3-certified MBA catalog of 108 rules (`src/deobf/rules/`).
5. Bounded current-function rax emulation (`src/hybrid/`, `RAX_HYBRID.md`).

Athena is x86/x64-first (PE, ELF, Mach-O, plus .NET IL). Chernobog’s product
surface is Hikari on AArch64/x86 with ObjC. The overlap that is worth
implementing is the set of **identities** Athena emits that Chernobog’s
existing machinery can consume: CFG idioms, flag-known predicates, NOR/NAND
MBA, and a closed-form string keystream. Full Athena VM lifting is a separate
handler family, not an extension of `vm_mba`.

---

## 2. Athena protection surface

### 2.1 Per-function compilation types

| Mode | Generator behaviour | Performance | Analysis difficulty |
|---|---|---|---|
| Mutation | Substitute instructions, insert garbage on free registers, rewrite some transfers | High | Low if CFG is intact; currently Chernobog leaves CFG broken |
| Virtualization | Translate native ops to stack RISC bytecode, embed an interpreter | Medium | High: unknown ISA, encrypted opcodes, cloned handlers |
| Ultra | Mutate, then virtualize the mutated stream | Low | Highest: VM handlers themselves are mutated |

Mutation exists to break signatures (PEiD, FLIRT), not to be cryptographically
hard. Virtualization is the real barrier. Ultra exists so that a recovered VM
handler still looks like mutated native code.

### 2.2 Whole-file options

These wrap the mutated/virtualized functions. They matter for IDB recovery
more than for Hex-Rays rewrites.

| Option | Effect | Chernobog relevance |
|---|---|---|
| Memory protection | CRC of non-writable sections before OEP | Out of decompiler scope; rax will fault or stop on CRC helpers |
| Import protection | Hide API names; runtime resolver writes IAT | Native xrefs / rax call summaries |
| Resource protection | Encrypt resources except icons/manifests | Not a decompiler problem |
| Pack output | In-memory unpack; OEP may itself be virtualized | Unpack is a loader problem; virtualized OEP is the VM problem |
| Debugger / hypervisor detection | Abort before OEP | Ignore |
| Watermarks | Per-license byte patterns in VM segments | Ignore |
| VM segment names | Default `.athenatuberlin`, user-renameable | Detection heuristic only; do not require the default name |
| Strip relocations / debug | Reloc space reused for VM | Affects image layout |
| Lock to serial | Virtualized fragment XORs immediates with session/product key | VM immediates are not plain constants |

### 2.3 Platforms Athena emits

- Windows PE 32/64, including SYS
- macOS Mach-O 32/64
- Linux ELF (core has ELF support)
- .NET IL virtualization (separate compiler path)

Chernobog only sees native Hex-Rays input. .NET IL virtualization is out of
scope.

---

## 3. Mutation engine

Mutation runs in two layers. The first is a cheap per-instruction rewrite plus
garbage. The second (`IntelObfuscation`) is a stack machine that can replace a
whole function. Ultra runs the first layer with `for_virtualization=true`
before bytecode lowering; the second layer also runs on VM *gates* and, when
enabled, on the VM processor itself.

### 3.1 Exact substitutions

Applied when the original instruction is compilable and a coin flip succeeds.
Flag-liveness is checked against free registers: `add`/`sub` → `lea` only if
the flags the original would write are dead.

| Original | Mutated | Conditions | Chernobog today |
|---|---|---|---|
| `xor r, r` | `sub r, r` | Same register both operands | Hex-Rays already treats both as zeroing; no handler needed |
| `add r, x` | `lea r, [r+x]` | Address-size register dest; `x` is register ≠ ESP or an imm on 32-bit; flags dead | No dedicated fold; Hex-Rays usually recovers `r+x` |
| `sub r, imm` | `lea r, [r-imm]` | Same, 32-bit only | Same |
| `jmp r/m` | `push r/m; ret` | Not far, not an immediate, not for-virtualization | **Gap.** `handle_push_return` only accepts `push imm; ret` |
| `call $+0` (call next) | 32-bit: `push next`. 64-bit: `push rax; lea rax, [next]; xchg [rsp], rax` | Direct near call whose target equals the next IP | Partial. `handle_call_pop` wants a later pop/discard gadget, not a push-next rewrite |
| `jcxz` / `loop` / `loope` / `loopne` | Expanded into extra `jmp` blocks so the short form is gone | Native mutation only | No expander-inverse |
| Far/invalid/`int3`-like | Forced back to native encoding | — | Irrelevant |

The important CFG break is **`push r/m; ret`**. Chernobog’s native engine
(`src/ida_analysis/native_engine.cpp`, `handle_push_return`) requires
`NN_push` with `o_imm`, then a return. Athena’s mutation uses a register or
memory operand. IDA therefore keeps an indirect return and does not add the
code xref to the true target.

### 3.2 Garbage insertion

After each real instruction that does not write EIP, the generator inserts
0–3 junk instructions chosen from a template list, instantiated with free
registers. Templates include:

- `mov` / `movsx` / `movzx` / `movsxd`
- `not`, `neg`, `inc`, `dec`
- `cmp`, `test`, `and`, `or`, `xor`, `add`, `adc`, `sub`
- `shl`/`shr`/`sal`/`sar`/`rol`/`ror` by `cl` or imm8
- `shld`/`shrd`, `bt`/`btc`/`btr`/`bts`
- `setcc`, `cmovcc` with a random condition
- `clc`/`stc`/`cmc`, `cbw`/`cwde`/`cwd`/`cdq`/`cdqe`/`cqo`, `lahf`, `bswap`
- `xchg`, `xadd`
- unconditional `jmp` (to a later real instruction, as padding)

When **not** mutating for virtualization, the list also includes `sbb`,
`rcl`/`rcr`, `bsr`/`bsf`, `rdtsc`.

Garbage is constrained so it only writes registers (or flags) that are free
until the next real use. It is semantically dead. Hex-Rays will often delete
it **if** the CFG is a single graph. It will not delete it if opaque `jcc`s
from the second layer split the function.

### 3.3 Implementation target (mutation CFG)

File: `src/ida_analysis/native_engine.cpp`, next to `handle_push_return` and
`handle_call_pop`.

Required recognizers:

1. **`push r/m; ret`**
   - `NN_push` of `o_reg` or `o_mem`/`o_displ`/`o_phrase`.
   - Immediate next instruction is a near `ret` (not `retn imm` unless the
     immediate is 0).
   - Target is not a constant, so this handler **cannot** add a code xref by
     itself. It should still:
     - mark the pair as a tail transfer, not a call/return,
     - prevent IDA from treating the `ret` as a function terminator when the
       push is of a computed address that rax later resolves,
     - accept a later exact target from rax evidence (`indirect_control`
       observations) and then add the xref the same way `handle_push_return`
       does for immediates.
   - When the pushed value *is* a constant recovered by the register tracker
     (`CHERNOBOG_IDA_REGISTER_SCAN_DEPTH`), add the xref immediately.

2. **`call next` rewritten as push**
   - 32-bit: `push imm` whose value equals the next IP, no corresponding
     call. Already almost `handle_push_return` if a `ret` follows; as a
     get-PC it is `push next` without `ret`. Annotate as get-PC / return
     address materialization.
   - 64-bit triple `push rax; lea rax, [next]; xchg [rsp], rax`. This is a
     new get-PC form for `classify_ida_get_pc_call` /
     `src/ida_analysis/get_pc_ida.cpp`.

3. **`ret n` after a matching `call` used as jmp**
   - See §4.3. Native analysis should not create a function boundary on that
     `ret`.

Config flags: reuse `CHERNOBOG_IDA_PUSH_RET` and `CHERNOBOG_IDA_CALL_POP`.
Do not add an Athena-named option. These idioms are not Athena-only.

Tests: a tiny x86-64 NASM/GAS fixture with `push rax; ret` to a known label,
and the 64-bit push/lea/xchg triple. Follow `tests/ida_native_prefix_gate_smoke.py`
and `tests/NATIVE_PREFIX_GATE.md` for the IDA smoke shape.

---

## 4. Stack-machine obfuscation

The second native layer is a local abstract machine:

- A software stack of tagged slots: register snapshot, immediate, flags
  (`EFX`), return address.
- A register-value store for slots whose concrete value is known.
- A flags object that records which of CF/ZF/SF/OF/PF are known and their
  values.

For every original instruction it:

1. Runs 30–39 random-command generator iterations (`AddRandomCommands`);
   the number of emitted native instructions is not fixed by that count.
2. If the original is `push`/`pop`/`pushf`/`call`/`ret`/`jmp`/`jcc`, rewrites
   it against the software stack (memory via `[esp+k]` instead of `push`/`pop`,
   restore-on-demand of overwritten slots).
3. Swaps the original with the first junk instruction when the original is a
   block entry, so xrefs land on junk.
4. Fixes up `jcc` targets after the whole stream is emitted.

### 4.1 Random command vocabulary

Weighted toward stack motion and flag-using control flow:

- `push` register or random imm32 (sign-extended)
- `pop` (actually restore-and-shrink the software stack)
- `call` used as a jump (`roUseAsJmp`) with a later matching `ret` / `ret n`
- `lea`, `mov`, `movsx`, `movzx`, `bswap`, width converters
- Arithmetic and logic on a random stack slot or a known-value register
- `bt*`
- If any flags are known: several `jcc`s, `setcc`, `cmov`, and if CF is known
  `clc`/`stc`/`cmc`, `adc`, `sbb`

Each arithmetic op is applied to the abstract value so later `jcc`/`cmov`/
`setcc` can be emitted with a condition that is **known true or known false**.

### 4.2 Opaque `jcc` / `cmov` / `setcc`

When flags are known:

- Pick a random subset of known flags as the condition.
- Randomly invert the condition (`roInverseFlag`).
- If the concrete flag state matches the (possibly inverted) condition, mark
  the `jcc` as `roUseAsJmp` (always taken). Otherwise it is never taken, and
  the link is pointed at a **random** later instruction so static analysis
  sees a plausible but dead edge.

This is stronger than Chernobog’s current x86 flag handler.

Chernobog today (`handle_known_x86_flag`):

- Architectures: x86 only.
- Instructions: `jb`/`jnb`/`jbe`/`ja`/`jz`/`jnz`/`jle`/`jnle` only.
- Flags: CF then ZF, scanned at most `CHERNOBOG_IDA_FLAG_SCAN_DEPTH` (default 8)
  instructions backward.
- Effect: replace generated code edges with the proven taken/fallthrough edge,
  retype the dead gap as bytes, comment `always/never taken (locally known CF/ZF)`.

Gaps versus Athena:

| Athena emits | Chernobog |
|---|---|
| Any `jcc` (JS, JO, JP, JL, …) | Only CF/ZF family |
| `cmovcc` with known flags | Not handled |
| `setcc` with known flags | Not handled |
| OF/SF/PF | Not scanned |
| Flag state from `clc`/`stc`/`cmc` plus later `adc`/`sbb` | Baseline CF scan may catch `clc`/`stc` within its 8-instruction window; generated sequences can exceed that window |
| Always-taken `jcc` marked as a jmp (`roUseAsJmp`) | Edge replacement exists; the junk volume exceeds scan depth |
| Never-taken `jcc` with a **random** target | IDA keeps a real xref to an unrelated block; Chernobog will not delete it without a proof |

`native_opaque_handler_t` is AArch64-only and patches `B.cond`/`CBZ`/`CBNZ`
to `B`/`NOP` with original bytes retained. It does not run on x86.

`jump_optimizer` / `rules_predicate` operate on Hex-Rays microcode after
lift. They will never see the native opaque `jcc` if IDA split the function
or if the condition is a live flag IDA cannot constant-fold.

### 4.3 Bogus call / ret pairs

The generator pushes a return-address slot, emits `call` with `roUseAsJmp`
(the call is a jump to the next junk instruction), later finds that slot, and
emits either:

- `add [esp+k], random; ret` on the first encounter (the add’s immediate is a
  reloc/`ltDelta` to the real continuation, minus 5), or
- `ret n` that also drops unused stack slots.

Net effect: the original control transfer is a `call`/`ret` pair whose
apparent target is junk and whose real continuation is `ret_addr + delta`.
IDA creates extra functions on the `ret` and loses the fallthrough.

Chernobog’s get-PC classifier handles `call` + `pop`/`add esp` discard. It
does not handle `call`-as-jmp with a later `add [esp+k], delta; ret`.

### 4.4 Address-generation noise

When emitting a memory operand, the generator may rewrite

```text
[base + disp]
```

into

```text
[base + reg*scale + (disp - known(reg)<<scale)]
```

using a register whose concrete value is in the register-value store. The
effective address is unchanged. Hex-Rays often keeps the scaled form. This
is already in the spirit of Chernobog’s constant folding / `lea` recovery;
worth a peephole only if it survives to microcode as a non-constant index.

### 4.5 Implementation target (opaque x86)

Two layers, both required:

**Native, before lift** — extend `handle_known_x86_flag`:

- All `jcc` types IDA reports (`NN_js`, `NN_jo`, `NN_jp`, `NN_jl`, …).
- `NN_cmovcc` and `NN_setcc` with the same flag analysis: SETcc writes a byte
  on both outcomes (1 when true, 0 when false). Never replace a false SETcc
  with NOP. CMOVcc needs separate handling of memory access/exception behavior
  and partial-register effects; a false condition alone does not justify NOP.
- Scan through dead arithmetic that does not write the consulted flag, or
  raise `CHERNOBOG_IDA_FLAG_SCAN_DEPTH` for this path. Sequences from 30–39
  generator iterations can exceed depth 8. The scan
  must classify writers: `clc`/`stc`/`cmc` define CF; `cmp`/`test`/`add`/…
  define the full set; `inc`/`dec` leave CF.

**Microcode, after lift** — `native_opaque` analogue for x86 is the wrong
abstraction (it patches native bytes). Prefer `jump_optimizer` plus a small
`cmov`/`setcc` peephole once the native pass has restored a single CFG.
Z3 is already used for opaque jumps (`OBF_OPAQUE_JUMP`).

Always-taken `jcc` with `roUseAsJmp` should become an unconditional edge
before deflattening. Never-taken `jcc` with a random target should drop that
xref; leaving it creates false blocks that poison CFF recovery.

---

## 5. NOR/NAND MBA from the VM lowering

The Athena VM is a stack RISC. Native AND/OR/NOT/flag extract are lowered
through NOR and NAND, with a coin flip choosing which operator is used for
the self-inverse step. Hex-Rays has no `m_nor`/`m_nand`; the same identities
appear as `bnot(bor(...))` and `bnot(band(...))`.

### 5.1 Primitive encodings

Let `NOR(a,b) = ~(a | b)` and `NAND(a,b) = ~(a & b)`.

**NOT x**

```text
NOR(x, x)   = ~(x | x) = ~x
NAND(x, x)  = ~(x & x) = ~x
```

**x AND c** (two variants)

Variant A — invert x, then NOR with `~c`:

```text
t = NOR(x, x)        ; or NAND(x, x)   →  ~x
r = NOR(t, ~c)       ;                 →  ~(~x | ~c) = x & c
```

Variant B — NAND, then invert:

```text
t = NAND(x, c)       ; → ~(x & c)
r = NOR(t, t)        ; or NAND(t, t)  →  x & c
```

The invert of `t` is implemented as a stack peek: `push esp; push [ss:esp];
NOR/NAND`, i.e. NOR/NAND a value with itself without a named temporary.

**x OR c**

```text
t = NOR(x, c)        ; → ~(x | c)
r = NOR(t, t)        ; or NAND(t, t)  →  x | c
```

**x XOR y** is not a primitive. It is built from AND/OR/NOT of those forms
when the native instruction was `xor`. After lift this is ordinary MBA.

### 5.2 Flag extract and conditional VM jumps

Flags live in a VM register `EFX`. Extracting a condition:

- One-bit flag: `NOR(EFX, ~mask)` isolates the bit; optional prior
  `NOR(EFX,EFX)` inverts (for `jnz` vs `jz`).
- Multi-bit (SF^OF for `jl`, etc.): isolate each bit, NOR/NAND-invert, NOR
  together, then invert if needed.
- Shift the isolated bit to bit 0 or to a stack-slot selector.

Conditional VM goto (non-demo):

```text
idx = cond + (-1)           ; 0 if taken, -1 if not  (or the reverse)
fall = dest0 AND NOT idx    ; NAND/NOR forms
taken = dest1 AND idx
goto (fall + taken + ERX)   ; ERX is the VM instruction pointer / handler base
```

That is a select of two linked immediates through NAND/NOR, then an add of
the handler base. After MBA simplification it should become a normal `jcc`.

### 5.3 What the catalog already covers

Existing rules that fire **after** Hex-Rays folds `x|x` / `x&x` / `~~x`:

| After local folds | Existing rule |
|---|---|
| `~(~x \| ~y)` → `x & y` | `And_HackersDelightRule_3` |
| `~(~x & ~y)` → `x \| y` | `Or_MbaRule_1` |
| `~~x` → `x` | `Bnot_HackersDelightRule_1` |
| `x \| x` → `x` | `Const_OrSelf` |
| `x & x` → `x` | `Const_AndSelf` |

So Variant B of AND, and OR-via-NOR-then-invert, often collapse for register
operands. They do **not** collapse when:

- operands are stack-memory (`[esp+k]`),
- widths differ (byte NAND feeding a dword invert),
- the inverted immediate is not recognised as `~c` (e.g. `NOR(t, 0xFFFFFF00)`
  for a byte mask),
- `x|x` is a memory-memory form Hex-Rays will not fold.

### 5.4 Rules to add

Add these as ordinary `PatternMatchingRule`s, Z3-certified at 8/16/32/64,
registered next to the AND/OR/BNOT groups. Names should describe the
identity, not Athena.

The useful new shapes, written in catalog AST, each with the commutative
matcher’s usual operand swap:

1. `bnot(bor(x_0(), x_0()))` → `bnot(x_0())`
2. `bnot(band(x_0(), x_0()))` → `bnot(x_0())`
3. `bnot(bor(bnot(x_0()), bnot(x_1())))` → `band(x_0(), x_1())`
   (already `And_HackersDelightRule_3` — keep; ensure constants bind as `x_1`)
4. `bnot(bor(bnot(x_0()), c_1()))` → `band(x_0(), bnot(c_1()))`
   (constant-right form of 3; needed if `c_1` is not matched as a variable)
5. `bnot(band(bnot(x_0()), bnot(x_1())))` → `bor(x_0(), x_1())`
   (already `Or_MbaRule_1`)
6. Select via mask: `add(band(a, k), band(b, bnot(k)))` with `k` in `{0, ~0}`
   after the `cond + (-1)` lowering. If `k` is not constant, this is a
   multiplex; do not rewrite unless Z3 proves `k` is all-zero or all-one.

Files:

- `src/deobf/rules/rules_and.h` / `rules_or.h` / `rules_misc.h`
- register in the matching `rules_*.cpp`
- certification: `tests/catalog_tests.cpp` via the existing harness
  (`tests/CATALOG_HARNESS.md`). UNKNOWN remains a rejected rule.

Do not special-case Athena. These identities show up in any NOR/NAND VM.

### 5.5 Carry into `vm_mba`

`vm_mba_handler_t` (`src/deobf/handlers/vm_mba.cpp`) is for tail-call-threaded
handlers named `prog_bb_<digits>` with SSE unpack and a bytecode-read /
IP-advance structure. Athena handlers are **not** that family:

- Athena: one interpreter, many opcode handlers, stack RISC, optional
  cloned bodies, register permutation.
- `vm_mba`: many functions, each a micro-op, threaded via A2, SSE packing.

Do not extend `vm_mba` detection to Athena. If Athena VM recognition is
built later, it is a new `obf_type_t` and handler.

---

## 6. String encryption

Two distinct schemes share a keystream. Chernobog’s Hikari path (XOR with a
constant, bitwise NOT, `EncryptedString*` names) matches neither.

### 6.1 Keystream

For byte index `i` and 32-bit key `k`:

```text
ks8(i)  = uint8( rol32(k, i) + i )
ks16(i) = uint16( rol32(k, i) + i )
```

`rol32(k, i)` uses `i` as the rotate count (mod 32). The add is 32-bit, then
truncated.

ANSI: `out[i] = in[i] XOR ks8(i)`, including the terminating NUL.

UTF-16: `out[i] = in[i] XOR ks16(i)`, including the terminating 0.

This is used for:

- loader messages (`sice.sys`, `MessageBoxW`, debugger/VM/corruption text),
- import DLL and API names when import protection is on (§7),
- runtime `StringManager` payloads (§6.2).

### 6.2 Runtime string table

Layout at a data pointer `data`, instance base `image`, key `k`:

```text
STRING_DIRECTORY { uint32 NumberOfEntries XOR k }
STRING_ENTRY[n]  { uint32 Id XOR k, OffsetToData XOR k, Size XOR k }
payload bytes at image + OffsetToData, encrypted with the keystream
```

Lookup: the argument to `DecryptString` is treated as `id = str - image` when
the high bit is clear; binary search by decrypted `Id`. First use decrypts
into a heap buffer; `FreeString` refcounts and zeroizes.

Public exports: `ExportedDecryptString` / `ExportedFreeString` (and the SDK
wrappers). Chernobog’s rax call-summary table should model these as “returns
a pointer to a decrypted C or UTF-16 string of Size bytes” once the table is
known.

### 6.3 Implementation target (strings)

Microcode / ctree, next to `string_decrypt` and `ctree_string_decrypt`:

1. **Closed-form recoverer.** Given a buffer and a candidate 32-bit key,
   apply the keystream and require a NUL-terminated admissible UTF-8 or
   UTF-16 payload (reuse `chernobog::string_recovery`). Keys can come from:
   - a nearby 32-bit immediate,
   - a load from a known key slot,
   - brute force of 32-bit keys only when the ciphertext length is small
     and the plaintext constraint is strong (do not brute 2^32).
2. **Table recognizer.** `NumberOfEntries XOR k` becomes a small integer
   `n`; `n` entries of 12 bytes each XOR the same `k` produce increasing
   `Id`s and in-image `OffsetToData`. Once `k` is found, decrypt every
   payload and annotate.
3. **Call-site materialization.** If rax or microcode sees a call to a
   decrypt helper with `id = arg - image`, replace the use with a transient
   literal the same way runtime UTF-8 consensus works today
   (`RAX_HYBRID.md` category 4). Fail closed on conflicts.

Hikari `EncryptedString*` detection stays. This is an additional kind in
`static_write_kind_t` or a sibling of it, not a replacement.

Tests: a C fixture that encrypts `"Hello"` with a known key using the
keystream, linked so IDA smoke can see the buffer. Follow
`tests/runtime_strings/` and `tests/RUNTIME_UTF8.md`.

---

## 7. Import protection

When enabled, original IAT names for protected DLLs are replaced. The loader
carries **encrypted** DLL and API name strings (same keystream as §6.1) and
resolves them at startup into a new IAT. Only one plaintext API name per DLL
may remain as a native import to bootstrap `GetProcAddress`.

Loader runtime (`runtime/loader.cc`) walks an `IAT_INFO` array after unpack
and writes resolved pointers.

Chernobog should not rewrite the IAT in the file. It should:

- decrypt the loader name blobs with §6,
- add IDB comments / dummy names on the IAT slots,
- feed resolved names into rax call summaries so later evidence is typed.

This is native metadata plus rax, not a Hex-Rays handler. Evidence apply
already has `data_references`, `strings`, `comments`, `function_recovery`
(`src/ida_analysis/analysis_config.hpp`, `evidence_apply.cpp`).

---

## 8. Virtual machine

### 8.1 ISA

Stack RISC. Bytecode is a stream of opcodes plus immediates. Forward or
backward (`backward_direction_` is a coin flip per VM).

Virtual registers (in addition to a permutation of the native GPRs):

| Name | Role |
|---|---|
| `EFX` | flags |
| `ETX` / `ERX` / `EIX` | temporaries (extract, IP/handler base, index) |
| `Empty` | discard (pop to nowhere) |
| stack register | VM stack pointer (native GPR, random among EBX/EBP/ESI/EDI/R8–R15) |
| pcode register | bytecode pointer (same pool) |
| jmp register | Advanced dispatch only: handler-table pointer |
| crypt register | rolling opcode key when bytecode encryption is on |

Native GPRs are pushed in a **per-VM shuffled order** at entry and popped in
that order at handler boundaries (`registr_order_`). Handler identification
cannot assume a fixed push order.

Bytecode primitives used for ordinary integer code:

- `push` register / immediate / memory
- `pop` register / memory / discard
- `add` (stack binary)
- `nor`, `nand`
- `shl`, `shr`
- `jmp`, `call`
- `crc` (memory protection)
- section begin/end (context save/restore around a native instruction)

FPU, SIMD, string ops, and privileged ops have dedicated handlers; they are
not NOR/NAND-lowered.

### 8.2 Two dispatch styles

`VirtualMachineType`:

**Classic (`vtClassic`).** Opcode byte (or encrypted byte) selects a handler.
End of handler is a direct `jmp` to the next-opcode fetch.

**Advanced (`vtAdvanced`).** After the handler, read an encrypted dword from
pcode, sign-extend on 64-bit, add it to `jmp_registr_`, jump there. Handler
successors are relative and encrypted. This is the harder recovery: the
handler graph is not a switch on a byte.

Demo/unregistered builds pin VM GPRs (`ESI` pcode, `EBP` stack, `EBX` crypt,
`EDI`/`R11` jmp). Registered builds pick them at random from the work set,
excluding `R12–R15` on x64 (unwind / calling convention).

### 8.3 Opcode and value cryptors

A `ValueCryptor` is a random chain of 4–100 invertible ops, stopping after at
least 4 ops with 50% probability, hard-capped at 100. Ops are from:

```text
add, sub, xor, inc, dec, bswap, rol, ror, not, neg
```

Constraints: no two identical ops in a row; no adjacent add-family
(`add`/`sub`/`inc`/`dec`); no adjacent rotates; `bswap` not on 8/16-bit.

Encrypt is the chain forward; decrypt is the inverse chain backward
(`add`↔`sub`, `rol`↔`ror`, `inc`↔`dec`; `xor`/`not`/`neg`/`bswap` are
involutions).

An `OpcodeCryptor` is a `ValueCryptor` plus a binary combiner currently
hard-wired to **XOR** of the two inputs, then the chain. Opcode fetch:

```text
; forward pcode
movzx tmp, [pcode]
add   pcode, size
tmp  = tmp OP crypt_reg          ; OP is xor (currently)
tmp  = ValueCryptor.decrypt(tmp)
crypt_reg = crypt_reg OP tmp     ; rolling key
```

Backward pcode subtracts first, then loads. Rolling the crypt register means
opcode decryption is sequential; you cannot decode a random offset without
replaying from a known point (section begin, or VM entry after
`entry_cryptor_`).

`entry_cryptor_` decrypts the pushed VM IP at the gate before adding the
image base.

Section cryptors wrap a native-instruction translation so that register
context pushed at the beginning is encrypted until the matching end.

### 8.4 Handler cloning

`CloneHandler` duplicates an existing handler body and retargets internal
jumps. The same opcode can therefore have several native bodies. Structural
hashing for handler identification must be clone-tolerant (normalize
addresses, keep opcode semantics).

### 8.5 VM entry gate

A virtualized call does not jump to the original bytes. A **gate** is
emitted:

```text
push  encrypted_vm_ip          ; ltJmp, entry_cryptor
call  vm_entry                 ; roUseAsJmp, ltCall
```

On matching bitness, the gate itself may be passed through the stack-machine
obfuscator (§4). A short gate is a plain `jmp`.

Recognition:

- `push imm; call rel` where the call target is a function that (a) pushes
  all GPRs in some order, (b) loads pcode from `[esp+k]`, (c) runs a small
  cryptor chain on that value, (d) falls into an opcode fetch.
- The pushed immediate decrypts with the same cryptor to an in-image
  bytecode address.

This is the Athena analogue of Hikari’s dispatch wrappers. It belongs in
native analysis / a new handler, not `hikari_wrapper`.

### 8.6 Multiple VMs per binary

Different fragments can use different VMs (different GPR assignment, cryptor
chain, Classic vs Advanced, direction). A single global interpreter
assumption is wrong. Identify VMs by their entry command / processor
function, then attach each gate to one VM.

### 8.7 Ultra and mutated interpreters

Ultra mutates the native stream *before* lowering, so bytecode semantics are
those of the mutated instructions (`lea` instead of `add`, `push; ret`
instead of `jmp`, etc.). Recovering Ultra bytecode to *original* source
requires running the mutation inverse on the lifted RISC, or accepting
mutated native as the recovered form.

The VM processor (interpreter) can itself be obfuscated with §4. Handler
bodies then contain opaque `jcc`s and bogus call/ret. Slice 1–3 of §11 are
prerequisites for VM recognition.

### 8.8 What VM recovery would look like in Chernobog

A later handler family, not in the first slice:

1. Find gates (§8.5) and VM entries (§8.2).
2. Replay opcode fetch symbolically (pcode ± size, rolling cryptor) to
   recover the opcode stream. rax is allowed: one worker, current function
   only, no callee sweep — but the “current function” for a VM is the
   interpreter, which is the wrong grain. VM recovery almost certainly
   needs a dedicated explorer that snapshots bytecode and steps handlers,
   still without a database-wide emu job.
3. Classify handlers by effect on the VM stack (push imm, nor, add, …)
   using the same micro-op summary idea as `vm_mba_handler_t::micro_op_t`,
   but keyed by opcode value, not by `prog_bb_*` name.
4. Lift bytecode to a RISC trace, apply NOR/NAND MBA (§5), emit microcode
   or ctree for the original function.
5. Fail closed on `coLockToKey` immediates (session key / product code
   mixed in via `xadd` on pushes). Those constants are not recoverable
   from the binary alone.

This is a project, not a patch. Do not start it until mutation-only samples
decompile cleanly.

---

## 9. Chernobog coverage matrix

| Athena emit | Chernobog site | Status |
|---|---|---|
| `xor r,r` → `sub r,r` | Hex-Rays | Covered |
| `add`/`sub` → `lea` | Hex-Rays | Usually covered |
| `jmp r/m` → `push r/m; ret` | `handle_push_return` | **Gap** (imm only) |
| `call $+0` → push next / lea+xchg | `handle_call_pop` | **Gap** |
| `jcxz`/`loop*` expansion | — | Low priority |
| Dead garbage on free regs | Hex-Rays DCE | Covered if CFG is whole |
| Opaque `jcc` from known CF/ZF, depth ≤ 8 | `handle_known_x86_flag` | Partial |
| Opaque `jcc` OF/SF/PF, depth ≫ 8 | — | **Gap** |
| Opaque `cmov`/`setcc` | — | **Gap** |
| Never-taken `jcc` to random target | — | **Gap** |
| Bogus `call`/`ret n` / `add [esp+k], delta` | get-PC classifier | **Gap** |
| Scaled-index EA noise | const fold | Partial |
| NOR/NAND after `x\|x` fold | AND/OR/BNOT catalog | Partial |
| NOR/NAND on stack slots, inverted imm | catalog | **Gap** |
| Hikari XOR/NOT strings | `string_decrypt` | Covered, different scheme |
| `rol32(k,i)+i` strings | — | **Gap** |
| `StringManager` table | — | **Gap** |
| Encrypted import names | — | **Gap** |
| Athena VM interpreter | `vm_mba` | **Different family** |
| Classic/Advanced dispatch | — | Not started |
| Opcode cryptor replay | — | Not started |
| Handler clones | — | Not started |
| VM gates | — | Not started |
| Multi-VM | — | Not started |
| Pack / CRC / anti-debug / watermarks / license | — | Out of scope |
| .NET IL VM | — | Out of scope |
| AArch64 opaque `B.cond` | `native_opaque` | Covered, not Athena |

---

## 10. Chernobog pipeline and where new work sits

Current deobfuscation order (`src/deobf/deobf_main.cpp`):

1. Select-chain collapse
2. `vm_mba` (opt-in)
3. Block merge
4. String decrypt, stack strings
5. Const decrypt, global const, write-only store removal
6. Pointer resolve
7. MBA substitution simplify (the 108-rule catalog)
8. Indirect branch / call, identity call, Hikari wrappers, savedregs, ObjC
9. Bogus CF
10. Deflatten (including recurrent switch)
11. Ctree string literals (after hybrid projection seal)

Native IDA analysis and early Hex-Rays (`call_pop_flowchart`, constant
folding) run **before** this list.

Insert Athena-related work as follows:

| Work | Where | Why |
|---|---|---|
| `push r/m; ret`, call-as-jmp, push-next | Native engine, before lift | CFG must exist for Hex-Rays |
| x86 known-flag `jcc`/`cmov`/`setcc` | Native engine, then jump_optimizer | Depth and predicate kinds |
| NOR/NAND catalog rules | Step 7, existing registry | No new pass |
| Keystream strings | Step 4 / ctree string | Next to Hikari XOR |
| Import name comments | Evidence apply / rax summaries | Not microcode |
| Athena VM | New `obf_type_t`, new handler, after MBA | Needs CFG + MBA first |

Do not add `OBF_ATHENA`. Detect by idiom, not by vendor. A binary can mix
Hikari and Athena-like mutation.

---

## 11. Recommended slices

### Slice 1 — Mutation CFG (native)

- `push r/m; ret` pair classification
- 64-bit `push rax; lea rax, [next]; xchg [rsp], rax`
- `call` used as jmp + later `ret` / `ret n` without creating a function
- Register-tracker-proven push targets become xrefs (reuse
  `CHERNOBOG_IDA_REGISTER_SCAN_DEPTH`)

Success: IDA flowchart of a mutation-only function is a single connected
CFG; Hex-Rays decompiles without spurious extra functions.

### Slice 2 — NOR/NAND catalog

- Rules in §5.4, Z3-certified, catalog harness green
- No Athena-named APIs

Success: `chernobog_catalog_tests` proves every new rule at 8/16/32/64;
a hand-written microcode snippet `~(~x | ~c)` still simplifies (regression);
a stack-slot NAND-then-invert snippet newly simplifies.

### Slice 3 — x86 opaque predicates

- All `jcc` kinds; CF/ZF/OF/SF/PF
- Scan that skips non-defining instructions; `clc`/`stc`/`cmc` as CF defs
- `cmovcc`/`setcc` rewrite
- Drop never-taken edges whose target was a random junk instruction
  (only with a proof, never heuristically)

Success: a mutation+obfuscation sample with known-true `jz` after `xor r,r`
loses the dead edge; decompilation no longer contains the junk block.

### Slice 4 — Keystream strings

- `ks8`/`ks16` recoverer
- Optional `STRING_DIRECTORY` recognizer
- rax summary for decrypt/free exports if present

Success: a fixture encrypted with a known key appears as a ctree literal.

### Slice 5 — Test oracle

Protect tiny programs with Athena **mutation only**, then Ultra, using the
private protector. Keep the unprotected and protected binaries, and the
project settings, **outside** this repository. Record in this document only
the expected identities (e.g. “function `add` became `lea` + 12 junk ops +
one always-taken `jcc`”). Run Chernobog IDA smoke against the protected
file.

Never commit Athena sources, keys, or licensed runtimes here.

### Slice 6 — VM recognition (later)

Gate finder, opcode-fetch replay, handler classifier, bytecode lift. New
files under `src/deobf/handlers/`, new `obf_type_t`. Requires slices 1–3.

---

## 12. What not to port

- Athena VM interpreter, cryptor classes, loader, SDK, GUI
- Anti-debug, anti-VM, CRC, watermarks, Taggant, licensing, keygen
- Resource encryption, packer
- .NET IL virtualization
- Hard-coded default VM GPR assignment (demo-only; registered builds randomize)
- Default section name `.athenatuberlin` as a required detector
- Any Athena identifier in user-facing Chernobog output

If a comment must mention the mapping, point at this document.

---

## 13. Invariants for new code

Match existing Chernobog policy:

- Fail closed. No xref, no edge deletion, no literal, no MBA rewrite without
  a proof (register tracker, flag scan, or Z3).
- Native patches that change bytes must be reversible and must not modify the
  input file on disk (`native_opaque` is the template; x86 opaque work should
  prefer IDA xrefs/comments over byte patches unless a revert table exists).
- rax stays current-function, one worker, no callee sweep, no database job
  (`RAX_HYBRID.md` scope invariant).
- MBA rules go through `RuleVerifier`; UNKNOWN is rejection
  (`src/deobf/rules/rule_verifier.cpp`, `tests/CATALOG_HARNESS.md`).
- Runtime strings require cross-run consensus where rax is involved.
- New IDA smoke tests follow `tests/run_ida_smoke.py` isolation.

---

## 14. File index

### Athena (private catalog; do not copy)

The generator lives in the private AthenaTUBerlin tree. The identities above
were read from:

- Mutation and stack-machine obfuscation: Intel function mutate / obfuscation
  compile / random-command emitter
- VM ISA and dispatch: Intel VM command lowering, `InitCommands`,
  `AddReadCommand`, Classic vs Advanced end-handler
- Cryptors: `ValueCryptor::Init`, `OpcodeCryptor` (XOR combiner)
- Strings: loader `EncryptString`, runtime `VirtualString` / `StringManager`
- Imports: PE loader IAT name emission under import protection
- Product description: help pages for compilation types and project options

### Chernobog (implementation sites)

| Area | Path |
|---|---|
| Native CFG / flags | `src/ida_analysis/native_engine.cpp` |
| Native config | `src/ida_analysis/analysis_config.hpp`, `analysis_config.cpp` |
| Get-PC | `src/ida_analysis/get_pc_ida.cpp` |
| AArch64 opaque | `src/deobf/handlers/native_opaque.cpp` |
| Jump optimizer | `src/deobf/handlers/jump_optimizer.cpp`, `src/deobf/rules/jump_rules.*` |
| MBA catalog | `src/deobf/rules/rules_{and,or,xor,add,sub,misc,predicate}.*` |
| Registry / verifier | `src/deobf/rules/rule_registry.cpp`, `rule_verifier.cpp` |
| Catalog tests | `tests/catalog_tests.cpp`, `tests/CATALOG_HARNESS.md` |
| String decrypt | `src/deobf/handlers/string_decrypt.cpp`, `ctree_string_decrypt.cpp` |
| String recovery helpers | `src/common/string_recovery.h` |
| VM-family (other) | `src/deobf/handlers/vm_mba.cpp` |
| Pipeline | `src/deobf/deobf_main.cpp`, `src/deobf/deobf_types.h` |
| rax hybrid | `src/hybrid/`, `RAX_HYBRID.md` |
| Evidence apply | `src/ida_analysis/evidence_apply.cpp` |
| Native smoke style | `tests/ida_native_prefix_gate_smoke.py`, `tests/NATIVE_PREFIX_GATE.md` |

---

## 15. Worked identities (for tests)

These are the oracles slice 2 and slice 4 should encode. Widths 8/16/32/64
unless noted.

### 15.1 Boolean

```text
~(x | x)                = ~x
~(x & x)                = ~x
~(~x | ~y)              = x & y
~(~x & ~y)              = x | y
~(~x | ~c)              = x & c
~~(x & c)              = x & c
~~(x | c)              = x | c
~~(~(x & c))           = ~(x & c)
~~(~(x | c))           = ~(x | c)
```

### 15.2 Select from a boolean seen as 0 / -1

After `idx = cond + (-1)` on full width, `idx` is 0 or ~0.

```text
(dest0 & ~idx) + (dest1 & idx)   = idx ? dest1 : dest0
```

Only use this identity when Z3 proves `idx` is all-zero or all-one.
Constant destinations or use as a goto target do not relax this requirement.
For example, at width 32, `dest0=0x1000`, `dest1=0x10ff`, `idx=1` gives
the masked sum `0x1001`, not the conditional expression's `0x10ff`.

### 15.3 Keystream

Key `k = 0xA5A5A5A5`, plaintext `"Hi"` (plus NUL). The keystream is
`uint8(rol32(k, i) + i)`:

```text
i=0: rol32(k,0) = 0xA5A5A5A5 ; +0 → 0xA5A5A5A5 ; xor 'H' (0x48) → 0xED
i=1: rol32(k,1) = 0x4B4B4B4B ; +1 → 0x4B4B4B4C ; xor 'i' (0x69) → 0x25
i=2: rol32(k,2) = 0x96969696 ; +2 → 0x96969698 ; xor 0x00      → 0x98
```

A recoverer that does not reproduce `48 69 00` from `ED 25 98` with that
key is wrong. UTF-16 uses 16-bit little-endian units and `ks16`.

### 15.4 Mutation CFG

```text
; original
jmp rax
; mutated
push rax
ret
```

```text
; original x64 get-next
call  $+5
; mutated
push  rax
lea   rax, [rip_of_original_next]
xchg  [rsp], rax
```

The second form must not be a call in the IDA flowchart.

---

## 16. Decision log

- Improve Chernobog from Athena **identities**, not by importing Athena.
- First value is mutation CFG + NOR/NAND catalog + x86 opaque flags, not VM
  lifting.
- `vm_mba` stays the `prog_bb_*` SSE family.
- No vendor bit in `obf_type_t`.
- Test oracle binaries stay out of git.
- rax does not become a whole-database Athena unpacker.
