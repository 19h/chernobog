# Bounded repeated LODS values

Review rows 1b, 2a and V require native target and predicate facts only when
the repeated memory effects are established. The
[Intel REP instruction reference](https://cdrdv2-public.intel.com/868137/325462-089-sdm-vol-1-2abcd-3abcd-4.pdf)
uses the address-size count and direction flag to determine the executed
`LODS` reads. Each nonzero normal-completion path leaves the final loaded
element in the accumulator. `LODS` does not write memory or status flags.

Production IDA analysis now enumerates every compatible count from zero
through eight and both compatible direction-flag values for natural-address-
size long-mode `REP LODS`. It verifies every accessed address without
arithmetic wraparound and against an IDA readable segment. The final
element's value comes only from bytes written in the bounded local replay;
initial writable-image bytes are not assumed known. Resulting accumulator
words are joined across all count and direction alternatives. The existing
post-count helper sets RCX to zero on normal completion, and the index helper
joins the resulting RSI values. The local memory map and six modeled status
bits remain unchanged. Any unsupported prefix, unmatched decoded operand,
unknown source address, invalid range or count above eight retains the
previous conservative transfer. i386 nonzero reads remain unresolved because
the DS base is not proved by this state model.

An executed x86-64 Mach-O fixture exercises seven target shapes: two forward
byte reads; three backward byte reads; two byte reads with unknown initial
direction but equal final values; a count in {0, 1} with the same target on
both paths; exactly eight byte reads; two word reads; and two qword reads.
A separate dword case checks the final EAX value through `SETcc`. Nine byte
reads are an explicit beyond-cap control: the process reaches the target,
while static analysis abstains. Ten fixture calls for each of 256 inputs
produce 2,560 successful process results. Only the {0, 1} count case varies
its instruction count with the input; the other inputs check repeatability.
The process ran under x86-64 translation on the arm64 macOS host.

Fresh IDA 9.4 runs of the exact same binary and probe pass 34/34 prior-plugin
controls and 37/37 changed-plugin controls. The seven formerly unresolved
transfer sites each gain one exact register-definition target and one user
jump edge. The dword `SETcc` site changes from no fact to a true, one-byte
value fact. The nine-count site retains an unknown target and no user edge.
In a disposable database, moving the forward case's final local byte store
to another offset revokes its target and edge; restoring the bytes restores
both. The binary itself is unchanged. The prior exact-zero x86-64 and i386
probes each still pass 6/6 checks with the changed plugin.

A paired read-only inspection of the selected ownerless initializer root in
`samples/foo_x86_vmp` is unchanged: both profiles report 75 nodes, 77 edges
and three static-region facts, with byte-identical inspection reports and
preserved IDB inventories. This is a bounded protected-root negative control,
not a binary-wide recovery or false-positive measurement. The new fixture
does not change the historical 56-edge comparison benchmark denominator.

`VMP_REP_LODS_BOUNDED_EVIDENCE.json` pins the exact source, binary, prior and
current plugin, IDA, raw IDA report and protected control hashes. Reproduce
the process and changed-plugin control in fresh output directories:

```sh
xcrun clang -arch x86_64 -O2 -g0 \
  tests/vmp_native/rep_lods_bounded.S \
  tests/vmp_native/rep_lods_bounded_main.c \
  -o build/rep-lods-bounded-x64
build/rep-lods-bounded-x64
python3 -B tests/run_ida_smoke.py build/rep-lods-bounded-x64 \
  tests/ida_rep_lods_bounded_probe.py \
  --ida '/Applications/IDA Professional 9.4.app/Contents/MacOS/idat' \
  --plugin ../ida-sdk/src/bin/plugins/chernobog.dylib \
  --output-dir build/rep-lods-bounded-recheck \
  --set CHERNOBOG_IDA_REGISTER_SCAN_DEPTH=64
```

For the prior-plugin expectation, use the previous installed artifact and
add `--set CHERNOBOG_REP_LODS_BOUNDED_BASELINE=1`. The probe's source bytes
are otherwise identical. The protected negative control uses
`tests/ida_protected_region_inspect.py`, the supplied VMP file, root
`0x1002946b5`, `CHERNOBOG_IDA_DIRECT_JUMP_DECODE=1`, and
`CHERNOBOG_PROTECTED_REGION_EXPECT=complete`.

For `C` compatible counts (`C <= 9`), each `c <= 8`, element width `W` in
{8, 16, 32, 64} bits and at most `B = 128` retained bytes, the transfer
performs at most `2 sum(c) <= 144` address validations and `2C <= 18` final
value reads. Map lookup work is
`O(2 sum(c) + 2C (W/8) log(B+1))`, excluding IDA range-query cost and
surrounding graph traversal; extra working space is `O(1)`. Counts, bytes
and edges are exact dimensionless or byte units, with no rounding.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| R1 | The decoded natural-address-size `REP LODS` uses RCX, RSI and the specified element width. Count and value facts depend on this. | Compare the exact `F3 AC`, `F3 66 AD`, `F3 AD` and `F3 48 AD` fixture bytes with IDA's decoded operands; override address size or prefix and require abstention. |
| R2 | Each admitted source address is readable on normal completion and arithmetic does not wrap before an access. Final-value facts depend on this. | Move a source across a segment edge, remove read permission or place an access across `UINT64_MAX`; require the conservative transfer. |
| R3 | Retained local bytes still describe the final read, with no intervening write. The seven target gains and dword value fact depend on this. | Move the final local store by one byte; require target and user-edge revocation, then restore the store and require proof restoration. |
| R4 | Forward and backward completions are both included when DF is unknown. The unknown-DF target depends on their joined final value. | Execute caller wrappers with DF = 0 and DF = 1; change either final byte and require loss of the common target. |
| R5 | The count helper enumerates every compatible value up to eight and rejects larger domains. The {0, 1}, eight and nine results depend on this. | Execute both count alternatives; require the eight-count target and nine-count abstention. |
| R6 | Prior/current attribution uses equal binary, probe and IDA bytes; the protected control represents only one root. The measured gain and unchanged protected result depend on these scopes. | Compare runner hashes and exact fact/xref arrays; inspect additional protected roots or runtime-entered bytes before generalizing. |

- **High impact:** seven additional exact native target edges and one dword
  value fact are recovered in the bounded x86-64 fixture.
- **Medium risk:** i386 DS bases, larger counts, faults and protected-path
  effectiveness remain unresolved by this transfer.
- **Low impact:** the selected supplied protected root remains unchanged.

QG1: technical scope only. QG2: R1-R6 include falsification probes. QG3:
all four element widths, direction, count alternatives, the admitted limit,
revocation, process execution and one protected control are covered. QG4:
exact call and edge counts and bounded work are stated. QG5: unsupported
segments, aliases, ranges, counts and exceptional paths retain abstention.
QG6: the Intel primary reference and hash-linked source, process, plugin,
IDA and protected reports support the claims. QG7: broader protected
effectiveness and full review completion remain open.
