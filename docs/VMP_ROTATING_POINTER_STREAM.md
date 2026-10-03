# Bounded source-pointer streams in rotate/add/XOR recognition

This checkpoint extends review item 3c for a compiler-generated ctree shape.
The existing `transform_words` fixture now decompiles on x64 as a preheader
pointer to the immutable word array followed by one `*result++` source read per
loop iteration. Its native executable still yields the expected `VMPΩ` word
sequence. The prior plugin omitted the annotation. The current plugin recovers
one transient `16-bit units, key=0xA17E395B, units=5` UTF-16LE candidate.
The i386 fixture retains indexed reads and its result is unchanged. Exact
artifacts and paired run hashes are in
[VMP_ROTATING_POINTER_STREAM_EVIDENCE.json](VMP_ROTATING_POINTER_STREAM_EVIDENCE.json).

## Admission and proof scope

The ctree adapter records a pointer preheader only when its initializer is an
image object address or an already recorded preheader alias. It resolves a
direct `cot_ptr(cot_postinc(cot_var))` source to the object's initial address
plus one native pointed-to unit per iteration. The pointed-to unit must be one
or two bytes and equal the transform unit. A postincrement requires exactly
one source read in the bounded expression, because a later read through that
pointer would observe its advanced value. Source and destination address sequences
must each have exactly the admitted unit stride, stay within one loaded image
segment, and remain disjoint. The source segment must be readable and
non-writable; the destination segment must be writable. The existing typed
finite-index proof, byte/word decoding, terminated-text validation, native
load/store width checks, and current-function code/cipher freshness checks
still gate the annotation.

For a pointer initialized to source address \(S\), unit width \(b\) bytes and
loop bound \(N\), the admitted source read at index \(i\) is \(S+i b\), for
\(0\le i<N\). The bounds are \(b\in\{1,2\}\), \(Nb\le8192\) bytes, one
postincrement/source read and at most 128 expression nodes. Pointer resolution adds
O(log P) lookup per extracted pointer node for at most P preheader variables;
the existing exact value proof remains O(N·D·W) time and O(D·W) working space
for expression nodes D and fixed bit width W≤64. The output is a conditional
string value for this loop, not a claim that arbitrary runtime aliases or
later destination contents are known.

The compiled writable-word source also uses `*result++` on x64. A second
fixture reads multiple source words around a pointer increment; its native
oracle confirms a result different from the nominal word string. Both receive
no annotation under either plugin. The latter decompilation also has address
expressions outside the admitted shape, so it is an abstention control rather
than an isolated execution of the single-read guard. Additional writes,
unsupported pointer updates, non-image pointer initializers, uncertain source
permissions and source/destination overlap remain outside admission.

## Paired verification

| Exact input and architecture | Prior plugin | Current plugin | Control |
|---|---|---|---|
| x64 Mach-O, 14 routines | 57/60 checks pass; the three word-string checks fail | 60/60 pass; one exact word annotation | Writable and multiple-read sources abstain; source byte, native code and permission edits invalidate the positive receipt |
| i386 ELF, same 14 source routines | 57/57 pass | 57/57 pass | Prior/current captures are byte-identical; the word read remains indexed |

The paired verifier rehashes the source, both binaries, four copied plugins,
four copied IDA probes, run manifests and captures. It checks the x64
`cot_postinc` source shape, exact annotation inventory, three prior failures,
zero current failures, both negative abstentions and identical expression
inventories per architecture. It also executes the exact x64 binary and
requires its native plaintext oracle to exit zero. The full configured CTest
run passed 23/23 suites. Run:

```sh
python3 -B tests/verify_rotating_pointer_stream.py
ctest --test-dir build --output-on-failure -j 4
```

This fixture is independent native code, not a protected VMP output. The
result establishes recovery of the observed compiler shape under the stated
contract. Protected-corpus frequency and recovery gain remain unknown.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| P1 | The final ctree represents one source pointer advanced by one word per executed iteration. The recovered word candidate depends on this. | Require `cot_postinc` and `*result++` in the exact x64 record; reject a changed loop count, second source read, extra pointer update or extra loop write. |
| P2 | The preheader points to the recorded image source throughout the loop. The source-address sequence depends on this. | Require the exact object address, unit stride, disjoint destination and one loaded segment; an unknown pointer initializer or source/destination alias must abstain. |
| P3 | The recorded source is immutable over the loop. Ciphertext recovery depends on this. | The writable-word pointer source must abstain; changing source permissions or ciphertext bytes must remove a saved annotation. |
| P4 | The key, transform units and text encoding are independently established. The displayed `VMPΩ` candidate depends on this. | Check the exact key/unit/bound label, native plaintext bytes, typed proof and UTF-16 validation. Byte-encrypted UTF-16 remains a distinct 8-bit-unit case. |
| P5 | The archived paired runs refer to the stated binaries, plugin builds and probe. The measured delta depends on this. | Rehash copied artifacts, manifests and captures; require identical expressions across each pair and the precise three-to-zero x64 failure change. |

## Bounded expansion

- **Medium impact:** the adapter now recognizes an immutable image source
  expressed as a preheader pointer with one source postincrement. This
  addresses a real compiler variant of the reviewed transform.
- **High impact risk:** a pointer whose value or referent can change outside
  the admitted ctree and image-permission contract could invalidate the
  inferred source sequence. Such execution is not certified by these tests.
- **Low impact:** the one/two-byte unit, 8,192-byte, 128-node and one-update
  limits prevent this checkpoint from claiming general pointer-loop coverage.

QG1–QG7: no normative decision is required; assumptions and probes are above;
the source-pointer requirement has paired production and native evidence;
byte counts and asymptotic bounds use the stated units; mutable/alias and
freshness controls reject unsupported cases; local source and artifact hashes
provide provenance; remaining protected and alias coverage is explicit.
