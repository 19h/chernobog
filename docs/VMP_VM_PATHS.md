# Local VM paths across native blocks

Historical path checkpoint: the results below describe its recorded build.
Subsequent push/near-return support and updated corpus counts are recorded in
[VMP_VM_STACK_DISPATCH.md](VMP_VM_STACK_DISPATCH.md).

Chernobog now recognizes and summarizes two actual protected dispatch paths in
the paired corpus. Previously, function-only scanning could not inspect their
ownerless instructions, and contiguous matching rejected intervening direct
jumps and register/flag operations. The new inspection follows bounded existing
code references and retains every admitted path instruction in its semantic
model. It assigns neither function ownership nor VM execution permission.

Source and artifact hashes, native results, and IDA checks are recorded in
[VMP_VM_PATHS_EVIDENCE.json](VMP_VM_PATHS_EVIDENCE.json). The prior
[entry-decoding checkpoint](VMP_DIRECT_JUMP_DECODE.md) remains a prerequisite.

**Observed protected paths**

Both candidates occur in `virtualization-0`, the recorded seed-zero protected
artifact. Their bytecode reads and feedback operations use 32-bit values; final
dispatch adds a sign-extended value to a 64-bit base.

| Selected original function | Direction | VIP | Value | Key | Base | Path instructions |
|---|---|---|---|---|---|---:|
| `corpus_transform` | Backward | R11 | RAX | R8 | R10 | 33 |
| `corpus_branch` | Forward | RSI | R8 | RDI | R10 | 26 |

Both summaries retain five ordered memory operations: bytecode read, 64-bit
key push, 32-bit feedback read/write, and 64-bit key pop. All architectural GPR
outputs, the final memory array, defined arithmetic flags and symbolic dispatch
target are modeled under the existing normal-completion contract. Register writes
overwritten before the read or by the key pop remain in the model. TEST, CMP,
CLC/STC/CMC, partial/high-byte aliases and overwritten BSF results are represented.
Undefined BSF results are symbolic; admission confines these writes to values
subsequently overwritten. Flag-only operations are never erased from the summary.

The full 20-run corpus comparison passes with the same original/protected hashes.
The original's code inventory is unchanged. With entry decoding enabled, the
three mutation variants yield no VM candidate, the three virtualization variants
yield two candidates total, and the three combined variants yield none. Both new
hits are from development seed zero. The reserved protector seed still yields no
candidate. These are prefix-recognition counts, not complete handler coverage,
false-positive rates, or evidence of generalization across protector seeds.

The previous artifact had zero candidates for these same decoded prefixes.
Concrete VIP/key/context recovery, protected execution-transition corroboration,
push/RET dispatch modeling, broader interleaved instruction support and full
handler semantics remain incomplete. A symbolic local model does not establish
that a concrete target is unique or that its execution is admitted.

**Implementation and boundaries**

[region.cpp](../src/vm/region.cpp) validates the complete ordered path. Ordinary
steps must be physically adjacent; a discontiguous successor requires an explicit
direct jump to that exact instruction. Overlapping instructions, alternate
entries and any instruction after the terminal dispatch reject the candidate.
Pattern selection tolerates modeled flag operations,
overwritten pre-read value writes and scratch writes to a saved key. Every source
instruction remains in `Candidate.support` for symbolic evaluation.

[ida_regions.cpp](../src/vm/ida_regions.cpp) anchors inspection at the selected
IDA function. Existing fallthrough and near-jump xrefs may expose initialized,
executable ownerless instructions in the same mode. Calls are not followed;
another function owner stops traversal. No bytes, code items, xrefs or ownership
are created by inspection. Candidate provenance now includes ordered instruction
address/size spans and concatenated bytes. `end` follows the final dispatch and
is not a bounding address for a discontiguous path.

[observations.cpp](../src/vm/observations.cpp) checks recorded code writes against
each actual instruction span. A write to a lower-address path block invalidates
runtime code identity; a write into an unvisited gap does not. Exact ordered
execution samples remain required before a captured transition can be checked.

The added traversal has at most 1024 scheduled heads, 4096 examined outgoing
references, 8192 path steps, 128 instructions per path and 64 examined incoming
references per step. Candidate retention remains 64, summary retention 16, and
summary-comparison attempts 32. Per-path and reachability exhaustion are explicit
JSON fields and contribute to the GUI's scan-truncation status. Existing
contiguous scanning retains its own instruction counter.

For H cached heads, E outgoing references, S path steps, I incoming references per
step, C recognition attempts and P instructions per attempt, the added traversal
and recognition cost O(H log H + E + S(log H + I) + C·P²), with O(H + P) working
space excluding retained records and symbolic expressions. This is not an SMT
complexity bound; solver timeout/resource limits remain separate.

**Validation**

All 18 configured CTest tests pass in 9.08 s. Portable suites report 347 region,
4372 semantic, 89 observation and 632 transition checks. New controls cover
noncontiguous and overlapping code, altered links, alternate entries, invalid
high aliases, memory effects disguised as noise, unrestored register writes,
register renaming, clone relocation, final flag changes, and operations supplied
after the terminal jump. Noisy/normalized
paths compare UNSAT over all modeled outputs and ordered accesses; an observable
carry change produces SAT. A separate manually computed `CMP AH,0` case verifies
the distinction between AH=0 and AL=7.

An independent x64 assembly fixture executed 416 cases on the arm64 host through
compatibility translation: 208 noisy relative-dispatch cases and 208 table
controls. Each scenario has 40 corner combinations and 64 recorded seeded cases.
The checker performs 18,311 assertions including its portable controls. Native
observations cover VIP, value, key, base, stack pointer, retained stack bytes,
defined flags and reached target; they do not capture every preserved GPR or an
execution trace of the actual protected VM. The real protected summaries have
not yet been corroborated against such a trace.

Production IDA tests pass 251 checks: 36 protected-path terminal, 42 protected-path
GUI, 72 existing x64-region, 72 existing x86-region and 29 existing captured-transition
checks. Remote byte patches, alternate entry xrefs and foreign ownership revoke
the real candidates; restoration permits recognition again. A synthetic 133-head
path verifies explicit exhaustion of the 128-instruction limit, including the GUI
status. The GUI checks recognition freshness after event processing on the
untouched input, before mutation controls can enqueue IDA ownership analysis.
The GUI screenshot was inspected: candidate provenance and local effects are
visible, and execution capture/ownership remain unavailable.

Reproduce the independent execution check:

```sh
xcrun clang -arch x86_64 -O2 -DCHERNOBOG_VM_PATH_ORACLE=1 \
  tests/vmp_native/vm_semantics_oracle.c tests/vmp_native/vm_semantics_oracle.S \
  -o build/vmp-path-native
build/vmp-path-native > build/vmp-path-native.txt
build/chernobog_vm_semantics_tests build/vmp-path-native.txt --path
```

Run `tests/ida_vm_path_probe.py` through the isolated IDA runner against
`virtualization-0`, supplying `CHERNOBOG_CORPUS_ENTRIES` from the corpus manifest
and `CHERNOBOG_VIEW_MODULE` for the companion. The full inventory uses
`tests/run_vmp_analysis.py`. Input, IDA, plugin and probe hashes must match the
retained reports. Elapsed nanoseconds convert to seconds by multiplication by
10^-9; resource observations are retained as measurements, not speedup claims.

**Assumption register and scope**

| ID | Assumption / dependent conclusion | Falsification probe |
|---|---|---|
| P1 | Current IDB bytes, modes and xrefs describe the inspected static path. Recognition depends on this. | Remote-byte, alternate-entry and foreign-owner controls; re-read all spans for freshness. Runtime self-modification remains outside the static claim. |
| P2 | The admitted instruction vocabulary has the stated normal-completion effects. Summaries depend on this. | Independent executed cases, manual high-byte flags, full-output SMT comparisons and corruption counterexamples. Unsupported instructions reject instead of being discarded. |
| P3 | Data accesses succeed in flat little-endian memory without concurrent, device or segment-base effects. Equivalence depends on this. | Retain aliasing and ordered stack effects; do not generalize to faults, concurrency or omitted accesses. |
| P4 | Corpus artifacts are the intended source-attributed targets. Vendor-specific conclusions depend on this. | Validate recorded hashes; exact protector source-build equivalence remains unknown as documented in the paired corpus. |
| P5 | Two supported prefixes are a limited capability result. Broader coverage does not follow. | Retain zero-candidate results for other seeds/modes and require separate execution/coverage oracles. |

High impact: decoded ownerless code can remain invisible to function-only
analysis. High impact: removing apparent junk before modeling can lose flag,
partial-register or memory effects. Medium impact: one numeric address interval
cannot represent a path with backward native jumps. These extensions remain
within local binary analysis; VM execution ownership and full bytecode lifting
are not implied.

QG1: technical scope. QG2: P1–P5 include falsification probes. QG3: the path
extension is covered; the complete review remains in progress. QG4: counts,
resource units and complexity bounds are explicit. QG5: candidate recognition,
symbolic effects and actual execution corroboration are distinct. QG6: local
primary sources and artifact hashes are recorded. QG7: adjacent ownership,
effect-preservation and address-span risks are bounded above.
