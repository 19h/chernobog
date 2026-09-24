# Direction-flag instructions in native status-flag analysis

The x86 native abstract interpreter previously treated `CLD` and `STD` as
unknown operations and erased its entire state. Intel specifies that each
changes DF while leaving CF, PF, AF, ZF, SF and OF unaffected
([CLD](https://cdrdv2-public.intel.com/782156/325383-sdm-vol-2abcd.pdf),
[STD](https://cdrdv2-public.intel.com/774492/325383-sdm-vol-2abcd.pdf)).
The interpreter now preserves its tracked registers, stack suffix and six
status flags across these instructions. It does not model DF or infer the
effects of later DF-sensitive string instructions; those remain subject to the
existing unknown-operation barrier.

This change advances review row 2a. It applies to both owned-function and
explicit-root ownerless analysis through their shared transfer function.
No CFG edge, ordinary proof publication rule or microcode rewrite was changed.

## Matched controls

The same final x64 fixture binaries and IDAPython probe hashes were used with
the prior installed plugin and the new built plugin. Native execution passed
in both profiles. The prior plugin failed the owned `df_direction` admission
and the ownerless `od_cld` and `od_std` condition checks. The new plugin proved
all three. The ownerless control keeps a call-return barrier unresolved and
the 129-node graph truncated without partial facts.

| Suite | Prior x64 IDA result | New x64 / i386 result | Native checks per architecture |
|---|---|---|---:|
| Owned direct-CFG | `df_direction` missing | 56 / 56 assertions pass | 3,070 |
| Ownerless direct-CFG | `od_cld` and `od_std` unresolved | 352 / 352 assertions pass | 4,094 |

The owned native oracle also saves EFLAGS/RFLAGS before `STD`, after `STD`,
and after `CLD` for 256 input values. It compares all six modeled status bits
at both later points. Both x86-64 and i386 executions returned zero differences
for every case. The assembly clears DF before returning to C. The deliberately
corrupted ownerless result oracle is rejected on both architectures.

On the exact supplied `samples/foo_x86_vmp` initializer, the read-only
inspection still completes 75 nodes and returns the same three unresolved
facts with zero proved conditions. Its IDB inventory is unchanged by the
inspection. This is a negative protected-effect measurement for this root;
the local result does not measure other protected functions or dynamic paths.

The production build and all 21 CTest suites pass. One concurrent CTest run
encountered `PermissionError` in the existing process runner's `killpg` path;
the isolated failing suite and a subsequent complete 21-suite run passed.
The cause of that process-runner error was unknown at this checkpoint. A later
bounded shutdown correction is recorded in `VMP_PROCESS_TERMINATION.md`.
Exact source, fixture, probe, plugin and report hashes are
recorded in `VMP_DIRECTION_FLAGS_EVIDENCE.json`.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| D1 | Intel's ordinary x86/x64 `CLD`/`STD` contract applies to the decoded instruction. Preserving six status bits depends on this. | Compare the architecture manual with 256 executed before/during/after flag snapshots on x86-64 and i386; malformed encodings or exceptional execution remain outside the normal-completion scope. |
| D2 | The abstraction tracks CF, PF, AF, ZF, SF and OF, but not DF. Existing later string-instruction abstentions remain required. | Require both local `SETB` facts under the new plugin, the call-return barrier's unresolved fact, and unchanged protected-sample abstentions. A future DF-sensitive transfer needs its own explicit DF state and memory/exception model. |
| D3 | The paired IDA runs use identical fixture bytes and probes. The red/green attribution depends on that identity. | Compare binary/probe hashes per pair and plugin hashes across pairs; reject changed input identity. Both new-plugin architectures must pass. |
| D4 | The supplied VMP root is the hashed ownerless initializer from the earlier measurement. The zero-gain conclusion applies only there. | Rehash the input and compare exact nodes, records, frontiers and before/after IDB inventory. Other entry points require separate measurement. |

Each `CLD`/`STD` transfer is O(1) time and O(1) additional space; it leaves the
existing 128-node, 128-round and 256-incoming-reference region limits intact.
Counts above are dimensionless integers. The x64 process used macOS translation
on an arm64 host; i386 execution used the pinned Linux QEMU image. Native
oracle agreement does not establish physical-x86 timing or exceptional behavior.

- **High impact:** exact direction-only instructions no longer destroy
  established native status-flag proofs or register/stack facts.
- **Medium impact:** the supplied protected root retains zero proved
  conditions, so protected recovery effectiveness remains unmeasured beyond
  this negative control.
- **Low impact:** the concurrent process-runner failure requires a separate
  reliability check; it did not recur in isolated or full-suite reruns.

QG1: technical scope. QG2: D1–D4 and falsification probes. QG3: owned and
ownerless production paths, both architectures, native execution and the
supplied protected control are measured; complete review row 2a remains open.
QG4: flag mask, check counts and O(1) incremental cost are explicit. QG5:
unknown call/DF-sensitive effects and the one process-runner error are retained.
QG6: Intel's instruction reference, native oracle, actual IDA results and
hash-matched artifacts support each claim. QG7: protected and exceptional
limits are explicit.
