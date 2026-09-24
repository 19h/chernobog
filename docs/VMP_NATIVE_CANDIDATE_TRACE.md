# Bounded synthetic capture from a packed Morok data head

`chernobog_vm_trace_candidate(data_head_ea, seed)` now creates an image-only
snapshot and a separate native-region plan from an explicit unlabeled data head
in an executable x86/x64 segment. The optional
`chernobog_vm_trace_candidate_input(data_head_ea, seed, input_json)` accepts
the existing bounded scalar/object input schema. Neither API creates an IDA
instruction or function. Results use `scope=native-candidate-region`,
`candidate_decode=true` and `synthetic_entry=true`; ordinary function traces
retain their existing scope and function field. This advances review rows 6a
and V by making the previously unavailable packed entry measurable under an
explicit synthetic state. It does not establish actual program reachability,
runtime unpacked contents, logical VM identity or a handler summary.

The fresh fixed-time Morok keygen protected builds described in
`VMP_MOROK_KEYGEN_PAIRED_CONTROL.md` have identical SHA-256
`f479ae1ab6f03857a0598d61df4674e24c787328dcec77461be532e3d962bbae`.
Fresh IDA 9.4 SP1 processes trace their application trampoline at `0x418440`
with seed zero. Both six-check reports are byte-identical. Each candidate
plans 1,122 heads and records 4,096 instruction entries over 543 distinct
addresses, then stops at the configured `instruction-budget` at `0x419896`.
The entered prefix begins `0x418440`, `0x418441`, then the direct call target
`0x4185f0`; the ordinary function API is unavailable at the data root.
The separate owned-function control at packed startup `0x40021b` remains
available with its original `native-region` scope and stops after 33
instructions at an `environment-model-failure`.

The candidate records 915 data accesses, six final-write ranges and 15
planning frontiers. `data_trace_complete=true` describes accesses within this
captured prefix only. `region_code_changed=false` reports no detected change
to admitted instruction bytes before this stop; it is not evidence that later
unpacking or self-modification cannot occur. The entry is seeded with a
synthetic stack and registers. No CRT callback arguments, Linux process state,
system-call effects or actual entry trace are claimed. Instruction-entry
records do not prove retirement. The instruction-budget stop prevents a
complete application result or protected-edge recovery score.

An independent ELF64 program-header reader maps each entered address to
file bytes. Capstone 5.0.7 checks all 4,096 entries per run, including repeated
visits, and finds zero file-byte, instruction-size or linear-successor
mismatches. The two full candidate reports, including exact checked IDB
inventories, are byte-identical. Before and after each query, the inventory
contains 38,006 heads, 40,917 outgoing references and SHA-256
`aced12a072b293db11c869da5bc803a7fed070a05cce39f6119a84d8d09c2118`.
An explicit empty input reaches the separate candidate API; malformed input,
a data tail, an existing code head and a selected nonexecutable address are
rejected. All 21 CTest suites pass.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| T1 | The hashed protected builds and `0x418440` data head represent the selected packed application trampoline. The local capture identity depends on this. | Rebuild the paired source and rerun its process oracle; compare binary, startup immediate, IDA data flags and segment permissions. |
| T2 | The image-only snapshot contains the loaded bytes used by the planner and emulator. Captured byte identities depend on this. | Independently map ELF64 file segments and compare every entered byte; check the IDB inventory before and after; deliberately change a planned byte in a disposable database and require a changed or rejected capture. |
| T3 | IDA's mode-aware decoder partitions the entered prefix consistently with independent x86-64 decoding. The instruction-entry count depends on that partition. | Decode each retained entry with Capstone and test fallthrough successors; any mismatch rejects the count as an ISA-level observation. |
| T4 | The synthetic seeded entry state is a bounded experiment, not actual CRT invocation state. All reported execution paths depend on this choice. | Record real process entry registers, stack, memory mappings and executed addresses under a validated x86-64 runtime; compare entered bytes and edges before claiming runtime recovery. |
| T5 | The emulator stops at the configured instruction/time/resource frontiers. Prefix completeness and abstentions depend on those bounds. | Require explicit stop reason, 4,096-entry cap, negative root/input controls and no ordinary evidence publication; vary budgets in a separately recorded experiment. |

## Bounds, cost and impact

The snapshot admits at most 64 MiB of mapped image bytes. The planner retains
at most 4,096 heads; the execution limit is 4,096 instructions, timeout 250 ms
inside the emulator, and retained final-write bytes at most 65,536. For B
mapped bytes, H planned heads and I instruction entries, snapshot storage is
O(B), planning is O(H log H) plus mode-aware decode and image lookups, and
recorded execution is O(I + A) space for A retained accesses, excluding backend
internal state. The independent verifier processes V visits over at most 128
ELF program headers in O(V·P) file-map search plus O(V) Capstone calls and
O(V) retained mismatch diagnostics, where P is the number of load headers.
Counts and byte limits are exact. Wall-process duration includes IDA loading
and is not an emulator throughput estimate.

- **High impact:** a protected application entry previously classified only
  as data now yields a bounded, independently byte-checked execution prefix.
- **Medium impact:** explicit synthetic and ordinary scopes prevent this trace
  from being mistaken for a recovered function or actual process entry.
- **Low impact:** the 4,096-entry limit, unmodeled environment and unknown
  runtime unpacked state leave application and VM semantics unresolved.

`VMP_NATIVE_CANDIDATE_TRACE_EVIDENCE.json` records exact source, IDA,
native-plugin, protected-binary and raw-report hashes. The measured plugin
was built from the listed sources before this checkpoint was committed.
Reproduce with a hash-matched console IDA and plugin in fresh directories:

```sh
python3 -B tests/run_ida_smoke.py \
  build/morok-keygen-evidence-final/protected-first/int_woma_keygen-linux-x86_64-static \
  tests/ida_native_candidate_trace_probe.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --output-dir build/candidate-trace-reproduction \
  --enable-rax --set CHERNOBOG_CANDIDATE_ROOT=0x418440 \
  --set CHERNOBOG_CANDIDATE_CODE_CONTROL=0x40021b \
  --set CHERNOBOG_CANDIDATE_NONEXEC_CONTROL=0x4442f8
```

QG1: technical scope. QG2: T1–T5 have falsification probes. QG3: two protected
builds, ordinary-owned and invalid-root controls, explicit input, byte
verification and existing tests are covered; the full review remains in
progress. QG4: units, budgets and asymptotic costs are explicit. QG5:
synthetic entry, entry-versus-retirement and instruction-budget limits are
distinguished. QG6: primary local binaries and exact raw artifacts are
hash-linked; independent Capstone decoding checks the entered spans. QG7:
impact and runtime/semantic boundaries are labeled.
