# Defined x86-64 flags on one Morok protected prefix

This checkpoint refines `VMP_NATIVE_MEMORY_REPLAY.md` with a *same-process*
instruction-register and memory oracle. It uses two fresh QEMU/GDB processes
of the fixed-seed Morok keygen protected ELF64 pair on the same 35-byte valid
stdin. Each `tests/morok_qemu_packed_entry_memory_states.py` report contains
the entry registers and 2,848 entry-memory bytes, the registers and 16-byte
instruction window at each of 4,094 reported entries, and 18 scalar
registers plus the same two memory windows at boundary PC `0x40c89b`.
The supplied keygen ELF remains a different artifact.

Fresh IDA replays use each process's *own* entry data and translated stack
windows. Both execute 4,096 candidate instructions. The independent verifier
aligns 4,094 QEMU/GDB entries after the same two bounded debugger omissions
at `0x40d63f` and `0x40c1a2`. It decodes every entered candidate instruction
with Capstone 5.0.7 and requires exact decoded length and protected-process
instruction bytes at each aligned entry. After reversing the explicit stack
translation, all `4,094 × 16 = 65,504` GPR values agree per run. All 18
boundary scalar registers and all `1,696 + 1,152 = 2,848` boundary-window
bytes agree per run.

The flag verifier tracks the definedness of CF, PF, AF, ZF, SF and OF before
each entered instruction. It starts with all six recorded entry bits known;
preserving instructions retain the mask. ADD, SUB, CMP, locked CMPXCHG and
locked XADD define all six. XOR, AND and TEST leave AF undefined and define
the other five. IMUL defines CF and OF; its SF, ZF, AF and PF results are
undefined. Every observed SHL/SHR has a nonzero immediate count below its
operand width: CF, PF, ZF and SF are defined, while AF and OF are undefined
because the count exceeds one. Every observed ROL also has a count above one:
it defines CF, leaves OF undefined and preserves PF, AF, ZF and SF. The
verifier rejects any instruction outside this exact whitelist or any shift
count outside its covered range. These masks follow the [Intel 64 and IA-32
Instruction Set Reference](https://cdrdv2-public.intel.com/782156/325383-sdm-vol-2abcd.pdf)
and its [XADD reference](https://cdrdv2-public.intel.com/671143/334569-sdm-vol-2d.pdf).
Capstone supplies instruction decoding, not the defined-flag mask.
The verifier also requires ZF to be defined at all 193 observed `JE`, `JNE`
and `SETE` entries per run.

Raw RFLAGS agree at `3,418/4,094` aligned entries per run. The other 676
entries contain 901 differing status bits per run, all outside the tracked
defined mask. All defined bits agree at every aligned entry: 18,811 exact
defined-bit comparisons per run, 37,622 across the pair. The per-run known
bit counts are CF 4,094; PF, ZF and SF 3,260 each; AF 1,383; and OF 3,554.
The verifier checks that no difference occurs outside these six status bits.
It observes 221 SF disagreements immediately after IMUL and 22 OF
disagreements immediately after multibit shifts per run, demonstrating that
those exclusions affect this fixture. A one-bit mutation to a defined value
is rejected; a one-bit mutation confined to an undefined value is ignored;
forcing comparison of all status bits rejects the raw trace. The database
inventory digest is unchanged after each IDA probe.

This result establishes equality of the six status bits **where they are
architecturally defined along this finite path**. It does not equate
architecturally undefined results, claim intermediate memory identity beyond
the recorded windows, or extend to other inputs and later execution. The
native plan is truncated. Logical VM state identity and ordinary function
evidence remain separate requirements.

## Reproduction and cost

The QEMU/GDB runs use the pinned `chernobog-linux-ci:latest` image, QEMU
10.0.13 and GDB 16.3 from `VMP_NATIVE_MEMORY_REPLAY_EVIDENCE.json` with the
GDB script `tests/morok_qemu_packed_entry_memory_states.py`. Set
`CHERNOBOG_PACKED_ENTRY_MEMORY_STATES_OUTPUT` to a unique report path per
process. The accepted reports are
`build/morok-runtime-probe/packed-entry-memory-states-{first,second}.json`.
Run `tests/ida_native_shadow_replay_memory_probe.py` through
`tests/run_ida_smoke.py` once per protected binary with its matching new
QEMU report in `CHERNOBOG_BOUNDARY_FILE`; the accepted outputs are
`build/ida-shadow-memory-states-{first,second}/shadow_memory_replay.json`.
Verify them with:

```sh
python3 -B tests/verify_native_shadow_defined_flags.py \
  --binary build/morok-keygen-evidence-final/protected-first/int_woma_keygen-linux-x86_64-static \
  --second-binary build/morok-keygen-evidence-final/protected-second/int_woma_keygen-linux-x86_64-static \
  --input build/morok-runtime-probe/valid.stdin \
  --shadow build/morok-runtime-probe/packed-first.bin \
  --second-shadow build/morok-runtime-probe/packed-second.bin \
  --first-ida build/ida-shadow-memory-states-first/shadow_memory_replay.json \
  --second-ida build/ida-shadow-memory-states-second/shadow_memory_replay.json \
  --first-runtime build/morok-runtime-probe/packed-entry-memory-states-first.json \
  --second-runtime build/morok-runtime-probe/packed-entry-memory-states-second.json \
  --output build/morok-runtime-probe/defined-flags-verification.json
```

For input/report bytes `B`, planned heads `H ≤ 16,384`, candidate
instructions `I = 4,096`, scalar registers `R = 16`, retained memory events
`D = 320` and memory-window bytes `W = 2,848`, verification uses
`O(B + H + I × R + D + W)` time and space. The QEMU/GDB step loops took
823,339,881 ns and 833,414,448 ns; this excludes container startup and
does not measure plugin throughput. Source, executable, report and runner
SHA-256 values are in `VMP_NATIVE_DEFINED_FLAGS_EVIDENCE.json`.
All 21 CTest suites pass with `-j 1`. A `-j 20` run under high unrelated
host load failed two pre-existing VM suites; each passed alone, and the
serial full run passed. The parallel result is recorded separately in the
evidence JSON.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| F1 | The hashed binary, stdin and unpacked entry bytes identify the same valid-input protected path. Every cross-tool comparison depends on this pairing. | Rehash every artifact and reject a changed binary, input or executable dump; keep the supplied keygen ELF distinct. |
| F2 | GDB reports each register state before its recorded instruction in the same process that provides the entry and boundary windows. The 37,622 defined-bit result depends on this timing. | Repeat under an independent x86-64 instruction tracer or physical debugger at the same PC/byte tuples. |
| F3 | The Intel status-bit effects listed above cover every decoded instruction and immediate count on this path. Defined-bit agreement depends on the mask. | Reject an unclassified mnemonic/count; force IMUL SF or multibit-shift OF to known and require the observed disagreements; flip a defined bit and require rejection. |
| F4 | The two missing debugger entries are bounded linear-successor observation gaps. The 4,094-entry alignment depends on this model. | Directly observe both retirements; any changed predecessor bytes or successor rejects alignment. |
| F5 | Explicit near-RSP annotations identify translated stack pointers. GPR and boundary-window equality depends on this mapping. | Omit one annotation and require replay rejection; inspect a wider stack interval for an unmarked near-RSP value. |
| F6 | The two data and stack windows bound the memory result. The 5,696-byte equality does not establish other addresses. | Capture wider windows or all writes, and run a different input; reject any stronger claim if new addresses differ. |

- **High impact:** 37,622 architecturally defined status-bit comparisons
  match across the two protected processes.
- **Medium impact:** same-process entry and instruction observations remove
  the earlier cross-process stack-offset confounder.
- **High impact risk:** unknown flag effects on another instruction or input
  must make this verifier abstain; the 676 raw RFLAGS differences per run are
  still real measurements of undefined values.
- **Low impact:** Capstone flag-effect metadata is not used for the mask; the
  Intel instruction rules are encoded explicitly for this whitelist.

QG1: technical scope. QG2: F1–F6 state dependent results and falsification
probes. QG3: same-process registers and memory, exact bytes/decodes, defined
flags, mutation controls and database inventory are checked; the complete
review remains in progress. QG4: counts, units and complexity are explicit.
QG5: raw undefined-bit differences are separated from defined-bit equality.
QG6: Intel's primary instruction reference and local source/report hashes
are recorded. QG7: other inputs, outside-window memory and VM identity
remain bounded unknowns.
