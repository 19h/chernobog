# Exact supplied Morok keygen: source candidate behavior

The supplied static ELF64 keygen has SHA-256
`7d1971b1db221174caac0a5922a7452e1bebe214ca2355ab36c889a635699fd9`.
The sibling Morok checkout contains `programs/int_woma_keygen.c`, a candidate
original source with SHA-256
`988a6144b6b3924c7ed432486d114c327f837e4ef424abb29c220fe6ee4f3628`.
This checkpoint compiles that unmodified source into a clean static Linux
x86-64 binary, SHA-256
`40d45fa9921d6b34ce545b8f7ecef620cea28ee50d2ae86793e4be15d9f472f2`.
It compares **that clean build** with the exact supplied ELF. Matching
behavior on the tested inputs does not establish the supplied ELF's source
revision, compiler settings, seed or complete semantic equivalence.

The source calls `time()` to seed its generator and may use the current date.
Each paired comparison therefore runs both binaries sequentially in one
Linux/amd64 container, checks the same input bytes in the guest, and accepts
the pair only when `date +%s` before and after both processes is identical.
The second repetition reverses execution order and uses a different second.
The harness injects no time shim into either process. UTC is fixed for both.
Five attempts crossed a clock boundary or repeated an epoch and are retained
as discarded observations; ten same-second pairs were accepted.

| Stdin case | Accepted pairs | Exit per executable | Stdout/stderr bytes equal | Path check |
|---|---:|---:|---|---|
| Empty | 2 | 1 | Both streams, both pairs | No password |
| Invalid MathID | 2 | 1 | Both streams, both pairs | `Bad MathID!` |
| Valid v14.1 | 2 | 0 | Both streams, both pairs | Password printed |
| Valid v14.0 | 2 | 0 | Both streams, both pairs | Password printed |
| Default expiry | 2 | 0 | Both streams, both pairs | Password printed |

The valid-v14.1 clean stdout SHA-256 differs across its two accepted seconds,
while each protected output equals its same-second clean output byte for
byte. The paired observations comprise 20 accepted executable runs and five
discarded two-executable attempts. Exact inputs, epochs, statuses, byte
counts, stream hashes, equality results, host measurements and discarded
attempts are retained in `VMP_SUPPLIED_MOROK_KEYGEN_BEHAVIOR_CAPTURE.json`.
Its SHA-256 is
`342fae9503234c785bf071957b034a787173f6e6022d0b1b3509ae214b2b24ca`.
The companion evidence manifest pins source, tool, image and runner hashes.

The container has no network, no capabilities, a read-only root, a 512 MiB
memory limit, 64-process limit, 16 MiB temporary filesystem, 2 MiB output
limit per stream and a 15 s wrapper timeout per attempted pair. Accepted
wrapper elapsed times were 478,264,666–593,447,208 ns
(0.478–0.593 s to three significant figures), including Docker startup and
both executables. Host client peak resident values were
47,415,296–48,037,888 bytes; they are not guest peak memory. No Chernobog
recovery, edge-accuracy or plugin speed claim follows from this comparison.

## Reproduction and bounds

```sh
python3 -B tests/run_supplied_morok_keygen_pair.py \
  --morok-dir ../morok \
  --sample samples/int_woma_keygen-linux-x86_64-static \
  --output-dir build/supplied-keygen-pair-reproduction
```

Use a new output directory. The exact process-output hashes change with the
clock; the required checks are byte equality within each accepted second,
both execution orders, distinct seconds for repetitions and a changed
valid-v14.1 output across those seconds. A wrong supplied-file hash is
rejected before building or executing either program.

For `K` cases, `R` accepted repetitions and at most `A = 12` attempts per
repetition, the harness launches at most `2KRA` guest executables. Hashing
the two binary artifacts of total size `B` and at most `O` bytes of output
per attempted executable costs `O(B + KRAO)` host time; the report retains
`O(KRA)` fixed-size hashes and metadata. The independent guest executions
and container startup are separately bounded by the per-attempt timeout.
Counts are dimensionless; sizes are bytes; elapsed values are nanoseconds.

## Assumption register and bounded expansion

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| S1 | The Morok source is a plausible original for this supplied ELF. The source-candidate interpretation depends on that lineage; observed finite-input equality does not. | Obtain a source-to-artifact build record or a matching clean original executable. Changed source or sample SHA-256 rejects this harness. |
| S2 | Same-second bounds and UTC give both processes the same time-dependent input. The paired-output interpretation depends on this clock behavior. | Check before/after seconds, reverse order, retain discarded crossings, and require the valid output to change across distinct seconds. An internal alternate clock source would falsify broader time-control claims. |
| S3 | The identified Linux/amd64 container executes these finite normal-completion paths consistently. The process comparison depends on that engine. | Repeat on physical x86-64 or an independent emulator and compare exact outputs and entered state; architecture-wide fidelity remains unknown. |
| S4 | The five finite stdin cases exercise the named rejection and password paths. The case-level conclusion depends on those exact bytes. | Check guest input SHA-256, status and path text; add boundary/fuzz inputs and compare selected memory and defined flags before claiming wider equivalence. |
| S5 | The supplied hash identifies the exact sealed, packed keygen. Its use as a supplied-sample control depends on that identity. | Rehash before and after; a deliberately wrong sample is rejected before any execution. Audit and build lineage remain separate claims. |

**High impact:** the exact supplied packed sample now has a finite-input
candidate-source process oracle, including both valid version paths.
**Medium risk:** same-second timing does not prove the two binaries share all
unobserved time or entropy inputs. **Low impact:** equal stdout, stderr and
exit status do not establish equal internal states or protected-edge recovery.

QG1: technical claims only. QG2: S1–S5 include falsification probes.
QG3: five named cases, both orders, temporal control, attribution and exact
captured outputs are covered; the complete review remains in progress.
QG4: byte, second, nanosecond and process-count arithmetic are explicit.
QG5: finite behavior, source lineage, guest fidelity and native analysis are
kept distinct. QG6: local primary source, exact binaries, identified tools,
container image and complete captured report are pinned. QG7: wider input
and state oracles are bounded above.
