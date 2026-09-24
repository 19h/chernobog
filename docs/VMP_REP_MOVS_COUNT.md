# Natural-address-size REP MOVS completion count

This is the historical 27/34 checkpoint at commit
`f071baa4764cca358516f7dbe8bf59a8a64f4afc`; the later exact stack-store
result is recorded in `VMP_STACK_TOP_STORES.md`.

The native x86 state transfer now writes zero to the full RCX/ECX repeat-count
register after normally completed `REP MOVS` with natural address size. Intel's
[REP instruction reference](https://cdrdv2-public.intel.com/868141/253667-089-sdm-vol-2b.pdf)
specifies a count selected by address size and repetition until that count
reaches zero. Plain `MOVS` still retains RCX/ECX; `REPNE` and non-natural
address-size forms still invalidate it. RSI/ESI, RDI/EDI, retained stack words
and writable-memory bytes remain invalidated because their post-state or
destination alias is not established. The six tracked status bits are retained.
This is a normal-completion fact; faults and incomplete execution are outside
the admitted transfer.

The existing `df_rep_movs_count_unknown` fixture now sets its incoming count
to `input & 1` before `REP MOVSB`, so 256 native inputs exercise both zero and
one iterations. It adds the post-count to a target address and returns through
that address. Both x86-64 and i386 native drivers pass 20,990 checks; the
ownerless drivers pass 4,094 checks and reject their corrupted-result controls.
The owned IDA probe passes 269 assertions and observes the exact user code xref;
the ownerless probe passes 1,042 assertions and retains an unchanged IDB
inventory, per architecture.

The matched prior-transfer control replaces only this state step with its old
count invalidation, then rebuilds and signs the plugin. Prior and current runs
use the same fixture, probe, runner, binary and IDA hashes; the production
source differs by the count-state transfer alone. The
expectation-only `CHERNOBOG_REP_COUNT_BASELINE=1` flag makes their IDA
environment hashes differ. The selected transfer changes from an unresolved
candidate to a proved register-definition target in both analysis paths and
architectures. All other 45 selected site outcomes are unchanged.

| Architecture and path | Prior correct / oracle edges | Current correct / oracle edges | Current false edges | Current unresolved eligible sites |
|---|---:|---:|---:|---:|
| x86-64 owned | 26/34 | 27/34 | 0 | 4/31 |
| x86-64 ownerless | 26/34 | 27/34 | 0 | 4/31 |
| i386 owned | 26/34 | 27/34 | 0 | 4/31 |
| i386 ownerless | 26/34 | 27/34 | 0 | 4/31 |

The exact current fraction is 27/34 = 79.4% to three significant figures.
Fifteen sites that depend on the concrete driver's initial-state or caller
contract remain excluded from the static denominator and unresolved. Wrapper
elapsed nanoseconds and peak resident bytes in the evidence JSON measure the
launcher including IDA startup, not isolated plugin execution; no speedup or
plugin-memory claim follows. All 21 CTest suites pass.

Reproduce from a clean checkout at the commit carrying this change with fresh
output directories. First run `run_native_dataflow.py` and
`run_ownerless_dataflow.py` with `--ida`, `--plugin`, `--linux32-image
chernobog-vmp-linux32:test` and `--output-dir` as in
`VMP_MOVS_FLAGS.md`; score the two reports with
`score_native_edge_benchmark.py`. The ignored exact reports and their SHA-256
values are recorded in `VMP_REP_MOVS_COUNT_EVIDENCE.json`. The prior plugin
control used `--rep-count-baseline` with the old transfer rebuilt from the
same tree; the frozen prior plugin SHA-256 distinguishes it. The earlier
26/34 source-oracle checkpoint in `VMP_NATIVE_EDGE_BENCHMARK.md` is historical
at commit `0b91fc548e915461790da1d7146cab812df65fcb`.

The REP MOVS state step clears at most 64 retained stack words and 128 retained
writable bytes, so its transfer costs O(S + B) time and O(1) additional space
for S stack words and B memory bytes. Writing the count word costs O(1).
Counts and edges are dimensionless; timing is nanoseconds and resident size is
bytes in the evidence.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| R1 | The decoded F3 prefix and natural address size denote a normal-completion `REP MOVS` count of zero. The new target proof depends on this. | Compare Intel's REP specification; execute zero- and one-iteration native cases on both architectures. Add address-size-override and `REPNE` controls before relaxing the guard. |
| R2 | The source-annotated target label is the exact fixed edge. The 27/34 score depends on this. | Rehash source and probes; resolve labels independently with `llvm-nm`; require exact IDB user xrefs and ownerless read-only proofs. |
| R3 | Prior/current binaries, IDA and probes are matched; the only semantic plugin difference is the count transfer. Attribution of one additional edge depends on this. | Compare binary/tool/source hashes and all 46 per-site classifications, then rerun with the prior transfer and baseline expectation flag. |
| R4 | Wrapper `wait4` accounting describes a launcher process. Resource observations depend on this scope. | Instrument IDA/plugin separately before making a plugin performance comparison. |

- **High impact:** a guaranteed postcondition can prove a target even when the
  incoming count is unknown to static analysis.
- **Medium impact:** repeated `STOS` and `LODS` may admit a similar count
  postcondition after separate instruction-specific controls.
- **Low impact:** `REPNE`, address-size override, faults and protected-binary
  effectiveness remain unmeasured or conservatively unresolved.

QG1: technical scope. QG2: R1–R4 have falsification probes. QG3: the count
transfer and selected native edge change are covered; broader review row V is
incomplete. QG4: edge arithmetic, units and complexity are explicit. QG5:
unsupported prefixes and address sizes retain uncertainty. QG6: Intel's
primary specification and exact source, binary, plugin, IDA and report hashes
support the claims. QG7: adjacent string operations and protected-mode limits
are bounded above.
