# Static indirect-jump census of supplied x86-64 binaries

## Scope and result

The source-pinned `VMP_PROTECTED_INDIRECT_CENSUS_EVIDENCE.json` records four
fresh IDA 9.4 SP1 autoanalysis processes using the same built plugin and
probe. The probe visits IDA code heads in executable segments, decodes
`NN_jmpni`, and classifies exact bytes. It does not discover code in data
items, establish that a code head executes, or attribute an instruction to
the protector rather than linked code. The supplied Hikari Mach-O is ARM64
and is outside this x86-64 instruction census.

| Exact input | Executable code heads | Decoded indirect jumps | Byte classes | Location bound |
| --- | ---: | ---: | --- | --- |
| `samples/foo_x86_orig` | 9 | 1 | one `FF 25` direct-memory | `__stubs`, zero in `__text` |
| `samples/foo_x86_vmp` | 219 | 2 | one `FF E6` register; one `41 FF E2` REX register | both in `.dlC1_hidden`; zero code heads in `__text` |
| `samples/boo-linux-x86_64-static` | 187,675 | 13 | nine unprefixed register; four other SIB-indexed | all in `.text`; zero jumps among 74,290 `.morok_npack_rx` code heads |
| `samples/int_woma_keygen-linux-x86_64-static` | 175,092 | 17 | nine unprefixed register; eight other SIB-indexed | all in `.text`; zero code heads in `.hdmoh1mxteam2f` |

The VMP REX register site is the previously inspected ownerless
`0x10024801a` (`JMP r10`), whose static target remains unresolved. The
Morok `other` examples are exact `FF 24` SIB-indexed forms with 7-byte
encodings. Their runtime reachability and function lineage are **unknown**.
No decoded protected-form `JMP [SP]` or `FF 25` appears in these three
protected binaries under this scan. The original's `FF 25` belongs to an
import stub, so it cannot validate the new local-write memory fact.

**Inference:** the present decoded protected sites cannot measure a recovery
gain for the new stack-top or direct-memory facts. Measuring those facts on
protector output requires a code path containing the form, or observed
runtime bytes and execution boundaries that expose it. The count alone does
not show whether packed code will contain such a form after unpacking.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| IC1 | IDA code heads define the universe of this static count. All absence statements depend on that scope. | Compare executed instruction addresses and runtime-mapped bytes against the saved IDB. Any executed nonhead is outside the census, not evidence of absence. |
| IC2 | The section names in the loaded IDB identify the reported locations. Location claims depend on that mapping. | Reparse the exact Mach-O/ELF headers and runtime mappings; reject a location claim if segment bounds or permissions differ. The names alone do not prove packing or execution. |
| IC3 | Loading the current plugin does not itself change the counted code-head population before a native query. The cross-input count comparison depends on this. | Repeat each scan in plugin-free IDA on the same binary and compare every code-head inventory; the present report does not establish that equivalence. |
| IC4 | The four inputs are the exact catalogued artifacts. Input-specific counts depend on their identity. | Require the input SHA-256, IDA/probe/plugin/environment hashes and raw report/run hashes in the certificate. |
| IC5 | The six byte classes preserve their exact encoding boundaries. Class counts depend on this classifier. | The independent verifier recomputes the class of every retained example and checks all per-segment and global count sums. Unretained examples beyond the 16-per-class cap are covered only by the probe's counted traversal. |

## Bounds and quality gates

For `H` IDA code heads and `S` executable segments, the scan takes `O(H)`
decoded-head visits and retains `O(S × 6 × 16)` example rows plus segment
counts. The run manifests contain exact process nanoseconds; their variation
is not a throughput estimate. Counts use integer units with no rounding.

| Impact | Bounded consequence |
| --- | --- |
| High | Packed/runtime code can be absent from or misclassified in IDA's static code-head universe; static absence cannot establish runtime absence. |
| Medium | The observed VMP unresolved frontier is register-indirect; the Morok SIB forms in `.text` are candidate sites for separate reachability and provenance checks. |
| Low | Zero decoded protected stack-top/direct-memory forms prevents an effectiveness claim for those new facts on this corpus. |

QG1: technical claims only. QG2: IC1–IC5 and probes above. QG3: all four
supplied x86-64 inputs and the ARM64 exclusion are explicit. QG4: exact
integer counts and complexity bounds are stated. QG5: decoded head,
executed instruction and protector lineage remain distinct. QG6: raw IDA
reports, manifests and source hashes are local primary artifacts. QG7:
runtime blind spots and candidate sites are bounded. The full review and
protected-mode recovery benchmark remain in progress.
