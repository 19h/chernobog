# Saved status flags in native stack replay

The x86 native interpreter previously erased its stack and stack-pointer facts
at `PUSHF/PUSHFD/PUSHFQ`, then erased its complete state at `POPF/POPFD/POPFQ`.
It now stores a bounded stack word with individually known bits. `PUSHF*`
copies the six tracked status flags (CF, PF, AF, ZF, SF, OF) into their
architectural bit positions. `POPF*` restores only bits known in the popped
word. A constant ordinary `PUSH` can also supply a known flags word. The
normal-completion transfer is limited to 32-bit and 64-bit operand sizes in
the existing x86/i386 analysis modes. Unsupported sizes and stack writes
continue to invalidate the saved word.

This advances review row 2a through the same transfer function used by owned
and ownerless native inspection. It does not model other EFLAGS/RFLAGS bits,
privileged flag changes, 16-bit modes, or exceptional paths. Intel specifies
the stack and status-flag behavior in the
[PUSHF/PUSHFD/PUSHFQ and POPF/POPFD/POPFQ instruction references](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html).

## Matched evidence

The final fixture binaries and probe were identical across the prior installed
plugin and new built plugin for each architecture. The prior plugin missed
three exact `SETcc` admissions: saved CF, saved OF after fully defined
arithmetic, and CF loaded from an immediate flags word. The new plugin proves
all three. A memory overwrite of the saved stack word and a dynamic flags
word retain no exact `SETcc` fact in both architectures. The independent native
oracle checks all six status bits before and after a saved-flags restoration
for each of 256 inputs per architecture.

| Architecture | Native checks | New IDA checks | Prior plugin missing facts | New plugin facts |
|---|---:|---:|---:|---:|
| x86-64 Mach-O | 4,606 | 67/67 | 3 | 3 |
| i386 ELF | 4,606 | 67/67 | 3 | 3 |

The i386 process used the pinned Linux/QEMU image. All 21 CTest suites pass.
On the exact supplied `samples/foo_x86_vmp` initializer, the new plugin still
completes 75 nodes and 77 edges with the same three unresolved condition
records. All eight inspection checks pass, and the IDB inventory is unchanged.
The protected control establishes no recovery gain at that root.

Exact source, fixture, report, plugin, IDA and CTest hashes are in
`VMP_SAVED_FLAGS_EVIDENCE.json`. Reproduce the paired owned fixture with:

```sh
python3 -B tests/run_native_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --output-dir build/vmp-saved-flags-repeat \
  --linux32-image chernobog-vmp-linux32:test
```

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| S1 | In normal completion, `PUSHF*` copies and `POPF*` restores the six unprivileged status bits at the selected operand width. Exact flag facts depend on this. | Compare Intel's instruction contract; execute before/after snapshots for all six bits over 256 inputs on both architectures. A faulting instruction or 16-bit operand is outside this transfer. |
| S2 | A tracked stack suffix still denotes the same top words until an explicit or unmodeled write invalidates it. Saved-word restoration depends on this. | Overwrite the saved stack slot and require abstention; vary the pushed word from input and require abstention; compare owned control results on both architectures. |
| S3 | The prior/new IDA probes differ only in plugin bytes. Red/green attribution depends on matched fixtures and probe. | Verify per-architecture binary, source-script and IDA hashes, and compare the three missing and three admitted exact facts. |
| S4 | The supplied VMP root is the prior 75-node initializer. Its negative-effect result depends on exact sample identity and scope. | Rehash the supplied input; compare nodes, edges, records and before/after IDB inventories. Other roots and dynamic paths require independent measurements. |

`PUSHF*` and `POPF*` visit six flag positions: O(1) time and O(1) additional
space per transfer. The stack suffix retains at most 64 words, each with a
64-bit known mask and 64-bit value. A dataflow join takes O(min(S1, S2)) time
and space for suffix lengths S1 and S2, both at most 64 words. Bit counts and
check counts are dimensionless integers; no rounding is involved.

- **High impact:** saved status bits and literal flags words can now support
  exact native condition proofs across a local stack transfer.
- **Medium impact:** the supplied protected root remains unresolved, so the
  measured improvement is confined to the independent fixture corpus.
- **Low impact:** unmodeled flags and exceptional execution remain explicit
  abstention boundaries.

QG1: no normative premise. QG2: S1–S4 include falsification probes. QG3:
owned native controls, both architectures, a matched prior plugin and a
protected-sample control cover this bounded change; the full review remains
open. QG4: operand widths, bit positions, counts and bounded complexity are
specified. QG5: overwritten, dynamic, unsupported-size and exceptional cases
do not inherit an exact fact. QG6: Intel's primary instruction reference and
hash-matched execution/IDA reports support the claims. QG7: protected and
ownerless effectiveness beyond the shared transfer remains unmeasured.
