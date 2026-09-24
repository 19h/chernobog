# Bounded corpus process termination

The shared paired-corpus process runner starts each command with
`start_new_session=True`, polls elapsed time and temporary stdout/stderr file
sizes, then uses `wait4` for process status and peak resident memory. During a
concurrent CTest run, its output-limit branch raised `PermissionError` from
`os.killpg`; the suite failed without returning a measurement. Python documents
the child-session creation and process-group operations
([subprocess](https://docs.python.org/3/library/subprocess.html),
[os](https://docs.python.org/3/library/os.html)). The exact cause of the
observed denial is **unknown**.

The bounded shutdown path now reads the live child's process-group ID. It
signals the group only when that ID equals the unreaped child PID. A denied or
vanished group signal falls back to a direct SIGKILL of the child PID.
`wait4` still supplies the exit status and resource usage, and the existing
`timed_out`/`output_exceeded` fields still mark rejected runs. The direct-PID
fallback may leave descendants running; it does not establish complete
process-tree termination. Container-backed callers retain their separate
named-container cleanup on rejected runs.

## Validation

Two new tests first failed against the prior runner: injected group-signal
`PermissionError` escaped, and a simulated child in another process group
still triggered `killpg`. With the new path, injected `PermissionError` and
`ProcessLookupError` each cause the output-limited child to exit by signal,
return `output_exceeded=true`, and cap captured stdout at 2,097,152 bytes.
The wrong-group control never signals a group and returns a signaled,
`timed_out=true` child. Ordinary success, timeout, output-limit and `wait4`
accounting controls also pass.

The complete CTest suite passes 21/21, including 21 Python corpus-admission
tests. Three new no-argument runs of the exact supplied original/protected
hello-world pair each exit zero with equal 11-byte stdout, empty stderr and
unchanged input hashes. These controls test normal runner behavior after the
shutdown change; they do not measure a latency improvement. Source, input and
report hashes are in `VMP_PROCESS_TERMINATION_EVIDENCE.json`.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| P1 | `start_new_session=True` normally makes the child its own process-group leader. Group-signaling scope depends on the current group ID, not this expectation alone. | Force `getpgid` to report another group and require zero `killpg` calls; ordinary timeout and output-limit controls require signaled child exits. |
| P2 | The parent can directly signal and reap its own child after a group-signal failure. Returning a bounded measurement depends on this. | Inject `PermissionError` and `ProcessLookupError` into `killpg`, require direct-PID termination, negative exit status and completed `wait4` accounting. A direct-PID permission denial remains an external execution failure. |
| P3 | A direct-PID fallback is sufficient to reject this measurement, but does not imply descendant cleanup. | Require `timed_out` or `output_exceeded` to remain true; inspect container caller cleanup separately. A descendant-spawning workload needs its own termination audit. |
| P4 | The supplied pair tests the unchanged successful-execution path. Any behavior comparison depends on exact input identities. | Rehash both binaries before and after three runs; require equal stdout/stderr bytes and exit codes per trial. Other inputs and protected families remain unmeasured here. |

The monitor performs O(P) polls for P iterations with O(1) additional state
per poll. Each returned stream is limited to 2,097,152 bytes (2 MiB), so the
two returned streams require at most 4,194,304 bytes (4 MiB) plus Python
object overhead. The temporary files can exceed the 2 MiB aggregate trigger
between polls; the trigger is not a strict disk-write quota. The added
termination branch uses O(1) system calls and memory. Elapsed time is measured
in nanoseconds and peak resident memory in bytes after the existing platform
conversion.

- **High impact:** failure to signal a process group no longer loses the
  benchmark's rejected-run result when direct child signaling succeeds.
- **Medium impact:** the live group-ID check avoids signaling a different
  process group during a startup-state or identity mismatch.
- **Medium impact:** descendant cleanup under direct-PID fallback remains
  unproved; broader protected benchmark completeness is still open.

QG1: technical scope. QG2: P1–P4 with injected and actual-process probes.
QG3: shared runner error and successful paired path are covered; the full
review benchmark matrix remains open. QG4: byte limits, units and asymptotic
costs are explicit. QG5: missing group, denied signal, wrong group and
descendant boundary are represented. QG6: Python's process API contract,
actual child exits and hashed paired reports support the claims. QG7: bounded
runner and benchmark limitations are stated.
