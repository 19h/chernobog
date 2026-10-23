# Native forwarding adapters

Chernobog inlines small AMD64 call/return adapters during Hex-Rays' initial
microcode generation. This removes wrapper names from callers and exposes the
underlying call to normal argument recovery and pseudocode rendering. It runs
when deobfuscation is requested for the caller, including automatic mode.

The implementation asks the released SDK's native inliner to generate the
adapter body. It does not replace an indirect target with the current contents
of a pointer slot, change function flags, patch native bytes, or rename the
callee. A mutable function pointer remains a load at the call site.

## Admission

| Native body | Treatment |
| --- | --- |
| `push rax; call target; pop rcx; ret` | Inline; equivalent scratch-register pops are accepted |
| Balanced `sub rsp, N; call target; add rsp, N; ret` | Inline for bounded, aligned reservations |
| Standard `push rbp; mov rbp, rsp` frame, one call, matching teardown | Inline with an optional bounded local reservation |
| `push rax; call target; pop rax; ret` | Retain the wrapper; it restores the incoming return register |
| Return arithmetic, additional calls, branches, memory side effects, or nonvolatile-register changes | Retain the wrapper |

Every candidate is decoded from its current function bytes. It must occupy one
contiguous function of at most 64 bytes and eight instructions. Calls must be
near calls and returns must not pop arguments. No name pattern or pseudocode
similarity admits a function. Both direct and indirect calls inside a supported
adapter retain their original native behavior.
The model is the ordinary AMD64 calling convention; an explicitly supplied
custom register calling convention rejects automatic inlining.
PE images additionally require the normal Windows x64 shadow-space reservation.

Nested adapters are supported. A call-site/target pair is considered once per
generation callback; recursive generation is guarded. Each callback allows at
most 128 expansions and 4,096 blocks. Unsupported architectures and larger
bodies retain ordinary calls. Candidate scans are bounded by
`O(K * B * I)`, where `K <= 128`, `B <= 4096`, and `I <= 8`, excluding the SDK's
inlining work. Tracking uses `O(K * B)` space in the worst case.

## Validation

The public fixture covers direct and mutable indirect calls, stack alignment,
frame-pointer wrappers, nested adapters, adjusted return values, and restoration
of the incoming RAX value. Its native AMD64 executable and reconstructed caller
C must produce the same results and call observations on 16 cases, including
changing the indirect target. The probe also checks repeated uncached
decompilation, function flags, and native bytes.

```sh
python3 tests/test_forwarder_inline.py \
    --ida /path/to/idat --plugin /path/to/chernobog.dylib \
    --output-dir /tmp/forwarder-inline
```

This is bounded adapter inlining, not general interprocedural optimization.
Functions outside these shapes remain available for analysis as separate calls.
