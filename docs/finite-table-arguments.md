# Constant table expressions in call arguments

Chernobog simplifies bounded read-only table expressions in call arguments even
when the callee is already direct. For example, an argument of the form
`second[first[index] ^ key] ^ index` may have one value for every possible byte
index. The pass checks the complete input domain before replacing it with that
value. It does not require emulation.

Argument roots receive their own bounded pass. This prevents unrelated nested
loads from consuming the argument-recovery budget. The preallocation callback
runs the pass even for functions without indirect control transfers and requests
a fresh allocation pass after a rewrite.

The pass preserves the call, its argument types, and its calling convention. A
replacement requires one value across every enumerated assignment, read-only
backing bytes, and recorded dependencies on those bytes. Expressions containing
calls, barriers, persistent instructions, assertions, or floating-point operations
are retained. Lookup reads require readable, immutable backing bytes; mutable
memory is never replaced with its initial contents. Current database values are
not treated as runtime observations.

Each argument pass inspects at most 4096 microinstructions and attempts at most 32
arguments within a 20 ms scheduling budget. Individual proofs retain the finite
domain's limits of 4096 nodes, 256 complete assignments, and two million evaluation
steps. A budget limit leaves the expression unchanged.

The regression fixture covers a direct call with a constant table argument, a
mutable table, and two stateful calls whose results must remain distinct. Its
reconstructed C is compiled and compared with the native fixture for all 256 byte
inputs. Run it with `tests/test_finite_table_arguments.py --ida <idat> --plugin
<plugin> --output-dir <directory>`.
