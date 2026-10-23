# Address-keyed expression recovery

The scalar MBA adapter admits address values in local expression proofs. It treats
an address as an opaque bitvector, without assuming a concrete stack location,
alignment, or equality between distinct frame objects. The available SDK operand
is retained for emission. Its identity includes the owner, offset or local index,
width, value number, and full input/output access extents. The source domain and
the emitted expression are checked independently before a rewrite is committed.

Local candidate discovery also visits computed call arguments. It simplifies
eligible pure subexpressions without changing the call, argument slots, or calling
convention. The existing shared function budget and proof gates still apply.

One bounded normalization handles both associations of this word identity:

```text
(x | c) - x + (x & d) = (x & (c ^ d)) ^ c   modulo 2^w
```

The terms `c & ~x` and `d & x` are disjoint, so adding them introduces no carry.
Partial masks remain partial: this identity does not assume the low bits of an
address are zero. Candidate and emitted-expression proofs still authorize the
result. Tests cover 8-, 16-, 32-, and 64-bit words with complete and partial masks
under both synthesis backends.

## Encoded addresses of mutable data

A separate AMD64 preallocation pass proves singleton load addresses through
read-only tables. It replaces an ordinary flat-segment indirect load with a
direct global read of the same width and destination. The pointed-to bytes remain
a runtime input; they are not read from the database to supply a constant value.
Read-only lookup dependencies are retained, and a fresh allocation pass is
requested after mutations.

This pass admits only readable writable targets within one mapped segment. It
retains barriers, persistent instructions, assertions, floating-point operations,
and unsupported address effects. It uses the finite evaluator's existing bounds,
with at most 4096 visited instructions, 32 attempted address proofs, and a 20 ms
scheduling allowance checked between attempts. It does not decode an FS/GS address
as a flat data address.

## Validation

`tests/test_mba_address_expressions.py` compares the source reference, the native
AMD64 fixture, and compiled reconstructed expressions for 256 inputs. The fixture
checks address-derived keys, masked sums, and distinct addresses in one frame.
Reconstruction preserves the frame aliases printed by IDA: two expressions such
as `&savedregs - 8` and an object at `rbp-8` must refer to the same storage. The
exported pseudocode and statistics are retained alongside the reconstruction.

The table-argument fixture also changes a mutable target before each input and
checks that its recovered read remains a variable load. Mutable table entries and
two stateful input calls remain negative controls.
