"""Typed, read-only semantic checks on captured primitive matcher inputs.

The input contract is normal-completion scalar microcode with unconstrained
snapshot bytes. No claim is made about native reachability, additional CFG
facts, memory aliasing between different storage classes, faults or a live
rewrite. An UNKNOWN query never proves equivalence or non-equivalence.
"""

import ctypes
import hashlib
import importlib.metadata
from pathlib import Path

import z3

from mba_match_replay import mask, packed
from mba_matching_diagnostics import parse_constant_failure, require

ENGINE = "4.16.0"
PACKAGE = "4.16.0.0"
BINARY = {"add", "sub", "mul", "and", "or", "xor"}
UNARY = {"bnot", "neg"}
CONVERSION = {"mov", "xdu", "xds", "low", "high"}
FLAGS = {"cfadd", "ofadd", "seto", "setp"}
COMPARISON = {"setnz", "setz", "setae", "setb", "seta", "setbe", "setg", "setge", "setl", "setle"}
PREDICATE = FLAGS | COMPARISON | {"sets", "lnot"}
CONTRACTS = {
    "Sub1_FactorRule_2": ("add", "subtract_one"),
    "And_Rule_3": ("and", "identity"),
    "Mul_Rule_4": ("mul", "negate"),
}


def engine_provenance():
    require(z3.get_version_string() == ENGINE, "unexpected Z3 engine")
    require(importlib.metadata.version("z3-solver") == PACKAGE, "unexpected Python Z3 package")
    root = Path(z3.__file__).parent
    names = ["__init__.py", "z3.py", "z3core.py", "z3types.py", "z3consts.py"]
    # Bind the CDLL retained by the pinned dispatcher's actual version function.
    # The package contains libraries for multiple operating systems.
    function = z3.z3core.Z3_get_version.__defaults__[0].f
    loaded = [v for v in function._objects.values() if isinstance(v, ctypes.CDLL)]
    require(len(loaded) == 1, "ambiguous loaded Z3 library")
    library = Path(loaded[0]._name).resolve()
    require(library.is_relative_to(root.resolve()), "Z3 library outside pinned package")
    pins = {"<python-z3>/" + n: hashlib.sha256((root / n).read_bytes()).hexdigest() for n in names}
    pins["<python-z3>/" + str(library.relative_to(root.resolve()))] = hashlib.sha256(
        library.read_bytes()
    ).hexdigest()
    return {"engine": ENGINE, "package": PACKAGE, "sha256": pins}


class Unsupported(ValueError):
    pass


class Primitive:
    """One scalar root; operands preserve width, versions and byte overlap."""

    def __init__(self, root, model, root_iprops=None):
        tags = model["mops"]
        self.op = {code: name for name, code in model["ops"].items()}.get(root[3])
        self.width = root[1]
        if root[0] != "n" or self.width not in (1, 2, 4, 8):
            raise Unsupported("unsupported root width or kind")
        if root[2][3] != 0:
            raise Unsupported("root value properties")
        if root_iprops is not None and (type(root_iprops) is not int or root_iprops != 0):
            raise Unsupported("root instruction properties")
        if self.op in PREDICATE and root_iprops is None:
            raise Unsupported("predicate integer/effect metadata unavailable")
        if self.op not in BINARY | UNARY | CONVERSION | PREDICATE:
            raise Unsupported("unsupported arithmetic root")
        if root[4] is None or (root[5] is None) != (
            self.op in UNARY | CONVERSION | {"sets", "lnot"}
        ):
            raise Unsupported("arithmetic arity")
        if self.op in PREDICATE - {"lnot"} and self.width != 1:
            raise Unsupported("predicate result must be one byte")
        self.bits = self.width * 8
        self.leaves, self.cells, self.loads, self.widths = {}, {}, [], {}
        for path, node in (("L", root[4]), ("R", root[5])):
            if node is None:
                continue
            if node[0] != "v":
                raise Unsupported("nonprimitive arithmetic subtree")
            kind, width, version, props, value = node[2]
            if width not in (1, 2, 4, 8) or node[1] != width:
                raise Unsupported("operand width or nested result mismatch")
            if self.op not in CONVERSION | PREDICATE and width != self.width:
                raise Unsupported("implicit operand width conversion")
            if self.op == "mov" and width != self.width:
                raise Unsupported("implicit MOV width conversion")
            if self.op in ("xdu", "xds") and width > self.width:
                raise Unsupported("extension narrows its input")
            if self.op in ("low", "high") and width < self.width:
                raise Unsupported("extraction widens its input")
            self.widths[path] = width
            if props != 0:
                raise Unsupported("operand value properties")
            if kind == tags["n"]:
                if value is None:
                    raise Unsupported("missing numeric payload")
                self.leaves[path] = {"constant": value & mask(width)}
                continue
            if kind == tags["r"]:
                if value < 8:
                    raise Unsupported("reserved or condition microregister needs a state contract")
                base = ["register", version, value]
            elif kind == tags["S"] and value is not None:
                base = ["stack", version, value[0], value[1]]
            elif kind == tags["v"]:
                base = ["global", version, value]
            elif kind == tags["l"] and value is not None:
                base = ["local", version, value[0], value[1], value[2]]
            elif kind == tags["d"] and value is not None:
                ins = value
                if (
                    ins[0] != model["ops"]["ldx"]
                    or ins[1] != 0
                    or ins[5] != [tags["z"], width, 0, 0, 0]
                    or ins[3][1] != 2
                    or ins[4][1] not in (4, 8)
                    or any(
                        m[0] not in (tags["r"], tags["n"])
                        or m[3] != 0
                        or (m[4] is None if m[0] == tags["n"] else m[4] < 8)
                        for m in ins[3:5]
                    )
                ):
                    raise Unsupported("unsupported nested value or explicit-load contract")
                # Separate occurrences remain independent, even for equal EAs.
                base = ["explicit_read", path, 0]
                self.loads.append({"path": path, "instruction": ins})
            else:
                raise Unsupported("unsupported operand effect or storage")
            keys = []
            for offset in range(width):
                identity = base[:-1] + [base[-1] + offset]
                key = packed(identity)
                self.cells.setdefault(key, identity)
                keys.append(key)
            self.leaves[path] = {"bytes": keys}
        if self.op in FLAGS | COMPARISON and self.widths["L"] != self.widths["R"]:
            raise Unsupported("predicate operand widths differ")

    def values(self, cells):
        require(set(cells) == set(self.cells), "counterexample byte population")
        for byte in cells.values():
            require(type(byte) is int and 0 <= byte <= 255, "counterexample byte domain")
        return {
            path: (
                value["constant"]
                if "constant" in value
                else sum(cells[k] << (8 * i) for i, k in enumerate(value["bytes"]))
            )
            for path, value in self.leaves.items()
        }

    def integer(self, values):
        require(set(values) == set(self.leaves), "integer operand population")
        require(
            all(type(v) is int and 0 <= v <= mask(self.widths[p]) for p, v in values.items()),
            "integer operand width",
        )
        x, y = values["L"], values.get("R", 0)
        input_bits = 8 * self.widths["L"]
        sign = 1 << (input_bits - 1)
        signed = lambda v: v - 2 * sign if v & sign else v
        outside = lambda v: not -sign <= v < sign
        result = {
            "add": lambda: x + y,
            "sub": lambda: x - y,
            "mul": lambda: x * y,
            "and": lambda: x & y,
            "or": lambda: x | y,
            "xor": lambda: x ^ y,
            "bnot": lambda: ~x,
            "neg": lambda: -x,
            "mov": lambda: x,
            "xdu": lambda: x,
            "xds": lambda: (
                x - (1 << (8 * self.widths["L"])) if x & (1 << (8 * self.widths["L"] - 1)) else x
            ),
            "low": lambda: x,
            "high": lambda: x >> (8 * (self.widths["L"] - self.width)),
            "lnot": lambda: int(x == 0),
            "sets": lambda: int(bool(x & sign)),
            "cfadd": lambda: int(x + y > mask(self.widths["L"])),
            "ofadd": lambda: int(outside(signed(x) + signed(y))),
            "seto": lambda: int(outside(signed(x) - signed(y))),
            "setp": lambda: int(((x - y) & 255).bit_count() % 2 == 0),
            "setnz": lambda: int(x != y),
            "setz": lambda: int(x == y),
            "setae": lambda: int(x >= y),
            "setb": lambda: int(x < y),
            "seta": lambda: int(x > y),
            "setbe": lambda: int(x <= y),
            "setg": lambda: int(signed(x) > signed(y)),
            "setge": lambda: int(signed(x) >= signed(y)),
            "setl": lambda: int(signed(x) < signed(y)),
            "setle": lambda: int(signed(x) <= signed(y)),
        }[self.op]()
        return result & mask(self.width)

    def symbolic(self, prefix):
        cells = {key: z3.BitVec(prefix + ":" + key, 8) for key in self.cells}
        values = {}
        for path, value in self.leaves.items():
            if "constant" in value:
                values[path] = z3.BitVecVal(value["constant"], self.widths[path] * 8)
            else:
                parts = [cells[k] for k in reversed(value["bytes"])]
                values[path] = parts[0] if len(parts) == 1 else z3.Concat(*parts)
        x, y = values["L"], values.get("R")
        left_bits = self.widths["L"] * 8
        boolean = lambda condition: z3.If(
            condition, z3.BitVecVal(1, self.bits), z3.BitVecVal(0, self.bits)
        )

        def overflow(subtract):
            wide = (
                z3.SignExt(1, x) - z3.SignExt(1, y)
                if subtract
                else z3.SignExt(1, x) + z3.SignExt(1, y)
            )
            return boolean(
                z3.Extract(left_bits, left_bits, wide)
                != z3.Extract(left_bits - 1, left_bits - 1, wide)
            )

        def parity():
            difference = x - y
            count = sum(z3.ZeroExt(7, z3.Extract(bit, bit, difference)) for bit in range(8))
            return boolean((count & 1) == 0)

        result = {
            "add": lambda: x + y,
            "sub": lambda: x - y,
            "mul": lambda: x * y,
            "and": lambda: x & y,
            "or": lambda: x | y,
            "xor": lambda: x ^ y,
            "bnot": lambda: ~x,
            "neg": lambda: -x,
            "mov": lambda: x,
            "xdu": lambda: z3.ZeroExt(self.bits - left_bits, x),
            "xds": lambda: z3.SignExt(self.bits - left_bits, x),
            "low": lambda: z3.Extract(self.bits - 1, 0, x),
            "high": lambda: z3.Extract(left_bits - 1, left_bits - self.bits, x),
            "lnot": lambda: boolean(x == 0),
            "sets": lambda: boolean(z3.Extract(left_bits - 1, left_bits - 1, x) == 1),
            "cfadd": lambda: boolean(
                z3.Extract(left_bits, left_bits, z3.ZeroExt(1, x) + z3.ZeroExt(1, y)) == 1
            ),
            "ofadd": lambda: overflow(False),
            "seto": lambda: overflow(True),
            "setp": parity,
            "setnz": lambda: boolean(x != y),
            "setz": lambda: boolean(x == y),
            "setae": lambda: boolean(z3.UGE(x, y)),
            "setb": lambda: boolean(z3.ULT(x, y)),
            "seta": lambda: boolean(z3.UGT(x, y)),
            "setbe": lambda: boolean(z3.ULE(x, y)),
            "setg": lambda: boolean(x > y),
            "setge": lambda: boolean(x >= y),
            "setl": lambda: boolean(x < y),
            "setle": lambda: boolean(x <= y),
        }[self.op]()
        return result, cells, values

    def witness(self, model, cells):
        data = {
            key: model.eval(value, model_completion=True).as_long() for key, value in cells.items()
        }
        values = self.values(data)
        return {"bytes": data, "operands": values, "result": self.integer(values)}


def solve(condition, timeout_ms=250, resource_limit=100000):
    require(type(timeout_ms) is int and 1 <= timeout_ms <= 10000, "solver time budget")
    require(
        type(resource_limit) is int and 1 <= resource_limit <= 10000000, "solver resource budget"
    )
    solver = z3.Solver()
    solver.set(timeout=timeout_ms, rlimit=resource_limit)
    solver.add(condition)
    state = solver.check()
    if state == z3.sat:
        return "sat", solver.model(), ""
    if state == z3.unsat:
        return "unsat", None, ""
    return "unknown", None, solver.reason_unknown()


def primitive_reductions(root, model, timeout_ms=250, resource_limit=100000, root_iprops=None):
    try:
        primitive = Primitive(root, model, root_iprops)
    except Unsupported as error:
        return {"status": "unsupported", "reason": str(error)}
    first, a, values = primitive.symbolic("first")
    second, b, _ = primitive.symbolic("second")
    states, queries = [], []
    state, assignment, reason = solve(first != second, timeout_ms, resource_limit)
    result = {"target": "any_constant", "state": state, "reason": reason}
    if assignment is not None:
        witnesses = [primitive.witness(assignment, cells) for cells in (a, b)]
        require(witnesses[0]["result"] != witnesses[1]["result"], "false nonconstant witness")
        result["counterexamples"] = witnesses
    queries.append(result)
    states.append(state)
    for path, operand in values.items():
        if primitive.widths[path] != primitive.width:
            continue  # A width-changing MOV is not a typed replacement.
        state, assignment, reason = solve(first != operand, timeout_ms, resource_limit)
        result = {"target": path, "state": state, "reason": reason}
        if assignment is not None:
            witness = primitive.witness(assignment, a)
            witness["proposed"] = witness["operands"][path]
            require(witness["result"] != witness["proposed"], "false operand-reduction witness")
            result["counterexample"] = witness
        queries.append(result)
        states.append(state)
    status = (
        "value_reduction"
        if "unsat" in states
        else "unknown" if "unknown" in states else "primitive_reduction_refuted"
    )
    return {
        "status": status,
        "bits": primitive.bits,
        "queries": queries,
        "explicit_reads": primitive.loads,
        "snapshot_cells": primitive.cells,
        "ineligible_operand_targets": [
            p for p, w in primitive.widths.items() if w != primitive.width
        ],
    }


def constraint_binding(sample, model):
    """Validate the actual rejected instance for both solving and replay."""
    require(
        sample["outcome"] == "constant_constraint" and sample["rule"] in CONTRACTS,
        "constraint contract",
    )
    root = sample["input"]["root"]
    primitive = Primitive(root, model, sample["input"].get("root_iprops"))
    operation, proposed = CONTRACTS[sample["rule"]]
    require(
        primitive.op == operation and primitive.width == sample["width_bytes"],
        "constraint opcode/width",
    )
    bindings, omitted = parse_constant_failure(sample["reason"])
    constants = [v for v in bindings if v["name"] == "c_minus_1"]
    require(omitted == 0 and len(constants) == 1, "complete constant binding")
    # The actual matcher tries right as the numeric binding before commutation.
    path = "R" if root[5][2][0] == model["mops"]["n"] else "L"
    captured = root[5 if path == "R" else 4][2]
    binding = constants[0]
    require(captured[0] == model["mops"]["n"] and captured[4] is not None, "actual numeric binding")
    require(
        (captured[1], captured[4]) == (binding["width_bytes"], binding["value"]),
        "numeric binding differs from actual input",
    )
    require(
        captured[4] & mask(captured[1]) != mask(captured[1]),
        "rejected all-ones constraint actually satisfied",
    )
    x_path = "L" if path == "R" else "R"
    return primitive, proposed, x_path


def constraint_reduction(sample, model, timeout_ms=250, resource_limit=100000):
    primitive, proposed, x_path = constraint_binding(sample, model)
    original, cells, operands = primitive.symbolic("constraint")
    x = operands[x_path]
    target = x - 1 if proposed == "subtract_one" else x if proposed == "identity" else -x
    state, assignment, reason = solve(original != target, timeout_ms, resource_limit)
    result = {
        "status": state,
        "reason": reason,
        "bits": primitive.bits,
        "proposed": proposed,
        "x_path": x_path,
    }
    if assignment is not None:
        witness = primitive.witness(assignment, cells)
        x = witness["operands"][x_path]
        new = x - 1 if proposed == "subtract_one" else x if proposed == "identity" else -x
        witness["proposed"] = new & mask(primitive.width)
        require(witness["result"] != witness["proposed"], "false actual-instance counterexample")
        result["counterexample"] = witness
    return result


def verify_primitive_witness(root, sdk_model, query, root_iprops=None):
    """Recheck SAT witnesses with integer arithmetic, without a solver query."""
    primitive = Primitive(root, sdk_model, root_iprops)
    require(query["state"] == "sat", "only SAT has a reduction counterexample")
    require(
        query["target"] == "any_constant"
        or (
            query["target"] in primitive.leaves
            and primitive.widths[query["target"]] == primitive.width
        ),
        "typed reduction target",
    )
    witnesses = (
        query["counterexamples"] if query["target"] == "any_constant" else [query["counterexample"]]
    )
    for witness in witnesses:
        values = primitive.values(witness["bytes"])
        require(
            values == witness["operands"]
            and type(witness["result"]) is int
            and primitive.integer(values) == witness["result"],
            "integer witness replay",
        )
    if query["target"] == "any_constant":
        require(
            len(witnesses) == 2 and witnesses[0]["result"] != witnesses[1]["result"],
            "nonconstant counterexample",
        )
    else:
        value = witnesses[0]
        require(
            type(value["proposed"]) is int
            and value["proposed"] == value["operands"][query["target"]]
            and value["result"] != value["proposed"],
            "operand counterexample",
        )


def verify_constraint_witness(sample, model, proof):
    primitive, proposed, x_path = constraint_binding(sample, model)
    require(
        proof["status"] == "sat"
        and proof["bits"] == primitive.bits
        and proof["proposed"] == proposed,
        "actual constraint proof contract",
    )
    require(proof["x_path"] == x_path, "actual bound operand path")
    witness = proof["counterexample"]
    values = primitive.values(witness["bytes"])
    require(
        values == witness["operands"]
        and type(witness["result"]) is int
        and primitive.integer(values) == witness["result"],
        "constraint integer replay",
    )
    x = values[x_path]
    target = x - 1 if proposed == "subtract_one" else x if proposed == "identity" else -x
    require(
        type(witness["proposed"]) is int
        and witness["proposed"] == target & mask(primitive.width)
        and witness["proposed"] != witness["result"],
        "actual constraint counterexample",
    )
