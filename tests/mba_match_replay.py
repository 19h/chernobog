"""Independent structural matcher replay and conservative local constant facts.

This does not execute rule-specific candidate/constant predicates or propose a
live rewrite. Byte microregister facts assume normal completion of the captured
consecutive prefix and a pure enclosing expression. Incoming values are unknown.
"""

import copy
import json
import re

from mba_matching_diagnostics import OUTCOMES, parse_match_failure, require, validate_matching

UINT64 = 2**64 - 1
STATUSES = ("complete", "no_ast", "depth_limit", "visit_limit", "byte_limit", "malformed", "cycle")
MOPS = set("z r n S v l d b f a h str c p fn sc".split())
OPS = set(
    "nop mov ldx stx add sub mul and or xor bnot neg low high xdu xds lnot "
    "udiv sdiv umod smod shl shr sar cfadd ofadd sets seto setp setnz setz "
    "setae setb seta setbe setg setge setl setle".split()
)
PURE = set("mov add sub mul and or xor bnot neg low high xdu xds".split())
FLAGS = set(
    "cfadd ofadd sets seto setp setnz setz setae setb seta setbe setg setge setl setle".split()
)


def packed(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True)


def integer(value, low=0, high=UINT64):
    require(type(value) is int and low <= value <= high, "capture integer domain")


class Grammar:
    def __init__(self, model, maximum=512, address_extents_required=False):
        self.tags = {code: name for name, code in model["mops"].items()}
        self.visits = 0
        self.maximum = maximum
        self.address_extents_required = address_extents_required

    def charge(self, depth):
        self.visits += 1
        require(depth <= 64 and self.visits <= self.maximum, "capture traversal budget")

    def operand(self, value, depth):
        self.charge(depth)
        require(type(value) is list and len(value) == 5, "operand shape")
        kind, width, number, props, payload = value
        integer(kind, 0, 255)
        integer(width, -1, 65535)
        integer(number, 0, 2**16 - 1)
        integer(props, 0, 255)
        name = self.tags.get(kind)
        if name in ("z", "f", "c", "p", "fn", "sc") or name is None:
            require(payload == 0, "opaque operand marker")
        elif name == "r":
            integer(payload, -(2**31), 2**31 - 1)
        elif name in ("v", "b"):
            integer(payload, -(2**31) if name == "b" else 0)
        elif name == "n":
            if payload is not None:
                integer(payload)
        elif name in ("S", "l"):
            if payload is not None:
                require(
                    type(payload) is list and len(payload) == (2 if name == "S" else 3),
                    "owner shape",
                )
                integer(payload[0], 0, 512)
                for field in payload[1:]:
                    integer(field, -(2**63), UINT64)
        elif name == "d":
            self.instruction(payload, depth + 1)
        elif name == "a":
            if payload is not None:
                if self.address_extents_required:
                    require(type(payload) is list and len(payload) == 3, "address extent shape")
                    self.operand(payload[0], depth + 1)
                    integer(payload[1], -(2**31), 2**31 - 1)
                    integer(payload[2], -(2**31), 2**31 - 1)
                else:
                    # Historical source-pinned captures predate extent fields.
                    require(type(payload) is list and len(payload) == 5, "legacy address shape")
                    self.operand(payload, depth + 1)
        elif name in ("h", "str") and payload is not None:
            require(
                isinstance(payload, str) and re.fullmatch(r"(?:[0-9a-f]{2}){0,4095}", payload),
                "hex text",
            )
            require(
                "00" not in [payload[i : i + 2] for i in range(0, len(payload), 2)],
                "embedded terminator",
            )

    def instruction(self, value, depth=0):
        if value is None:
            return
        self.charge(depth)
        require(type(value) is list and len(value) == 6, "instruction shape")
        integer(value[0], 0, 255)
        integer(value[1], 0, 2**32 - 1)
        integer(value[2])
        for operand in value[3:]:
            self.operand(operand, depth + 1)

    def candidate(self, value, depth=0):
        if value is None:
            return
        self.charge(depth)
        require(type(value) is list and value[0] in ("n", "v"), "candidate kind")
        require(len(value) == (6 if value[0] == "n" else 3), "candidate shape")
        integer(value[1], -1, 65535)
        self.operand(value[2], depth + 1)
        if value[0] == "n":
            integer(value[3], 0, 255)
            self.candidate(value[4], depth + 1)
            self.candidate(value[5], depth + 1)

    def pattern(self, value, depth=0):
        if value is None:
            return
        self.charge(depth)
        require(type(value) is list and value[0] in ("n", "v", "k"), "pattern kind")
        if value[0] == "n":
            require(len(value) == 4, "pattern node shape")
            integer(value[1], 0, 255)
            self.pattern(value[2], depth + 1)
            self.pattern(value[3], depth + 1)
        else:
            require(len(value) == (3 if value[0] == "k" else 2), "pattern leaf shape")
            if value[0] == "k":
                integer(value[1])
            require(
                isinstance(value[-1], str) and re.fullmatch(r"[A-Za-z0-9_]{0,128}", value[-1]),
                "pattern identifier",
            )


def catalog(value, names=None, disabled=False):
    require(
        set(value) == {"schema", "status", "model", "patterns"} and value["schema"] == 1,
        "catalog schema",
    )
    require(
        value["status"] == ("not_initialized" if disabled else "complete"), "catalog availability"
    )
    require(len(packed(value).encode()) <= 32768, "catalog byte quota")
    model = value["model"]
    require(
        set(model) == {"mops", "ops"} and set(model["mops"]) == MOPS and set(model["ops"]) == OPS,
        "SDK tag population",
    )
    for mapping in model.values():
        require(len(set(mapping.values())) == len(mapping), "duplicate SDK tags")
        for code in mapping.values():
            integer(code, 0, 255)
    patterns = value["patterns"]
    require(type(patterns) is list, "catalog patterns")
    grammar = Grammar(model, 8192)
    observed = []
    for item in patterns:
        require(type(item) is list and len(item) == 2, "catalog entry shape")
        name, pattern = item
        require(
            isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_]{1,128}", name), "rule identifier"
        )
        require(pattern is not None and pattern[0] == "n", "indexed pattern root")
        grammar.pattern(pattern)
        observed.append(name)
    observed_names = set(observed)
    require(len(observed_names) == len(observed), "duplicate certified rule")
    require(not disabled or not patterns, "disabled catalog populated")
    if names is not None:
        require(
            type(names) is list
            and all(isinstance(name, str) for name in names)
            and len(set(names)) == len(names),
            "registered rule population",
        )
        require(observed_names.issubset(names), "unregistered certified rule")
        # Runtime UNKNOWN excludes a rule from the indexed catalog. Replay its
        # actual certified subsequence in registration order, including empty.
        require(
            observed == [name for name in names if name in observed_names],
            "certified rule order",
        )
    return model, patterns


def capture(value, model):
    fields = {"root", "enclosing", "anchor", "prefix_status", "prefix"}
    require(
        set(value) in (fields, fields | {"root_iprops"}, fields | {"root_iprops", "schema"}),
        "input schema",
    )
    require("schema" not in value or value["schema"] == 2, "input schema version")
    if value.get("root_iprops") is not None:
        integer(value["root_iprops"], 0, 2**32 - 1)
    require(len(packed(value).encode()) <= 8192, "input byte quota")
    integer(value["anchor"])
    require(
        value["prefix_status"]
        in {"missing_anchor", "block_entry", "head_limit", "link_error", *STATUSES[2:]},
        "prefix frontier",
    )
    require(type(value["prefix"]) is list and len(value["prefix"]) <= 64, "prefix head quota")
    require(
        value["prefix_status"] not in ("missing_anchor", "link_error") or not value["prefix"],
        "untrusted prefix",
    )
    require(value["prefix_status"] != "head_limit" or len(value["prefix"]) == 64, "head frontier")
    grammar = Grammar(model, address_extents_required=value.get("schema") == 2)
    require(value["root"] is not None and value["root"][0] == "n", "matcher root node")
    grammar.candidate(value["root"])
    grammar.instruction(value["enclosing"])
    if value["enclosing"] is not None:
        require(value["enclosing"][2] == value["anchor"], "enclosing anchor")
    for instruction in value["prefix"]:
        require(instruction is not None, "null predecessor")
        grammar.instruction(instruction)
    return value


def mask(width):
    return (1 << (width * 8)) - 1 if 1 <= width < 8 else UINT64


def operand_difference(left, right, model):
    """Return the first strict difference; nested order is destination, left, right."""
    tags, ops = model["mops"], model["ops"]
    visits = 0

    def diff(a, b, depth):
        nonlocal visits
        visits += 1
        if depth > 64 or visits > 512:
            return ("comparison_budget",)
        for i, name in enumerate(
            ("operand_kind", "operand_width", "value_number", "operand_properties")
        ):
            if a[i] != b[i]:
                return name, a[i] & UINT64, b[i] & UINT64
        kind, x, y = a[0], a[4], b[4]
        if kind == tags["z"]:
            return None
        scalars = {
            tags[k]: v
            for k, v in (
                ("r", "register_identity"),
                ("n", "number_value"),
                ("v", "global_address"),
                ("b", "block_identity"),
            )
        }
        if kind in scalars:
            if kind == tags["n"] and (x is None or y is None):
                return None if x is y else ("null_payload",)
            return None if x == y else (scalars[kind], x & UINT64, y & UINT64)
        if kind in {tags[k] for k in ("S", "l", "d", "a", "h", "str")}:
            if x is None or y is None:
                return None if x is y else ("null_payload",)
            if kind in (tags["S"], tags["l"]):
                if x[0] != y[0]:
                    return ("frame_owner",)
                fields = ("stack_offset",) if kind == tags["S"] else ("local_index", "local_offset")
                for i, name in enumerate(fields, 1):
                    if x[i] != y[i]:
                        return name, x[i] & UINT64, y[i] & UINT64
                return None
            if kind == tags["d"]:
                for i, name in ((0, "nested_opcode"), (1, "instruction_props")):
                    if x[i] != y[i]:
                        return name, x[i], y[i]
                if x[0] == ops["ldx"] and x[2] != y[2]:
                    return "load_source", x[2], y[2]
                for i in (5, 3, 4):
                    result = diff(x[i], y[i], depth + 1)
                    if result:
                        return result
                return None
            if kind == tags["a"]:
                if len(x) == len(y) == 3:
                    for i, name in ((1, "address_input_size"), (2, "address_output_size")):
                        if x[i] != y[i]:
                            return name, x[i] & UINT64, y[i] & UINT64
                    return diff(x[0], y[0], depth + 1)
                require(len(x) == len(y) == 5, "mixed address capture formats")
                return diff(x, y, depth + 1)
            return None if x == y else ("text_value",)
        return ("unsupported_mop",)

    return diff(left, right, 0)


def match(pattern, candidate, model):
    """Replay matching without C++/SDK calls; preserve rollback and first ties."""
    bindings = {}
    count, failure = 0, None
    commutative = {model["ops"][k] for k in ("add", "mul", "and", "or", "xor")}

    def reject(kind, p, c, *values):
        nonlocal failure
        if failure is None or count > failure["matched_nodes"]:
            failure = {
                "kind": kind,
                "pattern_path": p[:64],
                "candidate_path": c[:64],
                "matched_nodes": count,
                "path_truncated": len(p) > 64 or len(c) > 64,
            }
            if values:
                failure.update(expected=values[0], actual=values[1])
        return False

    def walk(pat, val, p="", c=""):
        nonlocal count
        if pat is None or val is None:
            if pat is val:
                count += 1
                return True
            return reject("null_tree", p, c)
        if pat[0] in ("v", "k"):
            name = pat[-1]
            if pat[0] == "k":
                if val[2][0] != model["mops"]["n"]:
                    return reject("numeric_required", p, c, model["mops"]["n"], val[2][0])
                if val[2][4] is None:
                    return reject("null_payload", p, c)
                if not name:
                    wanted, actual = pat[1] & mask(val[2][1]), val[2][4] & mask(val[2][1])
                    if wanted != actual:
                        return reject("constant_value", p, c, wanted, actual)
                    count += 1
                    return True
            if name in bindings:
                difference = operand_difference(bindings[name], val[2], model)
                if difference:
                    return reject(difference[0], p, c, *difference[1:])
            elif len(bindings) == 8:
                return reject("binding_capacity", p, c)
            else:
                bindings[name] = val[2]
            count += 1
            return True
        if val[0] != "n":
            return reject("node_required", p, c)
        if pat[1] != val[3]:
            return reject("opcode", p, c, pat[1], val[3])
        arity = lambda a, b: int(a is not None) | (int(b is not None) << 1)
        pa, ca = arity(pat[2], pat[3]), arity(val[4], val[5])
        if pa != ca:
            return reject("arity", p, c, pa, ca)
        count += 1
        saved, saved_count = dict(bindings), count
        for swapped in (False, True) if pat[3] is not None and pat[1] in commutative else (False,):
            bindings.clear()
            bindings.update(saved)
            count = saved_count
            left, right = (val[5], val[4]) if swapped else (val[4], val[5])
            if pat[2] is not None and not walk(
                pat[2], left, p + "L", c + ("R" if swapped else "L")
            ):
                continue
            if pat[3] is not None and not walk(
                pat[3], right, p + "R", c + ("L" if swapped else "R")
            ):
                continue
            return True
        bindings.clear()
        bindings.update(saved)
        count = saved_count
        return False

    matched = walk(pattern, candidate)
    return matched, None if matched else failure


def replay(sample, patterns, model):
    root = sample["input"]["root"]
    require(root[3] == sample["opcode"] and root[1] == sample["width_bytes"], "actual root site")
    bucket = [(name, pattern) for name, pattern in patterns if pattern[1] == root[3]]
    require(len(bucket) == sample["indexed_patterns"], "actual root index")
    matched, best, best_rule = [], None, ""
    terminal = sample["outcome"] not in OUTCOMES[:5]
    for name, pattern in bucket:
        hit, failure = match(pattern, root, model)
        if hit:
            matched.append(name)
            if terminal and name == sample["rule"]:
                break
        elif best is None or failure["matched_nodes"] > best["matched_nodes"]:
            best, best_rule = failure, name
    require(len(matched) == sample["structural_matches"], "actual structural count")
    if sample["outcome"] == "structural_mismatch":
        require(
            not matched
            and sample["rule"] == best_rule
            and parse_match_failure(sample["reason"]) == best,
            "actual longest-prefix witness",
        )
    elif sample["outcome"] == "no_indexed_pattern":
        require(
            not bucket and sample["reason"] == "root_opcode_unindexed;opcode=" + str(root[3]),
            "actual missing index",
        )
    else:
        require(sample["rule"] in matched, "actual accepted/rejected structural rule")
    return matched


def local_constants(value, model):
    """Read-only normal-completion facts; exact overlapping byte writes."""
    tags, operations = model["mops"], {code: name for name, code in model["ops"].items()}
    state = {}

    def scalar(mop):
        return 1 <= mop[1] <= 8 and mop[3] == 0

    def pure_operand(mop):
        if mop[0] in (tags["z"], tags["r"], tags["n"]):
            return mop[3] == 0
        return (
            mop[0] == tags["d"]
            and mop[4] is not None
            and mop[4][5][0] == tags["z"]
            and pure_instruction(mop[4])
        )

    def pure_instruction(ins):
        return (
            ins[1] == 0
            and operations.get(ins[0]) in PURE | FLAGS
            and all(pure_operand(m) for m in ins[3:5])
        )

    def read(mop):
        if not scalar(mop):
            return None
        if mop[0] == tags["n"]:
            return None if mop[4] is None else mop[4] & mask(mop[1])
        if mop[0] == tags["r"] and mop[4] >= 0:
            cells = [state.get(mop[4] + i) for i in range(mop[1])]
            if all(cell is not None and cell[1] == mop[2] for cell in cells):
                return sum(cell[0] << (8 * i) for i, cell in enumerate(cells))
        if mop[0] == tags["d"] and mop[4] is not None:
            return evaluate(mop[4]) if mop[1] == mop[4][5][1] else None
        return None

    def evaluate(ins):
        if not pure_instruction(ins) or not scalar(ins[5]):
            return None
        op, a, b, dest = operations.get(ins[0]), ins[3], ins[4], ins[5]
        x, y, width = read(a), read(b), dest[1]
        if x is None:
            return None
        if op in ("mov", "bnot", "neg") and a[1] == width and b[0] == tags["z"]:
            return {"mov": x, "bnot": ~x, "neg": -x}[op] & mask(width)
        if (
            op in ("add", "sub", "mul", "and", "or", "xor")
            and y is not None
            and a[1] == b[1] == width
        ):
            return {
                "add": x + y,
                "sub": x - y,
                "mul": x * y,
                "and": x & y,
                "or": x | y,
                "xor": x ^ y,
            }[op] & mask(width)
        if b[0] != tags["z"]:
            return None
        if op in ("xdu", "xds") and a[1] <= width:
            if op == "xds" and x & (1 << (8 * a[1] - 1)):
                x -= 1 << (8 * a[1])
            return x & mask(width)
        if op in ("low", "high") and a[1] >= width:
            return (x >> (8 * (a[1] - width) if op == "high" else 0)) & mask(width)
        return None

    for ins in value["prefix"]:
        if ins[1] == 0 and operations.get(ins[0]) == "nop":
            continue
        dest = ins[5]
        if not pure_instruction(ins) or dest[0] != tags["r"] or not scalar(dest) or dest[4] < 0:
            state.clear()
            continue
        computed = evaluate(ins)
        for i in range(dest[1]):
            state.pop(dest[4] + i, None)
            if computed is not None:
                state[dest[4] + i] = ((computed >> (8 * i)) & 255, dest[2])
    transformed = copy.deepcopy(value["root"])
    resolved = []
    if value["enclosing"] is None or not pure_instruction(value["enclosing"]):
        return transformed, resolved

    def substitute(node, path=""):
        if node is None:
            return
        if node[0] == "n":
            substitute(node[4], path + "L")
            substitute(node[5], path + "R")
            if node[2][0] == tags["d"] and node[2][4] is not None:
                for child, index in ((node[4], 3), (node[5], 4)):
                    if child is not None:
                        node[2][4][index] = copy.deepcopy(child[2])
        elif node[2][0] == tags["r"]:
            number = read(node[2])
            if number is not None and node[1] == node[2][1]:
                resolved.append(
                    {"path": path, "register": node[2][4], "width_bytes": node[1], "value": number}
                )
                node[2] = [tags["n"], node[1], 0, 0, number]

    substitute(transformed)
    return transformed, resolved


def validate_inputs(value, statistics, entry, maturity, disabled, model, patterns):
    schema = value.get("schema")
    require(
        (schema == 1 and set(value) == {"schema", "events", "unrecorded", "counts", "samples"})
        or (
            schema == 2
            and set(value)
            == {"schema", "sample_limit", "events", "unrecorded", "counts", "samples"}
            and type(value["sample_limit"]) is int
            and value["sample_limit"] in (64, 1024)
        ),
        "input inventory schema",
    )
    limit = value.get("sample_limit", 64)
    require(set(value["counts"]) == set(STATUSES), "capture status population")
    for count in (*value["counts"].values(), value["events"], value["unrecorded"]):
        integer(count)
    require(
        sum(value["counts"].values()) == value["events"] == statistics["total_matches"],
        "input event accounting",
    )
    samples = value["samples"]
    require(type(samples) is list and len(samples) <= limit, "input key quota")
    require(len(samples) == limit or value["unrecorded"] == 0, "premature input omission")
    require(
        sum(s["count"] for s in samples) + value["unrecorded"] == value["events"],
        "input retained accounting",
    )
    keys, outcomes, statuses, seen = (
        set(),
        dict.fromkeys(OUTCOMES, 0),
        dict.fromkeys(STATUSES, 0),
        [],
    )
    for sample in samples:
        status = sample["capture_status"]
        require(
            status in STATUSES and (status == "complete") == (sample["input"] is not None),
            "capture status/payload",
        )
        key = packed({k: v for k, v in sample.items() if k != "count"})
        require(key not in keys, "duplicate input key")
        keys.add(key)
        statuses[status] += sample["count"]
        event = {k: v for k, v in sample.items() if k not in ("capture_status", "input")}
        # Aggregate duplicate old event keys: the new inventory distinguishes
        # payloads while the historical inventory deliberately does not.
        old_key = packed({k: v for k, v in event.items() if k != "count"})
        previous = next(
            (s for s in seen if packed({k: v for k, v in s.items() if k != "count"}) == old_key),
            None,
        )
        if previous is None:
            seen.append(event)
        else:
            previous["count"] += event["count"]
        outcomes[event["outcome"]] += event["count"]
        if status == "complete":
            require(event["outcome"] != "no_ast", "no-AST complete capture")
            capture(sample["input"], model)
            replay(sample, patterns, model)
        elif event["outcome"] == "no_ast":
            require(status == "no_ast", "no-AST status")
    require(all(statuses[s] <= value["counts"][s] for s in STATUSES), "per-status accounting")
    old_counts = statistics["matching"]["counts"]
    require(all(outcomes[s] <= old_counts[s] for s in OUTCOMES), "per-outcome input accounting")
    # Fill the omitted event counts from the independent full outcome totals.
    synthetic = {
        "schema": 1,
        "events": value["events"],
        "unrecorded": value["unrecorded"],
        "counts": old_counts,
        "samples": seen,
    }
    if value["unrecorded"]:
        # Old keys may aggregate to fewer than 64; validate their fields with
        # a zero-omission self-contained sample inventory instead.
        synthetic.update(events=sum(outcomes.values()), unrecorded=0, counts=outcomes)
        adjusted = dict(
            statistics,
            total_matches=synthetic["events"],
            successful_matches=sum(outcomes[s] for s in OUTCOMES[5:]),
        )
    else:
        adjusted = statistics
    validate_matching(synthetic, adjusted, entry, maturity, disabled, sample_limit=limit)
    return samples
