"""Compare complete protected captures and audit changed load/store expressions."""

import argparse
import copy
import hashlib
import itertools
import json
from pathlib import Path
import random

ROOT = Path(__file__).resolve().parent.parent
BINARY = {"m_add", "m_sub", "m_mul", "m_and", "m_or", "m_xor"}
UNARY = {"m_mov", "m_bnot", "m_neg", "m_xdu", "m_xds", "m_low", "m_high"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalized(value):
    if isinstance(value, dict):
        return {
            key: normalized(item)
            for key, item in value.items()
            if key not in ("text", "text_truncated")
        }
    if isinstance(value, list):
        return [normalized(item) for item in value]
    return value


def reports(path):
    report = json.loads(path.read_text())
    require(report["passed"] and not report["native_analysis_disabled"], "native profile")
    require(len(report["runs"]) == 40, "full capture population")
    for name, sha in report["artifact_sha256"].items():
        item = (ROOT / name).resolve()
        require(item.is_relative_to(ROOT), "capture path outside repository")
        if name in report["source_sha256"]:
            require(report["source_sha256"][name] == sha, "inconsistent source pin")
        else:
            require(digest(item) == sha, "capture artifact changed")
    captures = {}
    for row in report["runs"]:
        name = next(p for p in row["artifact_sha256"] if p.endswith("/protected_mba.json"))
        captured = json.loads((ROOT / name).read_text())
        require(captured["passed"] and not captured["errors"], "capture errors")
        for entry in captured["entries"]:
            for kind, value in (("entry", entry), ("body", entry["body"])):
                if value is not None:
                    key = row["architecture"], row["label"], row["disabled"], entry["name"], kind
                    require(key not in captures, "duplicate capture")
                    captures[key] = value
    return report, captures


def registers(value):
    result = set()
    if isinstance(value, dict):
        if value.get("kind_name") == "mop_r":
            result.add((value["register"], value["bytes"], value.get("value_number", 0)))
        for child in value.values():
            result.update(registers(child))
    elif isinstance(value, list):
        for child in value:
            result.update(registers(child))
    return result


class Fault(Exception):
    pass


def loads(value, branch=""):
    if value["opcode"] == "m_ldx":
        return [
            (
                branch,
                value["ea"],
                value["destination"]["bytes"],
                normalized(value["left"]),
                normalized(value["right"]),
            )
        ]
    result = []
    for name, suffix in (("left", "L"), ("right", "R")):
        operand = value[name]
        if operand["kind_name"] == "mop_d":
            result.extend(
                loads(
                    operand["instruction"], branch + suffix if value["opcode"] in BINARY else branch
                )
            )
    return result


class Evaluation:
    """Independent finite-width value and ordered read/write effect interpreter."""

    def __init__(self, inputs, samples, order, fault_read=None, fault_write=False):
        self.inputs = inputs
        self.samples = samples
        self.order = order
        self.fault_read = fault_read
        self.fault_write = fault_write
        self.events = []
        self.reads = 0

    def operand(self, operand, branch="", address=False):
        require(operand["properties"] == 0, "operand effects")
        size = operand["bytes"]
        require(size in (1, 2, 4, 8), "operand width")
        kind = operand["kind_name"]
        if kind == "mop_r":
            value = self.inputs[operand["register"], size, operand.get("value_number", 0)]
        elif kind == "mop_n":
            value = operand["value"]
        else:
            require(kind == "mop_d", "unsupported memory or value operand")
            require(operand["instruction"]["destination"]["bytes"] == size, "nested width")
            value = self.instruction(operand["instruction"], branch, address)
        return value & ((1 << (8 * size)) - 1)

    def instruction(self, ins, branch="", address=False):
        require(ins["properties"] == 0, "instruction effects")
        require(
            ins["destination"]["kind_name"] == "mop_z" and ins["destination"]["properties"] == 0,
            "nested destination effects",
        )
        width = ins["destination"]["bytes"]
        require(width in (1, 2, 4, 8), "instruction width")
        bits, mask = 8 * width, (1 << (8 * width)) - 1
        opcode = ins["opcode"]
        if opcode == "m_ldx":
            require(not address, "memory-dependent address")
            require(ins["left"]["bytes"] == 2 and ins["right"]["bytes"] in (4, 8), "load widths")
            selector = self.operand(ins["left"], address=True)
            offset = self.operand(ins["right"], address=True)
            index = self.reads
            self.reads += 1
            event = ("read", branch, ins["ea"], width, selector, offset)
            self.events.append(event)
            if index == self.fault_read:
                raise Fault(event)
            require(index < len(self.samples), "additional memory read")
            return self.samples[index] & mask
        require(opcode in BINARY | UNARY, "unsupported value opcode")
        if opcode in BINARY:
            operands = [("left", branch + "L"), ("right", branch + "R")]
            if self.order == "rl":
                operands.reverse()
            values = {name: self.operand(ins[name], path, address) for name, path in operands}
            left, right = values["left"], values["right"]
            require(ins["left"]["bytes"] == ins["right"]["bytes"] == width, "binary width")
            value = {
                "m_add": lambda: left + right,
                "m_sub": lambda: left - right,
                "m_mul": lambda: left * right,
                "m_and": lambda: left & right,
                "m_or": lambda: left | right,
                "m_xor": lambda: left ^ right,
            }[opcode]()
        else:
            require(ins["right"]["kind_name"] == "mop_z", "unary arity")
            left = self.operand(ins["left"], branch, address)
            input_bits = 8 * ins["left"]["bytes"]
            if opcode in ("m_mov", "m_bnot", "m_neg"):
                require(input_bits == bits, "unary width")
                value = {"m_mov": lambda: left, "m_bnot": lambda: ~left, "m_neg": lambda: -left}[
                    opcode
                ]()
            elif opcode in ("m_xdu", "m_xds"):
                require(input_bits <= bits, "extension width")
                value = (
                    left - (1 << input_bits)
                    if opcode == "m_xds" and left >> (input_bits - 1)
                    else left
                )
            else:
                require(input_bits >= bits, "extraction width")
                value = left if opcode == "m_low" else left >> (input_bits - bits)
        return value & mask

    def store(self, ins):
        require(ins["opcode"] == "m_stx" and ins["properties"] == 0, "store instruction")
        require(
            ins["right"]["bytes"] == 2 and ins["destination"]["bytes"] in (4, 8),
            "store address widths",
        )
        value = self.operand(ins["left"])
        selector = self.operand(ins["right"], address=True)
        offset = self.operand(ins["destination"], address=True)
        event = ("write", ins["ea"], ins["left"]["bytes"], selector, offset, value)
        self.events.append(event)
        if self.fault_write:
            raise Fault(event)
        return value


def evaluate(ins, inputs, samples, order, fault_read=None, fault_write=False):
    machine = Evaluation(inputs, samples, order, fault_read, fault_write)
    try:
        result, fault = machine.store(ins), None
    except Fault as error:
        result, fault = None, error.args[0]
    return result, machine.events, fault


def audit_store(before, after):
    require(before["opcode"] == after["opcode"] == "m_stx", "changed statement is not a store")
    require(
        normalized({k: v for k, v in before.items() if k != "left"})
        == normalized({k: v for k, v in after.items() if k != "left"}),
        "surrounding store changed",
    )
    before_loads = loads(before["left"]["instruction"])
    require(
        len(before_loads) == 2 and before_loads == loads(after["left"]["instruction"]),
        "explicit load contract changed",
    )
    inputs = {key: 0x23 if key[1] == 2 else 0x1000 for key in registers([before, after])}
    checks = faults = 0
    random_values = random.Random(0xC0FFEE)
    corners = [0, 1, 2, 7, 127, 128, 255, 256, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF]
    samples = itertools.chain(
        itertools.product(range(256), repeat=2),
        itertools.product(corners, repeat=2),
        ((random_values.getrandbits(32), random_values.getrandbits(32)) for _ in range(4096)),
    )
    for pair in samples:
        for order in ("lr", "rl"):
            left = evaluate(before, inputs, pair, order)
            right = evaluate(after, inputs, pair, order)
            require(
                left == right and left[2] is None and len(left[1]) == 3, "value/read/store mismatch"
            )
            checks += 1
    for order, fault in itertools.product(("lr", "rl"), (0, 1, "write")):
        arguments = (None, True) if fault == "write" else (fault, False)
        left = evaluate(before, inputs, (0x12345678, 0x89ABCDEF), order, *arguments)
        right = evaluate(after, inputs, (0x12345678, 0x89ABCDEF), order, *arguments)
        require(left == right and left[0] is None and left[2] is not None, "fault prefix mismatch")
        faults += 1
    return {"normal_effect_comparisons": checks, "fault_prefix_comparisons": faults}


def corruption_controls(before, after):
    controls = []

    def trial(name, edit):
        wrong = copy.deepcopy(after)
        edit(wrong)
        try:
            audit_store(before, wrong)
        except (ValueError, KeyError):
            controls.append(name)
            return
        raise ValueError("corrupted proposal accepted: " + name)

    expression = lambda tree: tree["left"]["instruction"]
    either = lambda tree: expression(tree)["left"]["instruction"]
    trial("wrong NOT", lambda tree: expression(tree).update(opcode="m_neg"))
    trial(
        "changed load address",
        lambda tree: either(tree)["left"]["instruction"]["right"].update(
            kind_name="mop_n", value=0x1008
        ),
    )
    trial(
        "dropped load",
        lambda tree: either(tree).update(
            right={"kind_name": "mop_n", "bytes": 4, "properties": 0, "value": 0}
        ),
    )
    trial(
        "swapped load occurrences",
        lambda tree: either(tree).update(
            left=copy.deepcopy(either(tree)["right"]), right=copy.deepcopy(either(tree)["left"])
        ),
    )
    trial(
        "changed load width",
        lambda tree: either(tree)["left"]["instruction"]["destination"].update(bytes=1),
    )
    trial("changed load source", lambda tree: either(tree)["left"]["instruction"].update(ea=0))
    trial(
        "additional nested destination write",
        lambda tree: either(tree)["left"]["instruction"]["destination"].update(
            kind_name="mop_v", global_address=0x3000
        ),
    )
    trial(
        "changed address value number",
        lambda tree: either(tree)["right"]["instruction"]["right"].update(value_number=999),
    )
    trial("changed store width", lambda tree: tree["left"].update(bytes=1))
    trial(
        "changed store address",
        lambda tree: tree["destination"].update(kind_name="mop_n", value=0x1000),
    )
    return controls


def compare(prior, current):
    old_report, old = reports(prior)
    new_report, new = reports(current)
    require(
        all(digest(ROOT / name) == sha for name, sha in new_report["source_sha256"].items()),
        "current source changed",
    )
    for name in (
        "tests/run_protected_mba_corpus.py",
        "tests/ida_protected_mba_probe.py",
        "tests/run_ida_smoke.py",
        "tests/run_vmp_corpus.py",
    ):
        require(
            old_report["source_sha256"][name] == new_report["source_sha256"][name],
            "capture harness changed",
        )
    require(
        old_report["ida_sha256"] == new_report["ida_sha256"]
        and old_report["ida_components_sha256"] == new_report["ida_components_sha256"],
        "toolchain changed",
    )
    require(old.keys() == new.keys(), "native population changed")
    changes, stages, captured = [], 0, 0
    for key in old:
        before, after = old[key], new[key]
        require(
            all(
                before.get(k) == after.get(k) for k in ("entry", "owner", "status", "native_chunks")
            ),
            "native owner/bytes changed",
        )
        require(len(before["stages"]) == len(after["stages"]), "stage population changed")
        for left, right in zip(before["stages"], after["stages"]):
            stages += 1
            require(
                all(
                    left.get(k) == right.get(k)
                    for k in ("maturity", "status", "error_code", "error_ea")
                ),
                "SDK outcome changed",
            )
            captured += right["status"] == "captured"
            require(len(left["blocks"]) == len(right["blocks"]), "block population changed")
            for a, b in zip(left["blocks"], right["blocks"]):
                require(
                    a["index"] == b["index"]
                    and a["successors"] == b["successors"]
                    and len(a["instructions"]) == len(b["instructions"]),
                    "CFG changed",
                )
                for old_ins, new_ins in zip(a["instructions"], b["instructions"]):
                    if normalized(old_ins) != normalized(new_ins):
                        require(not key[2], "disabled IR changed")
                        result = audit_store(old_ins, new_ins)
                        changes.append(
                            {
                                "architecture": key[0],
                                "label": key[1],
                                "name": key[3],
                                "kind": key[4],
                                "maturity": right["maturity"],
                                "store_ea": new_ins["ea"],
                                **result,
                                "corruption_controls": corruption_controls(old_ins, new_ins),
                            }
                        )
    require(
        stages == 456 and captured == 454 and len(changes) == 1,
        "observed capture/change population",
    )
    require(
        changes[0]["architecture"] == "i386"
        and changes[0]["label"] == "combined-12648430"
        and changes[0]["kind"] == "body"
        and changes[0]["maturity"] == 5,
        "protected rewrite attribution",
    )
    return {
        "passed": True,
        "prior_report_sha256": digest(prior),
        "current_report_sha256": digest(current),
        "prior_plugin_sha256": old_report["plugin_sha256"],
        "current_plugin_sha256": new_report["plugin_sha256"],
        "native_rows": len(new),
        "stages": stages,
        "captured_stages": captured,
        "changes": changes,
        "scope": "captured value, ordered explicit read and store effects under both operand schedules; modeled load/store faults; no whole-function, flags, hardware exception or logical-VM equivalence claim",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prior", type=Path, required=True)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = {"passed": False}
    try:
        pins = {path: digest(path) for path in (args.prior, args.current, Path(__file__))}
        report = compare(args.prior, args.current)
        require(all(digest(path) == sha for path, sha in pins.items()), "audit input changed")
        for path in (args.prior, args.current):
            reports(path)
    except Exception as error:
        report["failure"] = type(error).__name__ + ": " + str(error)
    report["verifier_sha256"] = digest(Path(__file__))
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
