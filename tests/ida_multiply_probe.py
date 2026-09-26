"""Inspect full/truncated multiplication, undefined flags, encodings and freshness."""

import json
import os
from pathlib import Path
import sys
import traceback

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_ida
import ida_idaapi
import ida_name
import ida_pro
import ida_ua
import idautils

sys.dont_write_bytecode = True
report = {"checks": [], "errors": [], "owned": {}, "ownerless": {}}
baseline = os.environ.get("CHERNOBOG_MULTIPLY_BASELINE") == "1"


def check(name, condition):
    report["checks"].append({"case": name, "passed": bool(condition)})
    if not condition:
        report["errors"].append(name)


def symbol(name):
    for candidate in (name, "_" + name):
        address = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
        if address != ida_idaapi.BADADDR:
            return address
    raise AssertionError("missing fixture symbol " + name)


def api(name, root):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, f"{name}({root})")
    return json.loads(value.c_str())


def current_values(view):
    return [
        row for row in view["records"] if row["kind"] == "setcc-value" and row["fresh"] == "true"
    ]


def inventory(sites):
    return [
        {
            "site": hex(site),
            "flags": int(ida_bytes.get_full_flags(site)),
            "bytes": (ida_bytes.get_bytes(site, ida_bytes.get_item_size(site)) or b"").hex(),
            "owner": (
                hex(owner.start_ea) if (owner := ida_funcs.get_func(site)) is not None else None
            ),
            "comment": ida_bytes.get_cmt(site, True),
            "refs": sorted(
                (ref.to, int(ref.type), bool(ref.user)) for ref in idautils.XrefsFrom(site)
            ),
        }
        for site in sites
    ]


def main():
    try:
        ida_auto.auto_wait()
        names = {
            "mp_mul_byte_value": 1,
            "mp_stack_source": 1,
            "mp_mul_byte_cf": 1,
            "mp_imul_byte_value": 1,
            "mp_imul_byte_of": 1,
            "mp_mul_word_high": 1,
            "mp_word_slices": 1,
            "mp_word_low_slice": 1,
            "mp_imul_word_two": 1,
            "mp_imul_word_imm8": 1,
            "mp_imul_word_imm16": 1,
            "mp_imul_word_high": 1,
            "mp_mul_dword_high": 1,
            "mp_imul_dword_high": 1,
            "mp_imul_fits": 1,
            "mp_imul_two": 1,
            "mp_imul_imm8": 1,
            "mp_imul_imm32": 1,
            "mp_unknown_zero": 1,
            "mp_unknown_one_cf": 1,
            "mp_unknown_one_high": 1,
            "mp_signed_unknown_one": 1,
            "mp_high_source": 1,
            "mp_accumulator_source": 1,
            "mp_high_byte_source": 1,
            "mp_imul_aliased_immediate": 1,
            "mp_memory": 1,
            "mp_memory_signed": 1,
            "mp_memory_two": 1,
            "mp_memory_three": 1,
            "mp_memory_retained": 1,
        }
        if ida_ida.inf_is_64bit():
            names.update(
                {
                    "mp_mul_quad_high": 1,
                    "mp_imul_quad_high": 1,
                    "mp_quad_imm32": 1,
                    "mp_zero_upper_low": 1,
                    "mp_zero_upper_high": 1,
                    "mp_quad_two": 1,
                    "mp_quad_imm8": 1,
                    "mp_quad_full_extended": 1,
                    "mp_extended": 1,
                }
            )
        controls = list(names) + [
            "mp_undefined_zf",
            "mp_undefined_sf",
            "mp_undefined_pf",
            "mp_unknown_multiply",
            "mp_memory_initial",
            "mp_locked",
            "mp_address_prefix",
            "mp_segment_prefix",
            "mp_target",
        ]
        guarded = {"mp_locked", "mp_address_prefix", "mp_segment_prefix"}
        sites = {}
        for name in controls:
            root = symbol(name)
            assert ida_funcs.get_func(root) or ida_funcs.add_func(root)
            function = ida_funcs.get_func(root)
            ida_auto.plan_and_wait(function.start_ea, function.end_ea)
            ida_auto.auto_wait()
            sites[name] = list(idautils.FuncItems(root))
            report.setdefault("decode", {})[name] = []
            for site in sites[name]:
                decoded = ida_ua.insn_t()
                if ida_ua.decode_insn(decoded, site) > 0 and ida_ua.print_insn_mnem(site) in {
                    "mul",
                    "imul",
                }:
                    report["decode"][name].append(
                        {
                            "site": hex(site),
                            "size": decoded.size,
                            "bytes": ida_bytes.get_bytes(site, decoded.size).hex(),
                            "mnemonic": ida_ua.print_insn_mnem(site),
                            "operands": [
                                {
                                    "type": operand.type,
                                    "bits": ida_ua.get_dtype_size(operand.dtype) * 8,
                                    "reg": operand.reg,
                                    "value": hex(operand.value),
                                }
                                for operand in (decoded.Op1, decoded.Op2, decoded.Op3)
                            ],
                        }
                    )
            view = api("chernobog_native_evidence", root)
            report["owned"][name] = view
            if name == "mp_target":
                rows = [
                    row
                    for row in view["records"]
                    if row["kind"] == "stack-transfer"
                    and row["fresh"] == "true"
                    and row["truth"] == "native-proof"
                ]
                check(name + " owned stack target", bool(rows) == (not baseline))
                if rows:
                    check(
                        name + " owned exact effects",
                        len(rows) == 1
                        and rows[0]["target"] == hex(symbol("mp_destination"))
                        and rows[0]["stack_delta_bytes"] == "0",
                    )
            else:
                rows = current_values(view)
                expected = not baseline and name in names
                check(name + " owned admission", bool(rows) == expected)
                if expected:
                    check(
                        name + " owned exact value",
                        len(rows) == 1 and rows[0]["value"] == hex(names[name]),
                    )
        if not baseline:
            root = symbol("mp_mul_byte_cf")
            opcode = next(
                site
                for site in sites["mp_mul_byte_cf"]
                if ida_bytes.get_bytes(site, 2) == b"\xf6\xe1"
            )
            old_rows = current_values(report["owned"]["mp_mul_byte_cf"])
            ida_bytes.patch_byte(opcode + 1, 0xE9)
            changed = api("chernobog_native_evidence", root)
            report["mutated_immediate"] = changed
            check(
                "opcode patch revokes old value publication immediately",
                not any(
                    row["publication"] == old_rows[0]["publication"] and row["fresh"] == "true"
                    for row in changed["records"]
                ),
            )
            function = ida_funcs.get_func(root)
            ida_auto.plan_and_wait(root, function.end_ea)
            ida_auto.auto_wait()
            changed = api("chernobog_native_evidence", root)
            report["mutated_reanalyzed"] = changed
            rows = current_values(changed)
            check(
                "signed replacement proves different overflow",
                len(rows) == 1 and rows[0]["value"] == "0x0",
            )
            ida_bytes.patch_byte(opcode + 1, 0xE1)
            ida_auto.plan_and_wait(root, function.end_ea)
            ida_auto.auto_wait()
            restored = api("chernobog_native_evidence", root)
            report["restored"] = restored
            rows = current_values(restored)
            check("restored MUL recomputes value", len(rows) == 1 and rows[0]["value"] == "0x1")
        # Remove owners in this disposable IDB, then query the same instruction
        # bytes through the separate read-only native-region API.
        owners = {
            owner.start_ea
            for spans in sites.values()
            for site in spans
            if (owner := ida_funcs.get_func(site)) is not None
        }
        for owner in sorted(owners):
            assert ida_funcs.del_func(owner)
        ida_auto.auto_wait()
        for name in controls:
            root = symbol(name)
            before = inventory(sites[name])
            view = api("chernobog_native_region_facts", root)
            report["ownerless"][name] = view
            check(name + " ownerless read-only inventory", before == inventory(sites[name]))
            if name in guarded:
                check(
                    name + " no exact value across unsupported encoding",
                    not any(row.get("status") == "proved" for row in view["records"]),
                )
                if not baseline:
                    check(
                        name + " unsupported encoding frontier",
                        (
                            view["converged"]
                            and any(
                                row["kind"] == "frontier"
                                and row["reason"] == "unsupported_multiply_encoding"
                                for row in view["edges"]
                            )
                        )
                        or (not view["converged"] and view["reason"] == "invalid_instruction_span"),
                    )
                continue
            check(
                name + " ownerless bounded convergence",
                view["available"]
                and view["converged"]
                and not view["truncated"]
                and not view["published"],
            )
            if name == "mp_target":
                rows = [row for row in view["records"] if row["kind"] == "push-return"]
                check(
                    name + " ownerless stack target",
                    len(rows) == 1
                    and rows[0]["status"] == ("unresolved" if baseline else "proved")
                    and rows[0]["target"]
                    == ("unknown" if baseline else hex(symbol("mp_destination"))),
                )
            else:
                rows = [row for row in view["records"] if row["kind"] == "setcc-value"]
                expected = not baseline and name in names
                check(
                    name + " ownerless exact or unknown value",
                    len(rows) == 1
                    and rows[0]["status"] == ("proved" if expected else "unresolved")
                    and rows[0]["value"] == (hex(names[name]) if expected else "unknown"),
                )
        report["baseline"] = baseline
    except BaseException as error:
        report["errors"].append(type(error).__name__)
        report["exception"] = [
            {"function": frame.name, "line": frame.lineno}
            for frame in traceback.extract_tb(error.__traceback__)
        ]
    (Path(os.environ["IDAUSR"]).parent / "multiply.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    print("[chernobog][multiply] " + ("FAIL" if report["errors"] else "PASS"), flush=True)
    return 2 if report["errors"] else 0


if __name__ == "__main__":
    ida_pro.qexit(main())
