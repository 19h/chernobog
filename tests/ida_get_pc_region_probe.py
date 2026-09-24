"""Exercise bounded automatic ownership of detached x86 get-PC gadgets."""

import json
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_name
import ida_nalt
import ida_netnode
import ida_pro
import ida_ua
import ida_xref
import idautils
import idc


def address(name):
    for label in ("_" + name, name):
        result = ida_name.get_name_ea(ida_idaapi.BADADDR, label)
        if result != ida_idaapi.BADADDR:
            return result
    raise RuntimeError("missing fixture symbol " + name)


def call_target(root):
    call = ida_ua.insn_t()
    assert ida_ua.decode_insn(call, root) > 0
    return call.Op1.addr


def function_info(ea):
    function = ida_funcs.get_func(ea)
    if function is None:
        return None
    root = function.start_ea
    heads = list(idautils.FuncItems(root))
    return {
        "start": int(root),
        "end": int(function.end_ea),
        "flags": int(function.flags),
        "name": ida_name.get_name(root),
        "user_name": bool(ida_bytes.has_user_name(ida_bytes.get_flags(root))),
        "user_type": bool(ida_nalt.is_userti(root)),
        "chunks": [[int(start), int(end)] for start, end in idautils.Chunks(root)],
        "sp_before": [[int(head), int(idc.get_spd(head))] for head in heads],
    }


def node_value(name, ea):
    node = ida_netnode.netnode(name, 0, False)
    return node.supval(ida_nalt.ea2node(ea))


def receipt(root):
    return node_value("$ chernobog.native_proof_ownership.v1", root)


def rejection(root):
    return node_value("$ chernobog.native_donor_rejections.v1", root)


def refresh_native():
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, "chernobog_native_analysis()")


report = {"roots": {}, "checks": {}, "errors": []}
bits = int(os.environ.get("CHERNOBOG_REGION_BITS", "32"))
assert bits in (32, 64)
backward_name = "gp32_backward" if bits == 32 else "gp_backward"
nonzero_name = "gp32_nonzero" if bits == 32 else "gp_nonzero"
anchor_name = "gp32_backward_anchor" if bits == 32 else "gp_backward_anchor"
word_bytes = bits // 8


def check(name, condition):
    report["checks"][name] = bool(condition)
    if not condition:
        report["errors"].append(name)


def save(name):
    return ida_loader.save_database(str(Path(os.environ["IDAUSR"]).parent / name), 0)


try:
    stage = os.environ.get("CHERNOBOG_REGION_STAGE", "inspect")
    report["stage"] = stage
    ida_auto.auto_wait()
    if stage == "prepare_negative":
        backward = address(backward_name)
        nonzero = address(nonzero_name)
        named_target = call_target(backward)
        alternate_entry = call_target(nonzero) + 3
        check(
            "user name staged",
            ida_name.set_name(named_target, "user_gp32_backward_gadget", ida_name.SN_FORCE),
        )
        check(
            "alternate entry staged",
            ida_xref.add_cref(
                address(anchor_name),
                alternate_entry,
                ida_xref.fl_JN | ida_xref.XREF_USER,
            ),
        )
        check("negative database saved", save("negative.i64"))
    else:
        refresh_native()
        ida_auto.auto_wait()
        refresh_native()
        assert ida_hexrays.init_hexrays_plugin()
        for name in (backward_name, nonzero_name):
            root = address(name)
            target = call_target(root)
            failure = ida_hexrays.hexrays_failure_t()
            cfunc = ida_hexrays.decompile(root, failure, ida_hexrays.DECOMP_NO_CACHE)
            report["roots"][name] = {
                "root": int(root),
                "target": int(target),
                "caller": function_info(root),
                "gadget": function_info(target),
                "target_name": ida_name.get_name(target),
                "target_refs": [int(ea) for ea in idautils.CodeRefsTo(target, True)],
                "receipt_version": (receipt(root) or b"")[:4].hex(),
                "rejection": (rejection(root) or b"").hex(),
                "ctree": str(cfunc) if cfunc is not None else None,
                "decompile_failure": failure.desc(),
            }

        if stage in ("write", "reopen"):
            for name, row in report["roots"].items():
                check(name + " gadget owned", row["gadget"]["start"] == row["root"])
                joined_offsets = [
                    sp
                    for head, sp in row["gadget"]["sp_before"]
                    if head >= row["target"] and (name != backward_name or head < row["root"])
                ]
                expected_offsets = (
                    [-word_bytes, 0, -word_bytes]
                    if name == backward_name
                    else [-word_bytes, -word_bytes, -2 * word_bytes]
                )
                check(name + " joined stack offsets", joined_offsets == expected_offsets)
                check(
                    name + " inferred noreturn cleared",
                    (row["caller"]["flags"] & ida_funcs.FUNC_NORET) == 0,
                )
                check(name + " donor receipt", row["receipt_version"] == "4e505203")
                check(name + " returning pseudocode", "return 7;" in (row["ctree"] or ""))
            if stage == "write":
                check("database saved", save("region.i64"))
            else:
                row = report["roots"][nonzero_name]
                root, target = row["root"], row["target"]
                old = ida_bytes.get_byte(root)
                assert old == 0xE8
                ida_bytes.patch_byte(root, 0xE9)
                donor = function_info(target)
                caller = function_info(root)
                report["after_patch"] = {"donor": donor, "caller": caller}
                check(
                    "patch restores separate donor", donor is not None and donor["start"] == target
                )
                check(
                    "patch restores donor stack",
                    donor is not None
                    and [sp for _, sp in donor["sp_before"]] == [0, 0, -word_bytes],
                )
                check("patch restores caller entry end", caller["end"] == target)
                check("patch removes donor receipt", (receipt(root) or b"")[:4] != b"NPR\x03")
                ida_bytes.patch_byte(root, old)
                ida_auto.plan_and_wait(root, root + 5)
                refresh_native()
                check("restored call rejoins donor", function_info(target)["start"] == root)
                check("restored call owns donor again", (receipt(root) or b"")[:4] == b"NPR\x03")

                row = report["roots"][backward_name]
                root, target = row["root"], row["target"]
                check("tail removal requested", ida_funcs.remove_func_tail_ea(root, target))
                check("tail exclusion persisted", bool(rejection(root)))
                ida_auto.auto_wait()
                refresh_native()
                donor = function_info(target)
                report["after_tail_removal"] = {"donor": donor, "caller": function_info(root)}
                check(
                    "tail removal restores separate donor",
                    donor is not None and donor["start"] == target,
                )
                check(
                    "tail removal restores donor stack",
                    donor is not None
                    and [sp for _, sp in donor["sp_before"]] == [0, word_bytes, 0],
                )
                check(
                    "tail removal revokes donor receipt", (receipt(root) or b"")[:4] != b"NPR\x03"
                )
                check("rejected database saved", save("rejected.i64"))
        elif stage == "rejected_reopen":
            row = report["roots"][backward_name]
            check("rejected donor remains separate", row["gadget"]["start"] == row["target"])
            check("rejection survives reopen", bool(rejection(row["root"])))
            check("rejected proof absent", row["receipt_version"] != "4e505203")
            row = report["roots"][nonzero_name]
            check("unrelated donor rejoins", row["gadget"]["start"] == row["root"])
            root = report["roots"][backward_name]["root"]
            target = report["roots"][backward_name]["target"]
            old = ida_bytes.get_byte(root)
            assert old == 0xE8
            ida_bytes.patch_byte(root, 0xE9)
            check("source patch clears exclusion", not rejection(root))
            ida_bytes.patch_byte(root, old)
            ida_auto.plan_and_wait(root, root + 5)
            refresh_native()
            check("restored source rejoins donor", function_info(target)["start"] == root)
            check("restored source owns donor", (receipt(root) or b"")[:4] == b"NPR\x03")
        elif stage == "rename_owned":
            row = report["roots"][backward_name]
            root, target = row["root"], row["target"]
            check(
                "owned target renamed",
                ida_name.set_name(target, "user_owned_gadget", ida_name.SN_FORCE),
            )
            refresh_native()
            donor = function_info(target)
            report["after_rename"] = {"donor": donor, "caller": function_info(root)}
            check("rename restores separate donor", donor is not None and donor["start"] == target)
            check("rename retains user name", ida_name.get_name(target) == "user_owned_gadget")
            check("rename revokes donor receipt", (receipt(root) or b"")[:4] != b"NPR\x03")
        elif stage == "negative":
            for name, row in report["roots"].items():
                check(
                    name + " donor separate",
                    row["gadget"] is None or row["gadget"]["start"] != row["root"],
                )
                check(name + " donor receipt absent", row["receipt_version"] != "4e505203")
            check(
                "user name retained",
                report["roots"][backward_name]["target_name"] == "user_gp32_backward_gadget",
            )
            nonzero = report["roots"][nonzero_name]
            check(
                "alternate entry retained",
                address(anchor_name)
                in [int(ea) for ea in idautils.CodeRefsTo(nonzero["target"] + 3, True)],
            )
        elif stage != "inspect":
            raise ValueError("unknown stage")
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "get_pc_region.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
line = "[chernobog][get-pc-region] " + (
    "PASS" if not report["errors"] else "FAIL " + "; ".join(report["errors"])
)
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(0 if not report["errors"] else 2)
