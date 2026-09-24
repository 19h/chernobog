"""Check bounded get-PC noreturn repair and owned metadata revocation."""

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
import idc


def address(name):
    for label in ("_" + name, name):
        result = ida_name.get_name_ea(ida_idaapi.BADADDR, label)
        if result != ida_idaapi.BADADDR:
            return result
    raise RuntimeError("missing fixture symbol")


def instruction(ea):
    decoded = ida_ua.insn_t()
    assert ida_ua.decode_insn(decoded, ea) > 0
    return decoded


def receipt(root):
    node = ida_netnode.netnode("$ chernobog.native_proof_ownership.v1", 0, False)
    return node.supval(ida_nalt.ea2node(root))


def refresh_native():
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, "chernobog_native_analysis()")


def admit(root):
    report.setdefault("admission", []).append("start:" + hex(root))
    function = ida_funcs.get_func(root)
    assert function is not None and function.start_ea == root, "function root"
    call = instruction(root)
    target = call.Op1.addr
    owner = ida_funcs.get_func(target)
    if owner is not None and owner.start_ea != root:
        assert owner.start_ea == target and ida_funcs.del_func(target), "delete auto gadget"
    report["admission"].append("owner_removed:" + hex(root))
    end = target
    for _ in range(8):
        report["admission"].append("decode:" + hex(end))
        current = instruction(end)
        report["admission"].append(current.get_canon_mnem())
        end += current.size
        if current.get_canon_mnem() == "retn":
            break
    assert current.get_canon_mnem() == "retn", "gadget return"
    if not ida_funcs.function_contains(root, target):
        assert ida_funcs.append_func_tail(function, target, end), "append gadget tail"
    report["admission"].append("tail_appended:" + hex(root))
    ida_auto.auto_wait()
    assert ida_funcs.function_contains(root, target), "gadget contained"


report = {"schema": 1, "checks": {}, "errors": []}


def check(name, condition):
    report["checks"][name] = bool(condition)
    if not condition:
        report["errors"].append(name)


try:
    stage = os.environ.get("CHERNOBOG_NORET_STAGE", "write")
    report["stage"] = stage
    ida_auto.auto_wait()
    assert ida_hexrays.init_hexrays_plugin()
    roots = [address("gp32_backward"), address("gp32_nonzero")]
    report["roots"] = roots
    if stage == "no_tail":
        check(
            "preexisting inferred flags",
            all(ida_funcs.get_func(root).flags & ida_funcs.FUNC_NORET for root in roots),
        )
        check(
            "no ownership without contained gadget",
            all((receipt(root) or b"")[:4] != b"NPR\x02" for root in roots),
        )
    elif stage == "unbalanced":
        root = roots[1]
        continuation = root + instruction(root).size
        lea = instruction(continuation)
        assert lea.size == 4 and ida_bytes.get_byte(continuation + 3) == 4
        ida_bytes.patch_byte(continuation + 3, 8)
        admit(root)
        check(
            "unbalanced stack keeps noreturn flag",
            bool(ida_funcs.get_func(root).flags & ida_funcs.FUNC_NORET),
        )
        check("unbalanced path has no noreturn receipt", (receipt(root) or b"")[:4] != b"NPR\x02")
    elif stage == "user_type":
        root = roots[1]
        check(
            "user noreturn type applied",
            bool(
                idc.SetType(root, "void __noreturn gp32_nonzero(void);")
                and ida_nalt.is_userti(root)
            ),
        )
        admit(root)
        check(
            "user noreturn contract retained",
            bool(ida_funcs.get_func(root).flags & ida_funcs.FUNC_NORET),
        )
        check("user contract has no owned flag receipt", (receipt(root) or b"")[:4] != b"NPR\x02")
    elif stage in ("write", "reopen"):
        if stage == "write":
            check(
                "inferred flags precede tail admission",
                all(ida_funcs.get_func(root).flags & ida_funcs.FUNC_NORET for root in roots),
            )
            for root in roots:
                admit(root)
            refresh_native()
        else:
            retained = []
            for root in roots:
                call = instruction(root)
                retained.append(ida_funcs.function_contains(root, call.Op1.addr))
            check("reopened tails retained", all(retained))
            refresh_native()
        report["function_flags_before_check"] = [
            int(ida_funcs.get_func(root).flags) for root in roots
        ]
        report["receipt_versions_before_check"] = [
            (receipt(root) or b"")[:4].hex() for root in roots
        ]
        check(
            "current paths clear inferred noreturn",
            all((ida_funcs.get_func(root).flags & ida_funcs.FUNC_NORET) == 0 for root in roots),
        )
        check(
            "no explicit noreturn contract",
            all(not ida_nalt.is_noret(root) and not ida_nalt.is_userti(root) for root in roots),
        )
        check(
            "owned flag receipts are version two",
            all((receipt(root) or b"")[:4] == b"NPR\x02" for root in roots),
        )
        check(
            "returning pseudocode",
            all(
                "return 7;" in str(ida_hexrays.decompile(root, None, ida_hexrays.DECOMP_NO_CACHE))
                for root in roots
            ),
        )
        if stage == "write":
            check(
                "database saved",
                ida_loader.save_database(str(Path(os.environ["IDAUSR"]).parent / "noret.i64"), 0),
            )
        else:
            root = roots[1]
            old = ida_bytes.get_byte(root)
            assert old == 0xE8
            ida_bytes.patch_byte(root, 0xE9)
            check(
                "patch restores prior noreturn flag",
                bool(ida_funcs.get_func(root).flags & ida_funcs.FUNC_NORET),
            )
            check("patch removes owned flag receipt", (receipt(root) or b"")[:4] != b"NPR\x02")
            ida_bytes.patch_byte(root, old)
            ida_auto.plan_and_wait(root, root + instruction(root).size)
            refresh_native()
            check(
                "restored proof clears noreturn",
                (ida_funcs.get_func(root).flags & ida_funcs.FUNC_NORET) == 0,
            )
            check("restored proof owns flag again", (receipt(root) or b"")[:4] == b"NPR\x02")
            continuation = root + instruction(root).size
            lea = instruction(continuation)
            assert lea.get_canon_mnem() == "lea"
            following = continuation + lea.size
            mov = instruction(following)
            assert mov.get_canon_mnem() == "mov"
            natural_return = following + mov.size
            old_return = ida_bytes.get_byte(natural_return)
            assert old_return == 0xC3
            ida_bytes.patch_byte(natural_return, 0xCC)
            check(
                "continuation patch restores noreturn",
                bool(ida_funcs.get_func(root).flags & ida_funcs.FUNC_NORET),
            )
            check(
                "continuation patch revokes flag receipt", (receipt(root) or b"")[:4] != b"NPR\x02"
            )
            ida_bytes.patch_byte(natural_return, old_return)
            ida_auto.plan_and_wait(root, natural_return + 1)
            refresh_native()
            check(
                "restored continuation clears noreturn",
                (ida_funcs.get_func(root).flags & ida_funcs.FUNC_NORET) == 0,
            )
            check("restored continuation owns flag again", (receipt(root) or b"")[:4] == b"NPR\x02")
            backward = roots[0]
            call = instruction(backward)
            target = call.Op1.addr
            check(
                "gadget tail removed",
                ida_funcs.remove_func_tail(ida_funcs.get_func(backward), target),
            )
            check(
                "tail removal restores noreturn",
                bool(ida_funcs.get_func(backward).flags & ida_funcs.FUNC_NORET),
            )
            check("tail removal revokes owned flag", (receipt(backward) or b"")[:4] != b"NPR\x02")
    else:
        raise ValueError("unknown test stage")
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))

report["passed"] = not report["errors"]
(Path(os.environ["IDAUSR"]).parent / "get_pc_noreturn.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
line = "[chernobog][get-pc-noreturn] " + (
    "PASS" if report["passed"] else "FAIL " + "; ".join(report["errors"])
)
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(0 if report["passed"] else 2)
