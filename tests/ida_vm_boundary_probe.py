"""Read-only production region audit and disposable IDB boundary controls."""
import json
import os
from pathlib import Path
import struct
import sys
import traceback
from collections import deque

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_loader
import ida_pro
import ida_segment
import ida_ua
import ida_xref

sys.dont_write_bytecode = True
checks, errors, captures = [], [], {}


def check(name, value):
    checks.append({"case": name, "passed": bool(value)})
    if not value:
        errors.append(name)


def api(ea):
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, f"chernobog_vm_regions({ea})")
    return json.loads(value.c_str())["boundary_audit"]


def refs(ea, incoming):
    x = ida_xref.xrefblk_t()
    ok = x.first_to(ea, ida_xref.XREF_ALL) if incoming else x.first_from(ea, ida_xref.XREF_ALL)
    values = []
    while ok:
        values.append((int(x.frm), int(x.to), int(x.type), bool(x.iscode)))
        assert len(values) <= 10000
        ok = x.next_to() if incoming else x.next_from()
    return values


def snapshot(addresses):
    result = []
    for ea in sorted(addresses):
        f, seg = ida_funcs.get_func(ea), ida_segment.getseg(ea)
        chunk = ida_funcs.get_fchunk(ea)
        result.append((ea, int(ida_bytes.get_full_flags(ea)),
                       (ida_bytes.get_bytes(ea, 15) or b"").hex(),
                       None if f is None else (int(f.start_ea), int(f.end_ea), int(f.flags), int(f.tailqty)),
                       None if chunk is None else (int(chunk.start_ea), int(chunk.end_ea), int(chunk.flags)),
                       None if seg is None else (int(seg.bitness), int(seg.perm)), refs(ea, True), refs(ea, False)))
    return result


def inspection_scope(root):
    # Independent over-approximation: existing non-call xrefs plus decoded near
    # operands and fallthrough. Prefixes and foreign targets may add extra nodes.
    pending, scheduled = deque([root]), {root}
    edges = 0
    while pending:
        ea = pending.popleft()
        f = ida_funcs.get_func(ea)
        if f is not None and f.start_ea != root:
            continue
        if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
            continue
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) <= 0:
            continue
        targets = set()
        for _, target, kind, code_ref in refs(ea, False):
            edges += 1
            assert edges <= 16384
            if code_ref and kind & ida_xref.XREF_MASK in {ida_xref.fl_F, ida_xref.fl_JN}:
                targets.add(target)
        if not ida_idp.is_call_insn(insn):
            if insn.Op1.type == ida_ua.o_near:
                targets.add(int(insn.Op1.addr))
            if not insn.get_canon_feature() & ida_idp.CF_STOP:
                targets.add(ea + insn.size)
        for target in sorted(targets):
            if target not in scheduled:
                assert len(scheduled) < 4096
                scheduled.add(target)
                pending.append(target)
    return scheduled


def inspect(name, root):
    scope = inspection_scope(root)
    initial = snapshot(scope)
    first = api(root)
    addresses = {root}
    for n in first["nodes"]:
        addresses.add(int(n["site"], 0))
    for e in first["edges"]:
        addresses.add(int(e["target"], 0))
    check(name + " first inspection preserves independent native inventory",
          addresses <= scope and initial == snapshot(scope))
    before = snapshot(addresses)
    second = api(root)
    check(name + " repeatable read-only inspection", first == second and before == snapshot(addresses))
    check(name + " no execution admission", not second["execution_admitted"])
    check(name + " bounded output", len(second["nodes"]) <= 1024 and len(second["edges"]) <= 2048
          and second["incoming_examined"] <= 8192)
    accepted = [n for n in second["nodes"] if not n["rejection"]]
    check(name + " source bytes retained", all(n["bytes"] == ida_bytes.get_bytes(int(n["site"], 0), int(n["size"])).hex() for n in accepted))
    check(name + " decoded counts consistent", len(accepted) == second["decoded_heads"]
          and sum(n["owner"] == "none" for n in accepted) == second["ownerless_heads"])
    captures[name] = second
    return second


def reasons(a):
    return {f["reason"] for f in a["frontiers"]}


try:
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    v = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(v, ida_idaapi.BADADDR, "chernobog_native_analysis()")
    ida_auto.auto_wait()
    entries = {name: int(ea, 0) for name, ea in json.loads(os.environ["CHERNOBOG_CORPUS_ENTRIES"]).items()}
    for name, ea in entries.items():
        inspect(name, ea)
    if os.environ.get("CHERNOBOG_BOUNDARY_CONTROLS") == "1":
        # Stop automatic analysis while constructing intentionally ownerless,
        # stale-xref and shared-tail controls in this disposable database.
        ida_auto.enable_auto(False)
        mode = ida_segment.getseg(next(iter(entries.values()))).bitness
        base = (max(ida_segment.getnseg(i).end_ea for i in range(ida_segment.get_segm_qty())) + 0xFFFF) & ~0xFFFF
        assert ida_segment.add_segm(0, base, base + 0x10000, "boundary_controls", "CODE")
        seg = ida_segment.getseg(base)
        seg.perm, seg.bitness = 5, mode
        assert ida_segment.update_segm(seg)

        def code(ea, payload):
            ida_bytes.put_bytes(ea, payload)
            assert ida_ua.create_insn(ea) == len(payload)

        def jump(ea, target):
            code(ea, b"\xe9" + struct.pack("<i", target - ea - 5))

        root, body, other = base, base + 0x100, base + 0x200
        jump(root, body)
        code(body, b"\x90")
        code(body + 1, b"\xc3")
        assert ida_funcs.add_func(root, root + 5)
        a = inspect("ownerless", root)
        check("ownerless native path reaches unresolved RET", a["decoded_heads"] == 3 and a["ownerless_heads"] == 2
              and reasons(a) == {"unresolved_return"})
        # An arbitrary xref on a RET cannot authorize a native dispatch edge.
        code(other, b"\xc3")
        assert ida_xref.add_cref(body + 1, other, ida_xref.fl_JN | ida_xref.XREF_USER)
        a = inspect("ret_xref", root)
        check("RET xref never followed", len(a["nodes"]) == 3 and all(int(n["site"], 0) != other for n in a["nodes"]))
        ida_xref.del_cref(body + 1, other, False)
        assert ida_xref.add_cref(other, body, ida_xref.fl_JN | ida_xref.XREF_USER)
        check("side entry reported", "external_code_entry" in reasons(inspect("side_entry", root)))
        ida_xref.del_cref(other, body, False)
        assert ida_xref.add_cref(root, body + 1, ida_xref.fl_JN | ida_xref.XREF_USER)
        check("spurious internal xref reported", "unverified_internal_xref" in reasons(inspect("internal_xref", root)))
        ida_xref.del_cref(root, body + 1, False)
        assert ida_funcs.add_func(body, body + 2)
        check("foreign owner reported", "foreign_function" in reasons(inspect("foreign", root)))
        assert ida_funcs.del_func(body)
        check("ownership removal restores inspection", api(root) == captures["ownerless"])
        assert ida_funcs.add_func(other, other + 1)
        assert ida_funcs.append_func_tail(ida_funcs.get_func(root), body, body + 2)
        assert ida_funcs.append_func_tail(ida_funcs.get_func(other), body, body + 2)
        check("shared tail reported", "shared_function_tail" in reasons(inspect("shared_tail", root)))
        assert ida_funcs.remove_func_tail(ida_funcs.get_func(other), body)
        assert ida_funcs.remove_func_tail(ida_funcs.get_func(root), body)
        assert ida_funcs.del_func(other)
        check("tail removal restores inspection", api(root) == captures["ownerless"])
        # Decoder target remains authoritative even after removing its IDB xref.
        ida_xref.del_cref(root, body, False)
        a = inspect("missing_xref", root)
        check("decoded branch does not require IDB xref", a["decoded_heads"] == 3 and any(int(e["target"], 0) == body for e in a["edges"]))
        assert ida_xref.add_cref(root, body, ida_xref.fl_JN)
        # Call, indirect jump, trap and missing-code cases use separate roots.
        for index, (name, payload, expected) in enumerate([
            ("call", b"\xe8\0\0\0\0", "call_requires_summary"),
            ("indirect", b"\xff\xe0", "unresolved_indirect"),
            ("trap", b"\xcc", "unsupported_control"),
            ("prefix", b"\xf3\xc3", "unsupported_prefix"),
            ("missing", b"\x90", "missing_code_head"),
        ]):
            at = base + 0x400 + index * 0x40
            code(at, payload)
            assert ida_funcs.add_func(at, at + len(payload))
            a = inspect(name, at)
            check(name + " classified boundary", expected in reasons(a))
            if name in {"call", "indirect", "trap"}:
                check(name + " no continuation", len(a["nodes"]) == 1 and not a["edges"])
        # A far target segment tests permissions and mode without changing root.
        target = base + 0x20000
        assert ida_segment.add_segm(0, target, target + 0x1000, "boundary_target", "CODE")
        ts = ida_segment.getseg(target)
        ts.perm, ts.bitness = 5, mode
        assert ida_segment.update_segm(ts)
        code(target, b"\xc3")
        at = base + 0x700
        jump(at, target)
        assert ida_funcs.add_func(at, at + 5)
        ts.perm = 4
        assert ida_segment.update_segm(ts)
        check("permissions boundary", "nonexecutable_target" in reasons(inspect("permissions", at)))
        ts.perm, ts.bitness = 5, 1 if mode == 2 else 2
        assert ida_segment.update_segm(ts)
        check("mode boundary", "mode_boundary" in reasons(inspect("mode", at)))
        ts.bitness = mode
        assert ida_segment.update_segm(ts)
        # Incoming and head ceilings are reached independently.
        for i in range(65):
            at = base + 0x1000 + i * 8
            jump(at, body)
        a = inspect("incoming_budget", root)
        check("incoming cap explicit", a["incoming_limit"] and "incoming_limit" in reasons(a))
        at = base + 0x4000
        ida_bytes.put_bytes(at, b"\x90" * 1025 + b"\xc3")
        for i in range(1026):
            assert ida_ua.create_insn(at + i) == 1
        assert ida_funcs.add_func(at, at + 1026)
        a = inspect("head_budget", at)
        check("head cap explicit", a["head_limit"] and len(a["nodes"]) == 1024 and "head_limit" in reasons(a))
except Exception as error:
    errors.append(type(error).__name__)
    captures["exception_frames"] = [{"function": f.name, "line": f.lineno} for f in traceback.extract_tb(error.__traceback__)]

report = {"schema": 1, "passed": not errors, "checks": checks, "errors": errors, "captures": captures}
(Path(os.environ["IDAUSR"]).parent / "vm_boundaries.json").write_text(json.dumps(report, indent=2) + "\n")
line = "[chernobog][vm-boundary] " + ("FAIL" if errors else "PASS")
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
