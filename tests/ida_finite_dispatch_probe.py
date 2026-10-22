"""Exercise bounded table proofs, predicate edges, PAC bytes and shared frames."""

import json
import os
from pathlib import Path
import traceback

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_loader
import ida_lines
import ida_name
import ida_pro
import ida_segment
import idautils

report = {"passed": False, "checks": [], "errors": []}


def check(name, passed):
    report["checks"].append({"name": name, "passed": bool(passed)})
    if not passed:
        report["errors"].append(name)


def symbol(name):
    address = ida_name.get_name_ea(ida_idaapi.BADADDR, "_" + name)
    assert address != ida_idaapi.BADADDR, name
    return address


def microcode(root):
    failure = ida_hexrays.hexrays_failure_t()
    mba = ida_hexrays.gen_microcode(
        ida_hexrays.mba_ranges_t(ida_funcs.get_func(root)),
        failure,
        None,
        ida_hexrays.DECOMP_NO_CACHE,
        ida_hexrays.MMAT_GLBOPT3,
    )
    if mba is None:
        raise RuntimeError(f"{failure.desc()} at {failure.errea:X}")
    return mba


try:
    ida_auto.auto_wait()
    assert ida_hexrays.init_hexrays_plugin()
    root, site = symbol("main"), symbol("dispatch_site")
    false, true = symbol("fragment_false"), symbol("fragment_true")
    table2 = symbol("table2")
    call_site, helper = symbol("call_site"), symbol("identity_helper")
    call_owner = ida_funcs.get_func(call_site)
    if call_owner is not None and call_owner.start_ea == call_site:
        assert ida_funcs.del_func(call_site)
    site_owner = ida_funcs.get_func(site)
    if site_owner is not None and site_owner.start_ea == site:
        assert ida_funcs.del_func(site)
    assert ida_funcs.set_func_end(root, site + 4)
    for address in (false, true):
        if ida_funcs.get_func(address) is None:
            assert ida_funcs.add_func(address)
        assert ida_name.set_name(address, "", ida_name.SN_NOWARN)
    owner_snapshot = {address: ida_funcs.get_func(address).start_ea for address in (false, true)}
    instruction = {ea: ida_bytes.get_bytes(ea, 4) for ea in (site, call_site)}
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    mba = microcode(root)
    report["microcode"] = [
        {"start": hex(mba.get_mblock(i).start), "end": hex(mba.get_mblock(i).end)}
        for i in range(mba.qty)
    ]
    edges = {xref.to for xref in idautils.XrefsFrom(site, 0) if xref.iscode}
    check("both exact destinations", {false, true}.issubset(edges))
    condition = ida_bytes.get_cmt(site, False) or ""
    check("predicate polarity", f"false={false:X}" in condition and f"true={true:X}" in condition)
    insns = []
    for index in range(mba.qty):
        ins = mba.get_mblock(index).head
        while ins:
            insns.append(ins)
            ins = ins.next
    check(
        "both frame fragments included",
        all(any(a <= i.ea < ida_funcs.get_func(a).end_ea for i in insns) for a in (false, true)),
    )
    check(
        "dispatch becomes conditional",
        any(i.ea == site and i.opcode != ida_hexrays.m_ijmp for i in insns),
    )

    class CallVisitor(ida_hexrays.minsn_visitor_t):
        def __init__(self):
            super().__init__()
            self.resolved = False
            self.nested = False

        def visit_minsn(self):
            ins = self.curins
            if ins.ea == call_site and ins.opcode == ida_hexrays.m_call:
                self.resolved = ins.l.t == ida_hexrays.mop_v and ins.l.g == helper
                self.nested = ins != self.topins
            return 0

    calls = CallVisitor()
    mba.for_all_insns(calls)
    check("used-return helper call resolved", calls.resolved)
    check("helper return is nested in microcode", calls.nested)
    check(
        "authentication bytes retained",
        all(ida_bytes.get_bytes(ea, 4) == data for ea, data in instruction.items()),
    )
    check(
        "function ownership retained",
        owner_snapshot == {a: ida_funcs.get_func(a).start_ea for a in (false, true)},
    )
    cfunc = ida_hexrays.decompile(root, flags=ida_hexrays.DECOMP_NO_CACHE)
    assert cfunc is not None
    check("projected decompilation finishes as a function", not cfunc.mba.is_snippet())
    cached = ida_hexrays.decompile(root)
    cached_again = ida_hexrays.decompile(root)
    check(
        "projected function can be cached and reopened",
        cached is not None
        and cached_again is not None
        and cached.entry_ea == root
        and cached_again.entry_ea == root
        and not cached_again.mba.is_snippet(),
    )
    report["pseudocode"] = "\n".join(
        ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()
    )
    # Existing cached proofs must be invalidated by a table change. The
    # changed byte affects one of the 256 assignments, so it cannot be
    # dismissed because the database's initial runtime seed takes another.
    original = ida_bytes.get_byte(table2)
    ida_bytes.patch_byte(table2, original ^ 1)
    altered = microcode(root)
    check(
        "changed table revokes fragment projection",
        not any(altered.get_mblock(i).start in (false, true) for i in range(altered.qty)),
    )
    ida_bytes.patch_byte(table2, original)
    microcode(root)
    segment = ida_segment.getseg(table2)
    permission = segment.perm
    segment.perm |= ida_segment.SEGPERM_WRITE
    ida_segment.update_segm(segment)
    writable = microcode(root)
    check(
        "writable table revokes fragment projection",
        not any(writable.get_mblock(i).start in (false, true) for i in range(writable.qty)),
    )
    segment.perm = permission
    ida_segment.update_segm(segment)
    report["passed"] = not report["errors"]
except Exception as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))
    report["frames"] = [
        {"function": frame.name, "line": frame.lineno}
        for frame in traceback.extract_tb(error.__traceback__)
    ]

(Path(os.environ["IDAUSR"]).parent / "finite_dispatch.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print("[chernobog][finite-dispatch] " + ("PASS" if report["passed"] else "FAIL"), flush=True)
ida_pro.qexit(0 if report["passed"] else 2)
