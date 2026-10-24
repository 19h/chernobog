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
import idc

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
    nested_site = ida_name.get_name_ea(ida_idaapi.BADADDR, "_nested_dispatch_site")
    nested_targets = (
        (symbol("fragment_nested_false"), symbol("fragment_nested_true"))
        if nested_site != ida_idaapi.BADADDR
        else ()
    )
    single_site = ida_name.get_name_ea(ida_idaapi.BADADDR, "_single_dispatch_site")
    extra_targets = (
        (symbol("fragment_final"), symbol("fragment_final_false")) if nested_targets else ()
    )
    register_site = ida_name.get_name_ea(ida_idaapi.BADADDR, "_register_dispatch_site")
    table2 = symbol("table2")
    call_site, helper = symbol("call_site"), symbol("identity_helper")
    call_owner = ida_funcs.get_func(call_site)
    if call_owner is not None and call_owner.start_ea == call_site:
        assert ida_funcs.del_func(call_site)
    site_owner = ida_funcs.get_func(site)
    if site_owner is not None and site_owner.start_ea == site:
        assert ida_funcs.del_func(site)
    assert ida_funcs.set_func_end(root, site + 4)
    if nested_targets:
        owner = ida_funcs.get_func(nested_site)
        if owner is not None and owner.start_ea == nested_site:
            assert ida_funcs.del_func(nested_site)
        assert ida_funcs.set_func_end(true, nested_site + 4)
        owner = ida_funcs.get_func(single_site)
        if owner is not None and owner.start_ea == single_site:
            assert ida_funcs.del_func(single_site)
        assert ida_funcs.set_func_end(nested_targets[1], single_site + 4)
        owner = ida_funcs.get_func(register_site)
        if owner is not None and owner.start_ea == register_site:
            assert ida_funcs.del_func(register_site)
        assert ida_funcs.set_func_end(nested_targets[0], register_site + 4)
    for address in (false, true, *nested_targets, *extra_targets):
        if ida_funcs.get_func(address) is None:
            assert ida_funcs.add_func(address)
        assert ida_name.set_name(address, "", ida_name.SN_NOWARN)
    owner_snapshot = {
        address: ida_funcs.get_func(address).start_ea
        for address in (false, true, *nested_targets, *extra_targets)
    }
    instruction = {ea: ida_bytes.get_bytes(ea, 4) for ea in (site, call_site)}
    assert idc.SetType(helper, "int __fastcall identity_helper(int value);")
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
        any(i.ea == site and ida_hexrays.is_mcode_jcond(i.opcode) for i in insns),
    )
    check("address-based switch eliminated", not any(i.opcode == ida_hexrays.m_jtbl for i in insns))
    if nested_targets:
        nested_edges = {xref.to for xref in idautils.XrefsFrom(nested_site, 0) if xref.iscode}
        check("both nested destinations proved", set(nested_targets).issubset(nested_edges))
        check(
            "nested dispatch becomes conditional",
            any(i.ea == nested_site and ida_hexrays.is_mcode_jcond(i.opcode) for i in insns),
        )
        check(
            "nested frame fragments included",
            all(
                any(a <= i.ea < ida_funcs.get_func(a).end_ea for i in insns) for a in nested_targets
            ),
        )
        single_edges = {xref.to for xref in idautils.XrefsFrom(single_site, 0) if xref.iscode}
        check("single continuation proved", extra_targets[0] in single_edges)
        check(
            "single continuation included before liveness",
            any(
                extra_targets[0] <= i.ea < ida_funcs.get_func(extra_targets[0]).end_ea
                for i in insns
            ),
        )

    class CallVisitor(ida_hexrays.minsn_visitor_t):
        def __init__(self):
            super().__init__()
            self.resolved = False
            self.nested = False
            self.guards = []
            self.arguments = []
            self.constant_guard = False
            self.helpers = set()

        def visit_minsn(self):
            ins = self.curins
            if ins.opcode == ida_hexrays.m_call and ins.l.t == ida_hexrays.mop_h:
                self.helpers.add(ins.l.helper)
            if ins.ea == call_site and ins.opcode == ida_hexrays.m_call:
                self.resolved = ins.l.t == ida_hexrays.mop_v and ins.l.g == helper
                self.nested = ins != self.topins
                self.arguments = [arg.size for arg in ins.d.f.args]
            if (
                ins.opcode == ida_hexrays.m_call
                and ins.l.t == ida_hexrays.mop_h
                and ins.l.helper.startswith("__arm64e_auth_branch_")
            ):
                self.guards.append(ins.ea)
                if ins.ea == call_site:
                    target = ins.d.f.args[0]
                    self.constant_guard = (
                        target.t == ida_hexrays.mop_n and target.nnn.value == helper
                    )
            return 0

    calls = CallVisitor()
    mba.for_all_insns(calls)
    check("used-return helper call resolved", calls.resolved)
    check("helper return is nested in microcode", calls.nested)
    check("callee prototype used for native arguments", calls.arguments == [4])
    check("resolved guard target is constant", calls.constant_guard)
    check(
        "fixture contains a discarded authentication",
        "__arm64e_autia" in calls.helpers,
    )
    guard_sites = (
        (call_site, site, nested_site, single_site, register_site)
        if nested_targets
        else (call_site, site)
    )
    check(
        "each authentication guard retained once",
        all(calls.guards.count(ea) == 1 for ea in guard_sites),
    )
    check(
        "authentication bytes retained",
        all(ida_bytes.get_bytes(ea, 4) == data for ea, data in instruction.items()),
    )
    check(
        "function ownership retained",
        owner_snapshot == {a: ida_funcs.get_func(a).start_ea for a in owner_snapshot},
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
    check(
        "pseudocode uses structured conditions",
        "switch (" not in report["pseudocode"] and "BRAA" not in report["pseudocode"],
    )
    check(
        "discarded constant helper statements removed",
        "__arm64e_autia" not in report["pseudocode"]
        and not any(
            line.lstrip().startswith("__arm64e_") and line.rstrip().endswith(");")
            for line in report["pseudocode"].splitlines()
        ),
    )
    check(
        "constant byte lookups removed",
        "table1[" not in report["pseudocode"] and "table2[" not in report["pseudocode"],
    )
    if nested_targets:
        partial, partial_site = symbol("partial_main"), symbol("partial_site")
        independent = symbol("independent_target")
        assert ida_funcs.get_func(independent).flags & ida_funcs.FUNC_FRAME
        assert ida_name.set_name(independent, "", ida_name.SN_NOWARN)
        owner = ida_funcs.get_func(partial_site)
        if owner is not None and owner.start_ea == partial_site:
            assert ida_funcs.del_func(partial_site)
        assert ida_funcs.set_func_end(partial, partial_site + 4)
        partial_mba = microcode(partial)
        check(
            "partial frame projection declined",
            not any(
                partial_mba.get_mblock(i).start in (false, independent)
                for i in range(partial_mba.qty)
            ),
        )
        check("partial projection decompiles", ida_hexrays.decompile(partial) is not None)
        barrier, barrier_site = symbol("stack_barrier_probe"), symbol("stack_barrier_site")
        owner = ida_funcs.get_func(barrier_site)
        if owner is not None and owner.start_ea == barrier_site:
            assert ida_funcs.del_func(barrier_site)
        assert ida_funcs.set_func_end(barrier, barrier_site + 12)
        barrier_mba = microcode(barrier)

        class BarrierCalls(ida_hexrays.minsn_visitor_t):
            def __init__(self):
                super().__init__()
                self.indirect = False

            def visit_minsn(self):
                self.indirect |= (
                    self.curins.ea == barrier_site and self.curins.opcode == ida_hexrays.m_icall
                )
                return 0

        barrier_calls = BarrierCalls()
        barrier_mba.for_all_insns(barrier_calls)
        check("real call invalidates stored target", barrier_calls.indirect)
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
