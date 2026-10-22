"""Verify AMD64 byte proofs, relative targets, frames and inlined callee saves."""

import json
import os
import re
from pathlib import Path
import traceback

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_idp
import ida_loader
import ida_lines
import ida_name
import ida_pro
import ida_segment
import ida_ua
import idautils
import idc

report = {"passed": False, "checks": [], "errors": []}


def check(name, value):
    report["checks"].append({"name": name, "passed": bool(value)})
    if not value:
        report["errors"].append(name)


def symbol(name):
    result = ida_name.get_name_ea(ida_idaapi.BADADDR, "_" + name)
    assert result != ida_idaapi.BADADDR, name
    return result


def microcode(root, maturity=ida_hexrays.MMAT_GLBOPT3):
    failure = ida_hexrays.hexrays_failure_t()
    result = ida_hexrays.gen_microcode(
        ida_hexrays.mba_ranges_t(ida_funcs.get_func(root)),
        failure,
        None,
        ida_hexrays.DECOMP_NO_CACHE,
        maturity,
    )
    if result is None:
        raise RuntimeError(f"{failure.desc()} at {failure.errea:X}")
    return result


def instructions(mba):
    for index in range(mba.qty):
        ins = mba.get_mblock(index).head
        while ins:
            yield ins
            ins = ins.next


def join_function(root, sites, end):
    for site in sites:
        owner = ida_funcs.get_func(site)
        if owner and owner.start_ea == site and site != root:
            assert ida_funcs.del_func(site)
    assert ida_funcs.set_func_end(root, end)


def captures(mba, site):
    saved = {ida_hexrays.reg2mreg(ida_idp.str2reg(name)) for name in ("rbp", "rbx", "r12")}
    return sum(
        ins.ea == site
        and ins.opcode == ida_hexrays.m_mov
        and ins.l.t == ida_hexrays.mop_r
        and ins.l.r in saved
        and ins.d.t == ida_hexrays.mop_r
        and ins.d.r not in saved
        for ins in instructions(mba)
    )


try:
    ida_auto.auto_wait()
    assert ida_hexrays.init_hexrays_plugin()
    root, site, call = symbol("main"), symbol("dispatch_site"), symbol("call_site")
    inline_site = symbol("inline_call_site")
    single_site, register_site = symbol("single_site"), symbol("register_site")
    fragments = [
        symbol(name)
        for name in ("fragment_false", "fragment_true", "register_fragment", "fragment_final")
    ]
    join_function(root, (call, inline_site, site), site + ida_bytes.get_item_size(site))
    join_function(fragments[1], (single_site,), single_site + ida_bytes.get_item_size(single_site))
    join_function(
        fragments[2], (register_site,), register_site + ida_bytes.get_item_size(register_site)
    )
    for address in fragments:
        if ida_funcs.get_func(address) is None:
            assert ida_funcs.add_func(address)
        assert ida_name.set_name(address, "", ida_name.SN_NOWARN)
    helper, outlined = symbol("typed_helper"), symbol("outlined_helper")
    assert idc.SetType(helper, "int __fastcall typed_helper(int value);")
    assert idc.SetType(outlined, "int __fastcall outlined_helper(int *value);")
    assert idc.SetType(symbol("call_barrier"), "void __fastcall call_barrier(void);")
    assert idc.SetType(symbol("mutate_stack"), "void __fastcall mutate_stack(int *value);")
    assert idc.SetType(symbol("alternate_helper"), "int __fastcall alternate_helper(int value);")
    address_identity = symbol("address_identity")
    assert idc.SetType(address_identity, "unsigned int __fastcall address_identity(void);")
    function = ida_funcs.get_func(outlined)
    function.flags |= ida_funcs.FUNC_OUTLINE
    assert ida_funcs.update_func(function)
    for name in (
        "custom",
        "overwritten_save",
        "mismatched_pop",
        "external_tail",
        "sp_saved_overwrite",
    ):
        address = symbol(name + "_outline")
        declaration = (
            f"int __usercall {name}_outline@<eax>(int value@<edi>);"
            if name == "custom"
            else f"int __fastcall {name}_outline(int value);"
        )
        assert idc.SetType(address, declaration)
        function = ida_funcs.get_func(address)
        function.flags |= ida_funcs.FUNC_OUTLINE
        assert ida_funcs.update_func(function)
    owner_snapshot = {a: ida_funcs.get_func(a).start_ea for a in fragments}
    text = ida_segment.getseg(root)
    original = ida_bytes.get_bytes(text.start_ea, text.end_ea - text.start_ea)
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])

    class StackCalls(ida_hexrays.minsn_visitor_t):
        def __init__(self, site):
            super().__init__()
            self.site = site
            self.targets = []

        def visit_minsn(self):
            ins = self.curins
            if ins.ea == self.site and ins.opcode in (ida_hexrays.m_call, ida_hexrays.m_icall):
                self.targets.append(
                    ins.l.g
                    if ins.opcode == ida_hexrays.m_call and ins.l.t == ida_hexrays.mop_v
                    else None
                )
            return 0

    for name, resolved in (("disjoint", True), ("escaped", False)):
        address, call_site = symbol("stack_" + name), symbol("stack_" + name + "_site")
        assert idc.SetType(address, f"int __fastcall stack_{name}(void);")
        join_function(address, (call_site,), call_site + 4)
        observed = StackCalls(call_site)
        microcode(address).for_all_insns(observed)
        check(
            "stack " + name + " call effects respected",
            bool(observed.targets)
            and ((observed.targets == [helper]) if resolved else (helper not in observed.targets)),
        )
    generated = microcode(root, ida_hexrays.MMAT_GENERATED)
    report["initial_dispatch_opcode"] = next(
        i.opcode for i in instructions(generated) if i.ea == site
    )
    check("native callee saves captured before inlining", captures(generated, inline_site) == 2)
    for name in (
        "custom",
        "overwritten_save",
        "mismatched_pop",
        "external_tail",
        "sp_saved_overwrite",
    ):
        caller, callee = symbol(name + "_caller"), symbol(name + "_outline")
        call_sites = []
        for ea in idautils.FuncItems(caller):
            ins = ida_ua.insn_t()
            if ida_ua.decode_insn(ins, ea) and ins.Op1.addr == callee:
                call_sites.append(ea)
        assert len(call_sites) == 1
        negative = microcode(caller, ida_hexrays.MMAT_GENERATED)
        check(name + " ABI adapter declined", captures(negative, call_sites[0]) == 0)
    mba = microcode(root)
    insns = list(instructions(mba))
    edges = {x.to for x in idautils.XrefsFrom(site, 0) if x.iscode}
    check("signed relative destinations proved", set(fragments[:2]).issubset(edges))
    check(
        "relative dispatch lowered to condition",
        any(i.ea == site and ida_hexrays.is_mcode_jcond(i.opcode) for i in insns),
    )
    reopened = microcode(root, ida_hexrays.MMAT_GENERATED)
    reopened_instructions = list(instructions(reopened))
    for address in fragments:
        check(
            "continuation range included " + hex(address),
            any(i.ea == address for i in reopened_instructions),
        )
    check(
        "single continuation edge",
        fragments[2] in {x.to for x in idautils.XrefsFrom(single_site, 0) if x.iscode},
    )
    check(
        "register-only continuation edge",
        fragments[3] in {x.to for x in idautils.XrefsFrom(register_site, 0) if x.iscode},
    )

    class Calls(ida_hexrays.minsn_visitor_t):
        def __init__(self):
            super().__init__()
            self.target = False
            self.widths = []

        def visit_minsn(self):
            ins = self.curins
            if ins.ea == call and ins.opcode == ida_hexrays.m_call:
                self.target = ins.l.t == ida_hexrays.mop_v and ins.l.g == helper
                self.widths = [a.size for a in ins.d.f.args]
            return 0

    calls = Calls()
    mba.for_all_insns(calls)
    check("correlated byte call resolved", calls.target)
    check("prototype collected a single 32-bit argument", calls.widths == [4])
    cfunc = ida_hexrays.decompile(root, flags=ida_hexrays.DECOMP_NO_CACHE)
    assert cfunc
    report["pseudocode"] = "\n".join(ida_lines.tag_remove(x.line) for x in cfunc.get_pseudocode())
    check(
        "structured pseudocode",
        "switch (" not in report["pseudocode"] and "__asm" not in report["pseudocode"],
    )
    check(
        "opaque tables removed",
        "table1" not in report["pseudocode"] and "table2" not in report["pseudocode"],
    )
    check(
        "inlined scratch globals do not replace caller object", "table1" not in report["pseudocode"]
    )
    comparison = report["pseudocode"].find("runtime == 7")
    write = re.search(r"(?:LODWORD\()?runtime\)? = 0", report["pseudocode"])
    overwrite = write.start() if write else -1
    check(
        "predicate evaluated before its source is overwritten",
        comparison >= 0 and overwrite > comparison,
    )
    cached = ida_hexrays.decompile(root)
    cached_again = ida_hexrays.decompile(root)
    check(
        "projected function remains cacheable",
        cached and cached_again and not cached_again.mba.is_snippet(),
    )
    check(
        "native bytes unchanged",
        original == ida_bytes.get_bytes(text.start_ea, text.end_ea - text.start_ea),
    )
    check(
        "function owners unchanged",
        owner_snapshot == {a: ida_funcs.get_func(a).start_ea for a in fragments},
    )
    address_function = ida_hexrays.decompile(address_identity, flags=ida_hexrays.DECOMP_NO_CACHE)
    assert address_function
    address_text = "\n".join(
        ida_lines.tag_remove(x.line) for x in address_function.get_pseudocode()
    )
    report["address_identity"] = address_text
    check("address-valued MBA simplified", " | " not in address_text and " & " not in address_text)
    check(
        "address simplification retains valid local allocation",
        "local variable allocation has failed" not in address_text,
    )
    second = symbol("table2")
    old = ida_bytes.get_byte(second)
    ida_bytes.patch_byte(second, old ^ 1)
    ida_hexrays.mark_cfunc_dirty(root)
    invalidated = microcode(root)

    class IndirectCalls(ida_hexrays.minsn_visitor_t):
        def __init__(self):
            super().__init__()
            self.found = False

        def visit_minsn(self):
            self.found |= self.curins.ea == call and self.curins.opcode == ida_hexrays.m_icall
            return 0

    indirect = IndirectCalls()
    invalidated.for_all_insns(indirect)
    check("a counterexample row invalidates the call proof", indirect.found)
    ida_bytes.patch_byte(second, old)
    ida_hexrays.mark_cfunc_dirty(root)
    restored = microcode(root)
    restored_calls = Calls()
    restored.for_all_insns(restored_calls)
    check("restored table permits a fresh call proof", restored_calls.target)
    table_segment = ida_segment.getseg(second)
    original_permissions = table_segment.perm
    table_segment.perm |= ida_segment.SEGPERM_WRITE
    assert ida_segment.update_segm(table_segment)
    ida_hexrays.mark_cfunc_dirty(root)
    mutable = microcode(root)
    mutable_calls = IndirectCalls()
    mutable.for_all_insns(mutable_calls)
    check("writable table revokes the call proof", mutable_calls.found)
    table_segment.perm = original_permissions
    assert ida_segment.update_segm(table_segment)
    report["passed"] = not report["errors"]
except Exception as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))
    report["trace"] = traceback.format_exc()

(Path(os.environ["IDAUSR"]).parent / "x86_finite.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print("[chernobog][x86-finite] " + ("PASS" if report["passed"] else "FAIL"), flush=True)
ida_pro.qexit(0 if report["passed"] else 2)
