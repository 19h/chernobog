"""Check guarded shared-frame recovery with an observed ARM64 jump xref."""

import os
import traceback

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_loader
import ida_name
import ida_pro
import ida_segment
import ida_xref


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
    assert mba, failure.desc()
    return mba


def tails(mba):
    for index in range(mba.qty):
        if tail := mba.get_mblock(index).tail:
            yield tail


try:
    ida_auto.auto_wait()
    assert ida_hexrays.init_hexrays_plugin()
    root, site = symbol("main"), symbol("dispatch_site")
    fragment, table, independent = (
        symbol("dispatch_fragment"),
        symbol("dispatch_table"),
        symbol("independent_target"),
    )
    owner = ida_funcs.get_func(site)
    if owner is not None and owner.start_ea == site:
        assert ida_funcs.del_func(site)
    assert ida_funcs.set_func_end(root, site + 4)
    if ida_funcs.get_func(fragment) is None:
        assert ida_funcs.add_func(fragment)
    assert ida_name.set_name(fragment, "", ida_name.SN_NOWARN)
    assert ida_xref.add_cref(site, fragment, ida_xref.fl_JN | ida_xref.XREF_USER)
    assert ida_segment.getseg(table).perm & ida_segment.SEGPERM_WRITE
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])

    original = ida_bytes.get_dword(site)
    guarded = microcode(root)
    assert any(
        tail.ea == site
        and (ida_hexrays.is_mcode_jcond(tail.opcode) or tail.opcode == ida_hexrays.m_jtbl)
        for tail in tails(guarded)
    ), "observed xref erased runtime guard"

    class Fallback(ida_hexrays.minsn_visitor_t):
        found = False

        def visit_minsn(self):
            ins = self.curins
            self.found |= (
                ins.ea != site
                and guarded.map_fict_ea(ins.ea) == site
                and ins.opcode in (ida_hexrays.m_ijmp, ida_hexrays.m_icall)
            )
            return 0

    fallback = Fallback()
    guarded.for_all_insns(fallback)
    assert fallback.found, "no computed fallback for an unobserved destination"
    pseudocode = str(ida_hexrays.decompile(root, flags=ida_hexrays.DECOMP_NO_CACHE))
    assert "== 17" in pseudocode, pseudocode
    assert ida_bytes.get_dword(site) == original
    assert ida_funcs.get_func(fragment).start_ea == fragment

    assert ida_bytes.patch_qword(table, independent + 4)
    altered = microcode(root)
    assert not any(
        altered.get_mblock(i).start == fragment for i in range(altered.qty)
    ), "changed table retained a stale projected range"
except Exception:
    traceback.print_exc()
    print("[chernobog][writable-dispatch] FAIL")
    ida_pro.qexit(1)

print("[chernobog][writable-dispatch] PASS")
ida_pro.qexit(0)
