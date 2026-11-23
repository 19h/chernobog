"""Exercise projected ARM64 main dispatches on the Hikari AES and branches demos."""

import hashlib
import os
import re
import traceback

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays as hx
import ida_idaapi
import ida_loader
import ida_name
import ida_nalt
import ida_pro
import ida_segment
import ida_xref


def symbol(name):
    return ida_name.get_name_ea(ida_idaapi.BADADDR, "_" + name)


def segment_hash(segment):
    return hashlib.sha256(
        ida_bytes.get_bytes(segment.start_ea, segment.end_ea - segment.start_ea)
    ).digest()


try:
    ida_auto.auto_wait()
    if slide := int(os.environ.get("CHERNOBOG_PROBE_SLIDE", "0"), 0):
        assert (
            ida_segment.rebase_program(slide, ida_segment.MSF_FIXONCE) == ida_segment.MOVE_SEGM_OK
        )
        ida_auto.auto_wait()
    assert hx.init_hexrays_plugin()
    root = symbol("main")
    assert root != ida_idaapi.BADADDR
    text = ida_segment.getseg(root)
    original_text = segment_hash(text)

    aes = symbol("aes128_encrypt_block") != ida_idaapi.BADADDR
    expected_sites = 33 if aes else 4
    obligations = (
        (
            "sample_unhex(",
            "memcmp(",
            "aes128_encrypt_block(",
            "aes128_decrypt_block(",
            "PASS AES: 3 known-answer vectors, 64 in-place round trips",
        )
        if aes
        else ("branch_loop(", "switch_case(", "printf(", "<= 128", "return 0;")
    )
    write_rva = os.environ.get("CHERNOBOG_PROBE_WRITE_RVA")
    if write_rva:
        slot = ida_nalt.get_imagebase() + int(write_rva, 0)
        assert ida_xref.add_dref(root, slot, ida_xref.dr_W | ida_xref.XREF_USER)
    use_stable_data = os.environ.get("CHERNOBOG_WRITABLE_CONST") == "2" and not write_rva
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])

    for _ in range(2):
        pseudocode = str(hx.decompile(root, flags=hx.DECOMP_NO_CACHE))
        assert all(marker in pseudocode for marker in obligations), pseudocode
        has_fallback = bool(re.search(r"__asm\s*\{\s*BR\s", pseudocode))
        assert has_fallback == (not use_stable_data), pseudocode
    print("PSEUDOCODE", pseudocode)

    failure = hx.hexrays_failure_t()
    mba = hx.gen_microcode(
        hx.mba_ranges_t(ida_funcs.get_func(root)),
        failure,
        None,
        hx.DECOMP_NO_CACHE,
        hx.MMAT_GLBOPT3,
    )
    assert mba, failure.desc()
    indirect = {
        mba.map_fict_ea(tail.ea)
        for index in range(mba.qty)
        if (tail := mba.get_mblock(index).tail) and tail.opcode == hx.m_ijmp
    }
    assert len(indirect) == (0 if use_stable_data else expected_sites), indirect
    assert segment_hash(text) == original_text
except Exception:
    traceback.print_exc()
    print("[chernobog][hikari-dispatch] FAIL")
    ida_pro.qexit(1)

print(f"[chernobog][hikari-dispatch] PASS sites={expected_sites} fallbacks={len(indirect)}")
ida_pro.qexit(0)
