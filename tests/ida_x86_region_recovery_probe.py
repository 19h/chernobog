"""Exercise explicit recovery of synthetic ownerless AMD64 continuations."""

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
import ida_ua
import ida_xref
import idautils
import idc

report = {"passed": False, "checks": [], "errors": []}


def check(name, value):
    report["checks"].append({"name": name, "passed": bool(value)})
    if not value:
        report["errors"].append(name)


def symbol(name):
    address = ida_name.get_name_ea(ida_idaapi.BADADDR, "_" + name)
    assert address != ida_idaapi.BADADDR, name
    return address


def query(root, flags):
    return json.loads(idc.eval_idc(f"chernobog_recover_indirect_regions({root}, {flags});"))


try:
    ida_auto.auto_wait()
    assert ida_hexrays.init_hexrays_plugin()
    root, site, clean, old, overlap = [
        symbol("recovery_" + name) for name in ("root", "dispatch", "clean", "old_head", "overlap")
    ]
    stop = overlap + 9
    original = ida_bytes.get_bytes(root, stop - root)
    for address in (site, clean, old, overlap):
        owner = ida_funcs.get_func(address)
        if owner and owner.start_ea != root:
            assert ida_funcs.del_func(owner.start_ea)
    assert ida_funcs.set_func_end(root, site + 2)
    for address in (site, clean, old, overlap):
        assert ida_name.set_name(address, "", ida_name.SN_NOWARN)
    assert ida_bytes.del_items(old, ida_bytes.DELIT_SIMPLE, stop - old)
    assert ida_ua.create_insn(old) == 5
    assert ida_bytes.get_item_head(overlap) == old
    # Discard autoanalysis queued for the intentionally replaced test layout.
    ida_auto.auto_cancel(root, stop)
    assert idc.SetType(root, "int __fastcall recovery_root(void);")
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    initial = ida_hexrays.decompile(root, flags=ida_hexrays.DECOMP_NO_CACHE)
    assert initial
    report["initial_pseudocode"] = "\n".join(
        ida_lines.tag_remove(line.line) for line in initial.get_pseudocode()
    )
    report["initial_comment"] = ida_bytes.get_cmt(site, False)
    before = ida_bytes.get_flags(overlap)
    preview = query(root, 0)
    report["preview"] = preview
    rows = {r["target"]: r for r in preview["regions"]}
    check("both statically proved regions available", set(rows) == {clean, overlap})
    check("overlapping stream identified", rows[overlap]["overlap"])
    check("preview retains item boundary", ida_bytes.get_flags(overlap) == before)
    check(
        "preview retains orphan ownership",
        not ida_funcs.get_func(clean) and not ida_funcs.get_func(overlap),
    )
    table = symbol("recovery_table")
    row = ida_bytes.get_dword(table)
    ida_bytes.patch_dword(table, row + 1)
    check("changed table revokes recovery proof", query(root, 0)["regions"] == [])
    ida_bytes.patch_dword(table, row)
    check("restored exact table restores proof", len(query(root, 0)["regions"]) == 2)
    assert ida_xref.add_cref(root, clean, ida_xref.fl_CN)
    protected = {r["target"]: r for r in query(root, 0)["regions"]}
    check(
        "incoming call prevents recovery",
        protected[clean]["status"] == "protected incoming reference",
    )
    ida_xref.del_cref(root, clean, False)
    assert not any(x.to == clean and x.type == ida_xref.fl_CN for x in idautils.XrefsFrom(root, 0))
    assert ida_bytes.set_cmt(old, "protected synthetic metadata", False)
    protected = {r["target"]: r for r in query(root, 0)["regions"]}
    check(
        "comments prevent recovery", protected[overlap]["status"] == "protected bytes or metadata"
    )
    assert ida_bytes.set_cmt(old, "", False)
    assert ida_name.set_name(old, "protected_recovery_entry", ida_name.SN_NOWARN)
    protected = {r["target"]: r for r in query(root, 0)["regions"]}
    check(
        "user names prevent recovery", protected[overlap]["status"] == "protected bytes or metadata"
    )
    assert ida_name.set_name(old, "", ida_name.SN_NOWARN)
    simple = query(root, 1)
    report["simple"] = simple
    check(
        "ordinary orphan created",
        simple["recovered"] == 1 and ida_funcs.get_func(clean) is not None,
    )
    check(
        "overlap needs explicit selection",
        any(
            r["target"] == overlap and r["status"] == "overlap requires flag 2"
            for r in simple["regions"]
        ),
    )
    check("ordinary recovery retains overlapping item", ida_bytes.get_item_head(overlap) == old)
    selected = query(root, 3)
    report["selected"] = selected
    check("selected orphan stream recovered", selected["recovered"] == 1)
    check("selected entry is an instruction head", ida_bytes.is_head(ida_bytes.get_flags(overlap)))
    ida_auto.auto_wait()
    report["recovered_chunks"] = {str(a): list(idautils.Chunks(a)) for a in (root, clean, overlap)}
    report["selected_boundary"] = [
        old,
        overlap,
        ida_bytes.get_item_head(overlap),
        ida_bytes.get_item_size(overlap),
    ]
    ida_hexrays.mark_cfunc_dirty(root)
    failure = ida_hexrays.hexrays_failure_t()
    result = ida_hexrays.decompile(root, failure, ida_hexrays.DECOMP_NO_CACHE)
    if not result:
        raise RuntimeError(f"{failure.desc()} at {failure.errea:X}")
    text = "\n".join(ida_lines.tag_remove(line.line) for line in result.get_pseudocode())
    report["pseudocode"] = text
    check("new ranges upgrade existing projection", "__asm" not in text)
    check("projected return value retained", "return 42;" in text)
    check("native bytes unchanged", ida_bytes.get_bytes(root, stop - root) == original)
    check("unsupported flags rejected", "error" in query(root, 2))
    check("no remaining orphan candidate", query(root, 0)["regions"] == [])
    report["passed"] = not report["errors"]
except Exception as error:
    report["errors"].append(str(error))
    report["traceback"] = traceback.format_exc()

(Path(os.environ["IDAUSR"]).parent / "x86_region_recovery.json").write_text(
    json.dumps(report, indent=2)
)
print("[chernobog][x86-region-recovery] " + ("PASS" if report["passed"] else "FAIL"), flush=True)
ida_pro.qexit(0 if report["passed"] else 1)
