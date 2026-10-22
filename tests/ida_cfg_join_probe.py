"""Check late incoming edges cannot freeze a caller-dependent shared dispatch."""

import json
import os
from pathlib import Path
import traceback

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_gdl
import ida_idaapi
import ida_loader
import ida_lines
import ida_name
import ida_pro
import idc
import idautils

report = {"passed": False, "checks": [], "errors": []}


def check(name, condition):
    report["checks"].append({"name": name, "passed": bool(condition)})
    if not condition:
        report["errors"].append(name)


def symbol(name):
    address = ida_name.get_name_ea(ida_idaapi.BADADDR, "_" + name)
    assert address != ida_idaapi.BADADDR, name
    return address


generation = []


class GenerationHooks(ida_hexrays.Hexrays_Hooks):
    def microcode(self, mba):
        if mba.entry_ea == root:
            opcodes = [
                mba.get_mblock(i).tail.opcode
                for i in range(mba.qty)
                if mba.get_mblock(i).tail and mba.get_mblock(i).tail.ea == shared_site
            ]
            generation.append(opcodes)
        return 0


try:
    ida_auto.auto_wait()
    assert ida_hexrays.init_hexrays_plugin()
    root, end, shared, late, shared_site = [
        symbol(name) for name in ("main", "fixture_end", "shared", "late_site", "shared_site")
    ]
    authenticated = idc.print_insn_mnem(shared_site).upper().startswith("BRA")
    observed = symbol("observed")
    for address in list(idautils.Functions(root, end)):
        if address != root:
            assert ida_funcs.del_func(address)
    for start, stop in list(idautils.Chunks(root)):
        if start != root:
            assert ida_funcs.remove_func_tail(ida_funcs.get_func(root), start)
    report["original_root_end"] = hex(ida_funcs.get_func(root).end_ea)
    report["initial_chunks"] = list(idautils.Chunks(root))
    report["desired_end"] = hex(end)
    if ida_funcs.get_func(root).end_ea != end:
        assert ida_funcs.set_func_end(root, end)
    assert idc.SetType(root, "int __fastcall main(int argc, char **argv);")
    assert idc.SetType(symbol("observed"), "volatile unsigned int observed;")
    ida_auto.auto_cancel(root, end)
    original = ida_bytes.get_bytes(root, end - root)
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    idc.eval_idc(f"chernobog_request({root});")
    generation_hook = GenerationHooks()
    assert generation_hook.hook()
    failure = ida_hexrays.hexrays_failure_t()
    generated = ida_hexrays.gen_microcode(
        ida_hexrays.mba_ranges_t(ida_funcs.get_func(root)),
        failure,
        None,
        ida_hexrays.DECOMP_NO_CACHE,
        ida_hexrays.MMAT_GENERATED,
    )
    assert generated, failure.desc()
    matching = [
        b for b in ida_gdl.FlowChart(ida_funcs.get_func(root)) if b.start_ea <= shared < b.end_ea
    ]
    report["initial_shared_predecessors"] = [[hex(p.start_ea) for p in b.preds()] for b in matching]
    check(
        "shared dispatch initially has one caller",
        len(matching) == 1 and len(list(matching[0].preds())) == 1,
    )
    for iteration in range(3):
        cf = ida_hexrays.decompile(root, flags=ida_hexrays.DECOMP_NO_CACHE)
        assert cf
        text = "\n".join(ida_lines.tag_remove(line.line) for line in cf.get_pseudocode())
        report.setdefault("pseudocode", []).append(text)
        transfers = []
        stores = []
        for index in range(cf.mba.qty):
            ins = cf.mba.get_mblock(index).head
            while ins:
                if ins.ea == shared_site and ins.opcode == ida_hexrays.m_ijmp:
                    transfers.append(ins.d.t not in (ida_hexrays.mop_n, ida_hexrays.mop_v))
                if ins.d.t == ida_hexrays.mop_v and ins.d.g == observed:
                    stores.append(ins.opcode != ida_hexrays.m_mov or ins.l.t != ida_hexrays.mop_n)
                ins = ins.next
        dynamic_fallback = bool(transfers) and all(transfers)
        check(
            f"both native results retained on decompilation {iteration}",
            ("71" in text and "83" in text) or (authenticated and dynamic_fallback),
        )
        check(f"shared store retains caller state {iteration}", stores and all(stores))
        check(
            f"runtime input retained on decompilation {iteration}",
            "argc" in text[text.index("{") :],
        )
        report["blocks"] = []
        for i in range(cf.mba.qty):
            b = cf.mba.get_mblock(i)
            ins = b.head
            rows = []
            while ins:
                rows.append(
                    {
                        "ea": hex(ins.ea),
                        "opcode": ins.opcode,
                        "text": ida_lines.tag_remove(ins.dstr()),
                    }
                )
                ins = ins.next
            report["blocks"].append(
                {
                    "start": hex(b.start),
                    "pred": list(b.predset),
                    "succ": list(b.succset),
                    "insns": rows,
                }
            )
    check("native instructions unchanged", ida_bytes.get_bytes(root, end - root) == original)
    cached = ida_hexrays.decompile(root)
    cached_text = (
        "\n".join(ida_lines.tag_remove(line.line) for line in cached.get_pseudocode())
        if cached
        else ""
    )
    check(
        "cached view retains runtime input",
        "{" in cached_text and "argc" in cached_text.split("{", 1)[1],
    )
    check("discovery restarts native generation", len(generation) > 4)
    warmed = ida_hexrays.gen_microcode(
        ida_hexrays.mba_ranges_t(ida_funcs.get_func(root)),
        failure,
        None,
        ida_hexrays.DECOMP_NO_CACHE,
        ida_hexrays.MMAT_GENERATED,
    )
    assert warmed, failure.desc()
    opcodes = [
        warmed.get_mblock(i).tail.opcode
        for i in range(warmed.qty)
        if warmed.get_mblock(i).tail and warmed.get_mblock(i).tail.ea == shared_site
    ]
    check(
        "cached singleton never forces a generated goto",
        opcodes and ida_hexrays.m_goto not in opcodes,
    )
    report["generation_count"] = len(generation)
    report["generated_shared_opcodes"] = opcodes
    generation_hook.unhook()
    report["passed"] = not report["errors"]
except Exception as error:
    report["errors"].append(str(error))
    report["traceback"] = traceback.format_exc()

(Path(os.environ["IDAUSR"]).parent / "cfg_join.json").write_text(json.dumps(report, indent=2))
print("[chernobog][cfg-join] " + ("PASS" if report["passed"] else "FAIL"), flush=True)
ida_pro.qexit(0 if report["passed"] else 1)
