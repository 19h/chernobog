"""Capture fresh SETcc/CMOV generation and same-IDB invalidation controls."""

import json
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays as hx
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_name
import ida_pro
import ida_range
import ida_ua
import ida_xref
import idautils
import idc


def operand(op):
    result = {"type": int(op.t), "size": int(op.size), "text": op.dstr()}
    if op.t == hx.mop_r:
        result["register"] = int(op.r)
    elif op.t == hx.mop_n:
        result["value"] = int(op.nnn.value)
    elif op.t == hx.mop_d:
        result["instruction"] = instruction(op.d)
    elif op.t == hx.mop_h:
        result["helper"] = op.helper
    elif op.t == hx.mop_f:
        result["call"] = {
            "arguments": [operand(arg) for arg in op.f.args],
            "flags": int(op.f.flags),
            "spoiled": op.f.spoiled.dstr(),
            "all_memory_visible": bool(op.f.visible_memory.all_values()),
            "visible_memory": op.f.visible_memory.dstr(),
            "return_size": int(op.f.return_type.get_size()),
            "return_type": op.f.return_type.dstr(),
        }
    return result


def instruction(insn):
    return {
        "ea": int(insn.ea),
        "opcode": int(insn.opcode),
        "text": insn.dstr(),
        "iprops": int(insn.iprops),
        "left": operand(insn.l),
        "right": operand(insn.r),
        "destination": operand(insn.d),
    }


def stats():
    return {
        key: int(idc.eval_idc("chernobog_early_stats()." + key + ";"))
        for key in ("codegen_setcc", "codegen_cmov", "codegen_cmov_memory")
    }


def capture(name, entry, phase):
    function = ida_funcs.get_func(entry)
    assert function is not None
    native, sites = [], []
    for ea in idautils.FuncItems(entry):
        insn = ida_ua.insn_t()
        assert ida_ua.decode_insn(insn, ea) > 0
        mnemonic = insn.get_canon_mnem()
        native.append(
            {
                "ea": int(ea),
                "size": int(insn.size),
                "mnemonic": mnemonic,
                "bytes": ida_bytes.get_bytes(ea, insn.size).hex(),
            }
        )
        if mnemonic.startswith(("set", "cmov")):
            sites.append(int(ea))
    assert len(sites) == 1, "expected one condition in fixture"
    before = stats()
    failure = hx.hexrays_failure_t()
    ranges = hx.mba_ranges_t(function)
    if phase == "snippet":
        ranges = hx.mba_ranges_t()
        ranges.ranges.push_back(ida_range.range_t(function.start_ea, function.end_ea))
    maturity = getattr(hx, os.environ.get("CHERNOBOG_CONDITION_MATURITY", "MMAT_GENERATED"))
    mba = hx.gen_microcode(ranges, failure, None, hx.DECOMP_NO_CACHE | hx.DECOMP_ALL_BLKS, maturity)
    assert mba is not None, failure.desc()
    mba.verify(True)
    blocks = []
    for index in range(mba.qty):
        block = mba.get_mblock(index)
        items, insn = [], block.head
        while insn:
            items.append(instruction(insn))
            insn = insn.next
        blocks.append({"index": index, "instructions": items})
    after = stats()
    effect_sites = list(sites)
    if name.startswith("vc_cm_order_"):
        index = next(i for i, n in enumerate(native) if n["ea"] == sites[0])
        effect_sites += [native[index - 1]["ea"], native[index + 1]["ea"]]
    snippet = [i for b in blocks for i in b["instructions"] if i["ea"] in effect_sites]
    ctree = None
    if phase == "initial" and os.environ.get("CHERNOBOG_CONDITION_DECOMPILE") == "1":
        cfunc = hx.decompile(entry, failure, hx.DECOMP_NO_CACHE)
        assert cfunc is not None, failure.desc()
        ctree = str(cfunc)
    return {
        "name": name,
        "phase": phase,
        "entry": int(entry),
        "native": native,
        "sites": sites,
        "snippet": snippet,
        "blocks": blocks,
        "ctree": ctree,
        "delta": {key: after[key] - before[key] for key in before},
    }


records, errors, registers = [], [], {}
try:
    ida_auto.auto_wait()
    assert hx.init_hexrays_plugin()
    word = 8 if ida_ida.inf_is_64bit() else 4
    for name in (
        "rax",
        "rcx",
        "rdx",
        "rbx",
        "rsp",
        "rbp",
        "rsi",
        "rdi",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
        "ds",
        "cf",
        "zf",
        "sf",
        "of",
        "pf",
    ):
        if name in ("cf", "zf", "sf", "of", "pf"):
            registers[name] = int(getattr(hx, "mr_" + name))
        else:
            if word == 4 and name.startswith("r") and name[1:].isdigit():
                continue
            native_name = "e" + name[1:] if word == 4 and name.startswith("r") else name
            registers[name] = int(hx.reg2mreg(ida_idp.str2reg(native_name)))
    functions = sorted(
        (ida_name.get_name(ea).lstrip("_"), ea)
        for ea in idautils.Functions()
        if ida_name.get_name(ea).lstrip("_").startswith("vc_")
        and ida_name.get_name(ea).lstrip("_") != "vc_invoke"
    )
    assert len(functions) == 53, "fixture function coverage"
    for name, entry in functions:
        records.append(capture(name, entry, "initial"))
    entry = dict(functions)["vc_e"]
    prefix = next(
        insn
        for record in records
        if record["name"] == "vc_e"
        for insn in record["native"]
        if insn["bytes"] == "31c9"
    )
    site = prefix["ea"]
    original = bytes.fromhex(prefix["bytes"])
    assert original == b"\x31\xc9"
    try:
        ida_bytes.patch_bytes(site, b"\x85\xf6")  # TEST ESI,ESI: unknown input.
        ida_auto.plan_and_wait(site, site + 2)
        records.append(capture("vc_e", entry, "patched_unknown"))
    finally:
        ida_bytes.patch_bytes(site, original)
        ida_auto.plan_and_wait(site, site + 2)
    records.append(capture("vc_e", entry, "restored"))
    target = records[-1]["sites"][0]
    source = dict(functions)["vc_unknown"]
    try:
        assert ida_xref.add_cref(source, target, ida_xref.fl_JN | ida_xref.XREF_USER)
        records.append(capture("vc_e", entry, "alternate_entry"))
    finally:
        ida_xref.del_cref(source, target, False)
    records.append(capture("vc_e", entry, "entry_removed"))
    records.append(capture("vc_e", entry, "snippet"))
except BaseException as error:
    errors.append(type(error).__name__ + ": " + str(error))

report = {
    "records": records,
    "errors": errors,
    "registers": registers,
    "word_bytes": 8 if ida_ida.inf_is_64bit() else 4,
    "maturity": os.environ.get("CHERNOBOG_CONDITION_MATURITY", "MMAT_GENERATED"),
    "opcodes": {
        name: int(getattr(hx, name)) for name in ("m_mov", "m_xdu", "m_stx", "m_nop", "m_call")
    },
    "enabled": os.environ.get("CHERNOBOG_IDA_CONDITION_CODEGEN", "1") == "1",
}
(Path(os.environ["IDAUSR"]).parent / "conditions_microcode.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
line = "[chernobog][conditions-microcode] " + (
    "FAIL " + "; ".join(errors) if errors else "PASS captures=%d" % len(records)
)
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
