"""Check production native flag analysis against exact CFG and negative controls."""

import json
import os
from pathlib import Path

import ida_allins
import ida_auto
import ida_bytes
import ida_idaapi
import ida_kernwin
import ida_name
import ida_pro
import ida_ua
import ida_xref

CASES = {
    "vf_o": False,
    "vf_no": True,
    "vf_b": False,
    "vf_ae": True,
    "vf_e": True,
    "vf_ne": False,
    "vf_be": True,
    "vf_a": False,
    "vf_s": False,
    "vf_ns": True,
    "vf_p": True,
    "vf_np": False,
    "vf_l": False,
    "vf_ge": True,
    "vf_le": True,
    "vf_g": False,
    "vf_cmc": True,
    "vf_inc_cf": True,
    "vf_stc_zf": True,
    "vf_bswap": True,
    "vf_long_window": (
        True if int(os.environ.get("CHERNOBOG_IDA_FLAG_SCAN_DEPTH", "8")) >= 41 else None
    ),
    "vf_overflow": True,
    "vf_ah": True,
    "vf_zero_extend": True,
    "vf_set_false": True,
    "vf_set_true": True,
    "vf_cmov_false32": True,
    "vf_unknown_input": None,
    "vf_unknown_carry": None,
    "vf_unknown_count": None,
    "vf_alias_unknown": None,
    "vf_call_barrier": None,
    "vf_alternate_entry": None,
}
JCC = {
    getattr(ida_allins, "NN_" + n)
    for n in (
        "jo",
        "jno",
        "jb",
        "jnb",
        "jz",
        "jnz",
        "jbe",
        "ja",
        "js",
        "jns",
        "jp",
        "jnp",
        "jl",
        "jnl",
        "jle",
        "jnle",
        "jg",
        "jge",
        "jae",
        "jc",
        "je",
        "jne",
        "jna",
        "jnae",
        "jnbe",
        "jnc",
        "jng",
        "jnge",
        "jpe",
        "jpo",
    )
}


def address(name):
    for candidate in ("_" + name, name):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
        if ea != ida_idaapi.BADADDR:
            return ea
    raise RuntimeError("missing " + name)


def branch(name):
    ea = address(name)
    skip = 1 if name == "vf_alternate_entry" else 0
    for _ in range(64):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) <= 0:
            raise RuntimeError("decode failed " + name)
        if insn.itype in JCC:
            if skip:
                skip -= 1
            else:
                return insn
        ea += insn.size
    raise RuntimeError("missing branch " + name)


def outgoing(ea):
    result = []
    xref = ida_xref.xrefblk_t()
    ok = xref.first_from(ea, ida_xref.XREF_ALL)
    while ok:
        if xref.iscode:
            result.append((int(xref.to), int(xref.type) & ida_xref.XREF_MASK))
        ok = xref.next_from()
    return sorted(set(result))


def finish(code, message):
    line = "[chernobog][x86-flags] " + message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)
    ida_pro.qexit(code)


try:
    ida_auto.auto_wait()
    records, errors = [], []
    for name, expected in CASES.items():
        insn = branch(name)
        target, fall = int(insn.Op1.addr), int(insn.ea + insn.size)
        edges = outgoing(insn.ea)
        comment = "\n".join(
            filter(None, (ida_bytes.get_cmt(insn.ea, True), ida_bytes.get_cmt(insn.ea, False)))
        )
        actual = {to for to, _ in edges}
        wanted = {target, fall} if expected is None else {target if expected else fall}
        if actual != wanted:
            errors.append("%s: edges %r expected %r" % (name, actual, wanted))
        marker = "locally proven x86 flags" in comment
        if marker != (expected is not None):
            errors.append("%s: unexpected proof annotation %r" % (name, comment))
        records.append(
            {
                "name": name,
                "expected": expected,
                "ea": int(insn.ea),
                "edges": edges,
                "comment": comment,
                "raw": ida_bytes.get_bytes(insn.ea, insn.size).hex(),
            }
        )
    (Path(os.environ["IDAUSR"]).parent / "x86_flags.json").write_text(
        json.dumps({"records": records, "errors": errors}, indent=2) + "\n"
    )
    if errors:
        finish(2, "FAIL " + "; ".join(errors))
    finish(0, "PASS cases=%d" % len(records))
except BaseException as error:
    finish(9, "exception: %r" % (error,))
