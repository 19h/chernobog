"""Decode, consume and invalidate bounded native get-PC facts in IDA."""

import json
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_name
import ida_pro
import ida_ua
import ida_xref


def address(name):
    # Interior labels are assembler-local so the loader cannot interpret each
    # test observation point as an independent function entry.
    interior = {
        "gp_materialize_lea": ("gp_materialize", 1),
        "gp_materialize_xchg": ("gp_materialize", 2),
        "gp_materialize_ret": ("gp_materialize", 5),
        "gp_renamed_ret": ("gp_renamed", 5),
        "gp_restore_push": ("gp_restore", 1),
        "gp_restore_ret": ("gp_restore", 6),
        "gp_read_ret": ("gp_read", 6),
        "gp_alias_ret": ("gp_alias", 6),
        "gp_spwrite_ret": ("gp_spwrite", 6),
        "gp_call_resume": ("gp_call", 1),
        "gp_adjust_resume": ("gp_adjust", 4),
        "gp_sign8_set": ("gp_sign8", 3),
        "gp_sign32_set": ("gp_sign32", 4),
    }
    if name in interior:
        root, count = interior[name]
        ea = address(root)
        for _ in range(count):
            decoded = ida_ua.insn_t()
            assert ida_ua.decode_insn(decoded, ea) > 0
            ea += decoded.size
        return ea
    if name.endswith("_entry") or name in ("gp_call_ret", "gp_adjust_ret"):
        root = name.rsplit("_", 1)[0]
        decoded = ida_ua.insn_t()
        assert ida_ua.decode_insn(decoded, address(root)) > 0
        ea = decoded.Op1.addr
        if name.endswith("_ret"):
            for _ in range(2 if root == "gp_call" else 1):
                assert ida_ua.decode_insn(decoded, ea) > 0
                ea += decoded.size
        return ea
    for candidate in ("_" + name, name):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
        if ea != ida_idaapi.BADADDR:
            return ea
    raise AssertionError("missing " + name)


def comment(ea):
    return ida_bytes.get_cmt(ea, True) or ""


def jumps(ea):
    result = set()
    xref = ida_xref.xrefblk_t()
    ok = xref.first_from(ea, ida_xref.XREF_ALL)
    while ok:
        if xref.iscode and (xref.type & ida_xref.XREF_MASK) in (ida_xref.fl_JN, ida_xref.fl_F):
            result.add(int(xref.to))
        ok = xref.next_from()
    return result


def settle(*sites):
    for ea in sites:
        decoded = ida_ua.insn_t()
        assert ida_ua.decode_insn(decoded, ea) > 0
        ida_auto.plan_range(ea, ea + decoded.size)
    ida_auto.auto_wait()


records, errors = [], []


def check(label, condition, **evidence):
    records.append({"case": label, "passed": bool(condition), **evidence})
    if not condition:
        errors.append(label)


def annotation(name, expected):
    text = comment(address(name))
    check(
        name + " materialization",
        ("stack address materialization" in text) == expected,
        comment=text,
    )
    if expected:
        check(
            name + " retained effects",
            all(
                token in text
                for token in (
                    "width=64 bits",
                    "net SP delta=-8 bytes",
                    "flags preserved",
                    "saved register restored",
                    "locked XCHG retained",
                )
            ),
            comment=text,
        )


try:
    ida_auto.auto_wait()
    target = address("gp_target")
    for name in ("gp_sign8", "gp_sign32"):
        text = comment(address(name + "_set"))
        check(name + " sign extension reaches SETcc", "SETcc byte result 1" in text, comment=text)
    for name in (
        "gp_materialize",
        "gp_renamed",
        "gp_restore_push",
        "gp_read",
        "gp_alias",
        "gp_spwrite",
    ):
        annotation(name, True)
    for name in (
        "gp_wrongreg",
        "gp_offset",
        "gp_indexed",
        "gp_segment",
        "gp_width",
        "gp_partial",
        "gp_stackreg",
    ):
        annotation(name, False)
    for name in ("gp_materialize", "gp_renamed", "gp_restore", "gp_read"):
        site = address(name + "_ret")
        check(
            name + " consumer target",
            jumps(site) == {target},
            targets=sorted(jumps(site)),
            comment=comment(site),
        )
    for name in ("gp_alias", "gp_spwrite"):
        site = address(name + "_ret")
        check(
            name + " consumer unknown",
            not jumps(site) and "unresolved target" in comment(site),
            targets=sorted(jumps(site)),
            comment=comment(site),
        )
    for name in ("gp_call", "gp_adjust", "gp_next"):
        site = address(name)
        check(name + " call-context fact", "get-PC idiom" in comment(site), comment=comment(site))
        check(
            name + " exact entry",
            jumps(site) == {address(name + "_entry")},
            targets=sorted(jumps(site)),
        )
    for name in ("gp_call", "gp_adjust"):
        site = address(name + "_ret")
        check(
            name + " exact return",
            jumps(site) == {address(name + "_resume")},
            targets=sorted(jumps(site)),
            comment=comment(site),
        )
    for name in (
        "gp_ret_extra",
        "gp_ret_far",
        "gp_ret_width",
        "gp_popsp",
        "gp_call_alias",
        "gp_call_xchgsp",
    ):
        text = comment(address(name))
        check(name + " rejected", "get-PC idiom" not in text, comment=text)
    check("target function retained", ida_funcs.get_func_start(target) == target)

    root, swap = address("gp_materialize"), address("gp_materialize_xchg")
    site = address("gp_materialize_ret")
    original = ida_bytes.get_bytes(swap, 4)
    check("fixture exchange bytes", original == b"\x48\x87\x04\x24")
    ida_bytes.patch_bytes(swap, b"\x48\x87\x0c\x24")  # RCX replaces RAX.
    check(
        "support edit revokes annotation synchronously",
        "stack address materialization" not in comment(root),
    )
    settle(root, swap, site)
    check(
        "changed stack value removes consumer target", not jumps(site), targets=sorted(jumps(site))
    )
    ida_bytes.patch_bytes(swap, original)
    settle(root, swap, site)
    check(
        "restored materialization",
        "stack address materialization" in comment(root) and jumps(site) == {target},
        root_comment=comment(root),
        return_comment=comment(site),
        targets=sorted(jumps(site)),
    )
    other = address("gp_wrongreg")
    lea = address("gp_materialize_lea")
    ida_xref.add_cref(other, lea, ida_xref.fl_JN | ida_xref.XREF_USER)
    settle(root, lea)
    check("alternate entry rejects sequence", "stack address materialization" not in comment(root))
    ida_xref.del_cref(other, lea, False)
    settle(root, lea)
    check(
        "removed alternate entry restores sequence",
        "stack address materialization" in comment(root),
    )
    root, entry, site = address("gp_adjust"), address("gp_adjust_entry"), address("gp_adjust_ret")
    original = ida_bytes.get_bytes(entry, 5)
    check("fixture stack adjustment bytes", original == b"\x48\x83\x04\x24\x03")
    ida_bytes.patch_byte(entry + 2, 0x2C)  # SUB [RSP],3 is outside this recognizer.
    check(
        "CALL and RET annotations revoked synchronously",
        "get-PC idiom" not in comment(root) and "exact call-context" not in comment(site),
    )
    check(
        "CALL-context return edge revoked synchronously",
        not jumps(site),
        targets=sorted(jumps(site)),
    )
    settle(root, entry, site)
    check(
        "unsupported stack transform stays unresolved",
        "get-PC idiom" not in comment(root) and not jumps(site),
        targets=sorted(jumps(site)),
    )
    ida_bytes.patch_bytes(entry, original)
    settle(root, entry, site)
    check(
        "restored call context",
        "get-PC idiom" in comment(root) and jumps(site) == {address("gp_adjust_resume")},
        comment=comment(root),
        targets=sorted(jumps(site)),
    )
except BaseException as error:
    errors.append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "get_pc.json").write_text(
    json.dumps({"records": records, "errors": errors}, indent=2) + "\n"
)
message = "FAIL " + "; ".join(errors) if errors else "PASS assertions=%d" % len(records)
line = "[chernobog][get-pc] " + message
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
