"""Live IDA invalidation controls for native flag and stack-transfer evidence."""

import json
import os
from pathlib import Path

import ida_allins
import ida_auto
import ida_bytes
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_name
import ida_pro
import ida_segment
import ida_ua
import ida_xref


def address(name):
    for candidate in ("_" + name, name):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
        if ea != ida_idaapi.BADADDR:
            return ea
    return None


def instruction(ea):
    insn = ida_ua.insn_t()
    assert ida_ua.decode_insn(insn, ea) > 0
    return insn


def outgoing(ea):
    result = set()
    xref = ida_xref.xrefblk_t()
    ok = xref.first_from(ea, ida_xref.XREF_ALL)
    while ok:
        if xref.iscode:
            result.add(int(xref.to))
        ok = xref.next_from()
    return result


def user_jumps(ea):
    result = set()
    xref = ida_xref.xrefblk_t()
    ok = xref.first_from(ea, ida_xref.XREF_ALL)
    while ok:
        if xref.iscode and (xref.type & ida_xref.XREF_MASK) == ida_xref.fl_JN and xref.user:
            result.add(int(xref.to))
        ok = xref.next_from()
    return result


def settle(*addresses):
    for ea in addresses:
        ida_auto.plan_range(ea, ea + instruction(ea).size)
    ida_auto.auto_wait()


def comment(ea):
    return ida_bytes.get_cmt(ea, True) or ""


records = []


def check(label, condition):
    records.append({"case": label, "passed": bool(condition)})
    assert condition, label


def flag_checks():
    root = address("vf_e")
    defining = instruction(root)
    branch = instruction(root + defining.size)
    site, target, fall = branch.ea, branch.Op1.addr, branch.ea + branch.size
    check("initial exact branch", outgoing(site) == {target})
    original = ida_bytes.get_bytes(root, defining.size)
    check("fixture is xor eax,eax", original == b"\x31\xc0")
    user_line = "user annotation: retain verbatim"
    ida_bytes.set_cmt(site, comment(site) + "\n" + user_line, True)
    ida_bytes.patch_byte(root, 0x85)  # TEST EAX,EAX: incoming value unknown.
    check("proof comment revoked synchronously", "locally proven" not in comment(site))
    settle(root, site)
    check("unknown supports both edges", outgoing(site) == {target, fall})
    check("user comment preserved", comment(site) == user_line)
    ida_bytes.patch_bytes(root, original)
    settle(root, site)
    check("restored bytes recover proof", outgoing(site) == {target})

    source = address("vf_unknown_input")
    ida_xref.add_cref(source, site, ida_xref.fl_JN | ida_xref.XREF_USER)
    settle(site)
    check(
        "alternate entry revokes proof",
        outgoing(site) == {target, fall} and "locally proven" not in comment(site),
    )
    ida_xref.del_cref(source, site, False)
    settle(site)
    check("removed alternate entry permits proof", outgoing(site) == {target})

    # Explicit external assertion takes ownership of the formerly plugin edge.
    ida_xref.add_cref(site, target, ida_xref.fl_JN | ida_xref.XREF_USER)
    ida_bytes.patch_byte(root, 0x85)
    check("externally reasserted edge preserved", target in outgoing(site))
    settle(root, site)
    check(
        "user edge survives unknown proof",
        outgoing(site) == {target, fall} and comment(site) == user_line,
    )
    ida_bytes.patch_bytes(root, original)
    settle(root, site)
    owned_line = next(line for line in comment(site).splitlines() if "locally proven" in line)
    ida_bytes.set_cmt(site, comment(site) + "\n\n" + owned_line, True)
    ida_bytes.patch_byte(root, 0x85)
    check(
        "one user copy of an identical comment survives",
        comment(site).splitlines().count(owned_line) == 1 and user_line in comment(site),
    )


def stack_checks():
    adjust_root = address("vt_adjust")
    adjust_push = instruction(adjust_root + instruction(adjust_root).size)
    adjust_ret = adjust_push.ea + adjust_push.size
    adjust_target = address("vt_target")
    check("adjusted RET has no plugin jump", not user_jumps(adjust_ret))
    check("fixture has RET imm16 eight", ida_bytes.get_bytes(adjust_ret, 3) == b"\xc2\x08\x00")
    ida_bytes.patch_byte(adjust_ret + 1, 0)
    settle(adjust_push.ea, adjust_ret)
    check(
        "zero-adjustment RET has exact target",
        outgoing(adjust_ret) == {adjust_target} and "net SP delta=0" in comment(adjust_ret),
    )
    ida_bytes.patch_byte(adjust_ret + 1, 8)
    check("restored adjustment revokes plugin jump", not user_jumps(adjust_ret))
    settle(adjust_push.ea, adjust_ret)
    check(
        "restored adjustment republishes metadata only",
        not user_jumps(adjust_ret)
        and "net SP delta=+8 bytes" in comment(adjust_ret)
        and "adjusted RET edge withheld" in comment(adjust_ret),
    )

    reg_root = address("vt_reg")
    reg_push = instruction(reg_root + instruction(reg_root).size)
    reg_ret = reg_push.ea + reg_push.size
    original_ret_bytes = ida_bytes.get_bytes(reg_ret, 3)
    check(
        "plain RET fixture has exact target",
        outgoing(reg_ret) == {adjust_target}
        and user_jumps(reg_ret) == {adjust_target}
        and "net SP delta=0" in comment(reg_ret),
    )
    ida_bytes.patch_bytes(reg_ret, b"\xc2\x08\x00")
    check("adjusted RET revokes owned jump synchronously", not user_jumps(reg_ret))
    check(
        "adjusted RET revokes exact annotation synchronously",
        "exact push/return" not in comment(reg_ret),
    )
    settle(reg_push.ea, reg_ret)
    check(
        "adjusted RET remains metadata only after reanalysis",
        not user_jumps(reg_ret)
        and "net SP delta=+8 bytes" in comment(reg_ret)
        and "adjusted RET edge withheld" in comment(reg_ret),
    )
    ida_bytes.patch_bytes(reg_ret, original_ret_bytes)
    settle(reg_push.ea, reg_ret)
    check(
        "restored plain RET republishes exact target",
        outgoing(reg_ret) == {adjust_target}
        and user_jumps(reg_ret) == {adjust_target}
        and "net SP delta=0" in comment(reg_ret),
    )

    push = instruction(address("vt_mem"))
    site, pointer = push.ea + push.size, push.Op1.addr
    target, replacement = address("vt_target"), address("vt_unknown_reg")
    check("initial exact stack target", outgoing(site) == {target})
    original = ida_bytes.get_bytes(pointer, 8)
    external_target = address("vt_alias")

    class OtherAnalysisProvider(ida_idp.IDP_Hooks):
        def __init__(self):
            super().__init__()
            self.added = False

        def ev_add_cref(self, source, destination, kind):
            if source == site and destination == replacement and not self.added:
                self.added = True
                ida_xref.add_cref(site, external_target, ida_xref.fl_JN | ida_xref.XREF_USER)
            return 0

    other = OtherAnalysisProvider()
    check("other provider hook installed", other.hook())
    ida_bytes.patch_qword(pointer, replacement)
    check("pointer edit revokes old edge synchronously", target not in outgoing(site))
    settle(push.ea, site)
    check(
        "new pointer and independent provider coexist",
        other.added and outgoing(site) == {replacement, external_target},
    )
    other.unhook()
    ida_bytes.patch_bytes(pointer, original)
    check("other provider edge survives revocation", external_target in outgoing(site))
    ida_xref.del_cref(site, external_target, False)
    settle(push.ea, site)
    check("original pointer restores target", outgoing(site) == {target})

    segment = ida_segment.getseg(pointer)
    original_permissions = segment.perm
    segment.perm |= ida_segment.SEGPERM_WRITE
    ida_segment.update_segm(segment)
    check("writable pointer revokes proof synchronously", target not in outgoing(site))
    settle(push.ea, site)
    check(
        "writable memory remains unresolved",
        not outgoing(site) and "exact push/return" not in comment(site),
    )
    segment.perm = original_permissions
    ida_segment.update_segm(segment)
    settle(push.ea, site)
    check("read-only pointer permits proof", outgoing(site) == {target})

    source = address("vt_unknown_reg")
    ida_xref.add_dref(source, pointer, ida_xref.dr_W | ida_xref.XREF_USER)
    settle(push.ea, site)
    check(
        "write reference invalidates immutable proof",
        not outgoing(site) and "exact push/return" not in comment(site),
    )


try:
    ida_auto.auto_wait()
    if address("vf_e") is not None:
        flag_checks()
    else:
        assert address("vt_mem") is not None, "unsupported fixture"
        stack_checks()
    status, exit_code = "PASS", 0
except Exception as error:
    status, exit_code = "FAIL " + repr(error), 2

(Path(os.environ["IDAUSR"]).parent / "native_proof_lifecycle.json").write_text(
    json.dumps({"records": records, "status": status}, indent=2) + "\n"
)
line = "[chernobog][native-proof-lifecycle] " + status
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(exit_code)
