"""Save/reopen ownership for a stack transfer with an immutable pointer."""

import json
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_name
import ida_pro
import ida_ua
import ida_xref


def address(name):
    for label in ("_" + name, name):
        value = ida_name.get_name_ea(ida_idaapi.BADADDR, label)
        if value != ida_idaapi.BADADDR:
            return value
    raise AssertionError("missing fixture symbol " + name)


def instruction(ea):
    result = ida_ua.insn_t()
    assert ida_ua.decode_insn(result, ea) > 0
    return result


def outgoing(ea):
    result = set()
    xref = ida_xref.xrefblk_t()
    ok = xref.first_from(ea, ida_xref.XREF_ALL)
    while ok:
        if xref.iscode:
            result.add(int(xref.to))
        ok = xref.next_from()
    return result


records = []
stage = os.environ.get("CHERNOBOG_TEST_OWNERSHIP_STAGE", "write")
run_dir = Path(os.environ["IDAUSR"]).parent
user_line = "analyst stack-transfer annotation"


def check(label, condition):
    records.append({"case": label, "passed": bool(condition)})
    assert condition, label


try:
    ida_auto.auto_wait()
    push = instruction(address("vt_mem"))
    site, pointer, target = push.ea + push.size, push.Op1.addr, address("vt_target")
    check("exact memory transfer", outgoing(site) == {target})
    if stage == "write":
        ida_bytes.set_cmt(site, (ida_bytes.get_cmt(site, True) or "") + "\n" + user_line, True)
        check(
            "stack checkpoint saved",
            ida_loader.save_database(str(run_dir / "stack_ownership.i64"), 0),
        )
    else:
        log = (run_dir / "ida.log").read_text(errors="replace")
        check("stack receipts recovered", "native ownership receipts;" in log)
        replacement = address("vt_unknown_reg")
        ida_bytes.patch_qword(pointer, replacement)
        check("persisted stack edge revoked synchronously", target not in outgoing(site))
        check("stack comment ownership preserved", ida_bytes.get_cmt(site, True) == user_line)
        ida_auto.plan_range(push.ea, site + 1)
        ida_auto.auto_wait()
        check("new immutable target recovered", outgoing(site) == {replacement})
        check(
            "new proof and user annotation coexist",
            "exact push/return" in (ida_bytes.get_cmt(site, True) or "")
            and user_line in (ida_bytes.get_cmt(site, True) or ""),
        )
    status, exit_code = "PASS", 0
except Exception as error:
    status, exit_code = "FAIL " + repr(error), 2

(run_dir / "stack_ownership.json").write_text(
    json.dumps({"stage": stage, "records": records, "status": status}, indent=2) + "\n"
)
line = "[chernobog][stack-ownership] " + status
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(exit_code)
