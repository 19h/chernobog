"""Persist native ownership receipts, reopen, and verify relocation/invalidation."""

import json
import os
from pathlib import Path

import ida_auto
import ida_allins
import ida_bytes
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_name
import ida_nalt
import ida_netnode
import ida_pro
import ida_segment
import ida_ua
import ida_undo
import ida_xref


def address(name):
    for label in ("_" + name, name):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, label)
        if ea != ida_idaapi.BADADDR:
            return ea
    raise AssertionError("missing fixture symbol " + name)


def instruction(ea):
    insn = ida_ua.insn_t()
    assert ida_ua.decode_insn(insn, ea) > 0
    return insn


def branch(name):
    root = address(name)
    return instruction(root + instruction(root).size)


def outgoing(ea):
    result = set()
    xref = ida_xref.xrefblk_t()
    ok = xref.first_from(ea, ida_xref.XREF_ALL)
    while ok:
        if xref.iscode:
            result.add(int(xref.to))
        ok = xref.next_from()
    return result


def settle(*sites):
    for site in sites:
        ida_auto.plan_range(site, site + instruction(site).size)
    ida_auto.auto_wait()


def value_sites():
    setter = address("vf_set_false")
    cmov = address("vf_cmov_false32")
    for _ in range(8):
        current = instruction(cmov)
        if current.itype == ida_allins.NN_xor:
            break
        cmov += current.size
    assert instruction(cmov).itype == ida_allins.NN_xor
    return [
        (setter, setter + instruction(setter).size, "SETcc byte result 0"),
        (cmov, cmov + instruction(cmov).size, "CMOVcc condition false"),
    ]


records = []
stage = os.environ.get("CHERNOBOG_TEST_OWNERSHIP_STAGE", "write")
run_dir = Path(os.environ["IDAUSR"]).parent
user_line = "analyst note retained across database reopen"


def check(label, condition):
    records.append({"case": label, "passed": bool(condition)})
    assert condition, label


try:
    ida_auto.auto_wait()
    owned, user = branch("vf_e"), branch("vf_p")
    node = ida_netnode.netnode("$ chernobog.native_proof_ownership.v1", 0, False)
    if stage == "write":
        check("owned branch initially exact", outgoing(owned.ea) == {owned.Op1.addr})
        ida_bytes.set_cmt(
            owned.ea, (ida_bytes.get_cmt(owned.ea, True) or "") + "\n" + user_line, True
        )
        ida_xref.add_cref(user.ea, user.Op1.addr, ida_xref.fl_JN | ida_xref.XREF_USER)
        settle(user.ea)
        for defining, site, marker in value_sites():
            text = ida_bytes.get_cmt(site, True) or ""
            check(marker + " initially recorded", marker in text)
            ida_bytes.set_cmt(site, text + "\n" + user_line, True)
        key = ida_nalt.ea2node(address("vf_e") + instruction(address("vf_e")).size)
        data = node.supval(key)
        check(
            "receipt recorded with bounded schema",
            data is not None and data[:4] == b"NPR\x01" and len(data) <= 615,
        )
        check(
            "database checkpoint saved", ida_loader.save_database(str(run_dir / "ownership.i64"), 0)
        )
        check("save retains live proof", outgoing(owned.ea) == {owned.Op1.addr})
    else:
        log = (run_dir / "ida.log").read_text(errors="replace")
        check("prior receipts recovered on opening", "native ownership receipts;" in log)
        check("proof recomputed on opening", outgoing(owned.ea) == {owned.Op1.addr})
        check(
            "user note survived reopening", user_line in (ida_bytes.get_cmt(owned.ea, True) or "")
        )
        if stage in ("rebase", "rebase_nodes"):
            previous = int(owned.ea)
            flags = ida_segment.MSF_FIXONCE
            if stage == "rebase_nodes":
                flags |= ida_segment.MSF_NETNODES
            check("database rebased", ida_segment.rebase_program(0x100000, flags) == 0)
            owned, user = branch("vf_e"), branch("vf_p")
            settle(address("vf_e"), owned.ea, user.ea)
            check("symbol follows rebase", owned.ea == previous + 0x100000)
            check("relocated proof recomputed", outgoing(owned.ea) == {owned.Op1.addr})
            check("relocated user edge preserved", user.Op1.addr in outgoing(user.ea))
            check(
                "rebased checkpoint saved",
                ida_loader.save_database(str(run_dir / "ownership_rebased.i64"), 0),
            )
        if stage == "undo":
            check(
                "undo point available",
                ida_undo.create_undo_point("chernobog-proof-test", "proof input patch"),
            )
        ida_bytes.patch_byte(address("vf_e"), 0x85)  # XOR -> TEST; input unknown.
        check(
            "recovered ownership revokes old edge immediately",
            owned.Op1.addr not in outgoing(owned.ea),
        )
        check(
            "recovered comment ownership removes only proof",
            ida_bytes.get_cmt(owned.ea, True) == user_line,
        )
        settle(address("vf_e"), owned.ea)
        check(
            "unknown branch has normal successors",
            outgoing(owned.ea) == {owned.Op1.addr, owned.ea + owned.size},
        )
        ida_bytes.patch_byte(address("vf_p"), 0x85)
        check("saved user ownership preserved", user.Op1.addr in outgoing(user.ea))
        settle(address("vf_p"), user.ea)
        check(
            "no stale user-branch proof comment",
            "locally proven" not in (ida_bytes.get_cmt(user.ea, True) or ""),
        )
        for defining, site, marker in value_sites():
            original = ida_bytes.get_bytes(site, instruction(site).size)
            check(marker + " survived reopening", marker in (ida_bytes.get_cmt(site, True) or ""))
            ida_bytes.patch_byte(defining, 0x85)
            check(marker + " revoked synchronously", ida_bytes.get_cmt(site, True) == user_line)
            settle(defining, site)
            check(marker + " remains unknown", ida_bytes.get_cmt(site, True) == user_line)
            check(
                marker + " leaves instruction intact",
                ida_bytes.get_bytes(site, instruction(site).size) == original,
            )
        if stage == "undo":
            check("undo succeeds", ida_undo.perform_undo())
            settle(address("vf_e"), owned.ea)
            check("undo restores defining bytes", ida_bytes.get_byte(address("vf_e")) == 0x31)
            check(
                "undo restores exact proof",
                outgoing(owned.ea) == {owned.Op1.addr}
                and "locally proven" in (ida_bytes.get_cmt(owned.ea, True) or ""),
            )
            check("redo succeeds", ida_undo.perform_redo())
            settle(address("vf_e"), owned.ea)
            check("redo restores unknown input", ida_bytes.get_byte(address("vf_e")) == 0x85)
            check(
                "redo has no stale proof",
                outgoing(owned.ea) == {owned.Op1.addr, owned.ea + owned.size}
                and ida_bytes.get_cmt(owned.ea, True) == user_line,
            )
    status, exit_code = "PASS", 0
except Exception as error:
    status, exit_code = "FAIL " + repr(error), 2

(run_dir / "native_ownership.json").write_text(
    json.dumps({"stage": stage, "records": records, "status": status}, indent=2) + "\n"
)
line = "[chernobog][native-ownership] " + status
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(exit_code)
