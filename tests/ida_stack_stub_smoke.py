"""Check stack-stub ownership, early lowering and falsification in a disposable IDB."""

import json
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_name
import ida_pro
import ida_ua
import ida_xref
import idc


def address(name):
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
    assert ea != ida_idaapi.BADADDR, name
    return ea


def targets(ea):
    result = set()
    ref = ida_xref.xrefblk_t()
    ok = ref.first_from(ea, ida_xref.XREF_ALL)
    while ok:
        if ref.iscode and (ref.type & ida_xref.XREF_MASK) in (ida_xref.fl_JN, ida_xref.fl_F):
            result.add(int(ref.to))
        ok = ref.next_from()
    return result


def settle(start, end):
    assert ida_auto.plan_and_wait(start, end)
    assert ida_auto.auto_wait()
    # Synchronous IDAPython analysis does not emit the UI's auto_empty_finally
    # notification. Run the same post-analysis step explicitly.
    result = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, "chernobog_native_analysis()")


def microcode(name):
    root = address(name)
    failure = ida_hexrays.hexrays_failure_t()
    mba = ida_hexrays.gen_microcode(
        ida_hexrays.mba_ranges_t(ida_funcs.get_func(root)),
        failure,
        None,
        ida_hexrays.DECOMP_NO_CACHE | ida_hexrays.DECOMP_ALL_BLKS,
        ida_hexrays.MMAT_GENERATED,
    )
    assert mba is not None, failure.desc()
    result = []
    stack_reg = int(ida_hexrays.reg2mreg(ida_idp.str2reg("esp")))
    machine_regs = {
        int(ida_hexrays.reg2mreg(ida_idp.str2reg(reg))): 0x11111111 * (i + 1)
        for i, reg in enumerate(("eax", "ecx", "edx", "ebx", "ebp", "esi", "edi"))
    }
    original_regs = dict(machine_regs)
    start_sp = 0x100000
    adjustment = 4 if "_ret_" in name else 0
    machine_regs[stack_reg] = start_sp - (12 if adjustment else 8)
    before_sp = machine_regs[stack_reg]
    handler = address(name + "_handler")
    memory = {before_sp: handler, start_sp - 4: address(name + "_continuation")}
    if adjustment:
        memory[start_sp - 8] = 0x12345678
    original_memory = dict(memory)

    def value(op):
        assert op.size == 4
        if op.t == ida_hexrays.mop_r:
            return machine_regs[int(op.r)]
        assert op.t == ida_hexrays.mop_n
        return int(op.nnn.value)

    target = None
    for i in range(mba.qty):
        insn = mba.get_mblock(i).head
        while insn is not None:
            if insn.ea == address(name + "_return"):
                result.append({"opcode": int(insn.opcode), "text": insn.dstr()})
                if insn.opcode == ida_hexrays.m_pop:
                    assert insn.d.t == ida_hexrays.mop_r and insn.d.size == 4
                    machine_regs[int(insn.d.r)] = memory[machine_regs[stack_reg]]
                    machine_regs[stack_reg] += 4
                elif insn.opcode == ida_hexrays.m_add:
                    assert insn.d.t == ida_hexrays.mop_r and int(insn.d.r) == stack_reg
                    machine_regs[stack_reg] = (value(insn.l) + value(insn.r)) & 0xFFFFFFFF
                elif insn.opcode == ida_hexrays.m_goto:
                    if insn.l.t == ida_hexrays.mop_b:
                        target = int(mba.get_mblock(insn.l.b).start)
                    else:
                        assert insn.l.t == ida_hexrays.mop_v
                        target = int(insn.l.g)
                else:
                    # Negative probes retain the original unlowered return.
                    target = None
            insn = insn.next
    if target is not None:
        assert target == handler and machine_regs[stack_reg] == start_sp - 4
        assert all(machine_regs[reg] == val for reg, val in original_regs.items())
        assert memory == original_memory, "lowering must preserve stored stack bytes"
    return result


records = []
try:
    ida_auto.auto_wait()
    assert ida_hexrays.init_hexrays_plugin()
    names = [
        f"ss_{reg}_{form}_{mask}"
        for reg in ("eax", "ecx", "edx", "ebx", "ebp", "esi", "edi")
        for form in ("ret", "xchg")
        for mask in range(8 if form == "ret" else 4)
    ]
    for name in names:
        start, end = address(name), address(name + "_continuation") + 1
        # Explicit fixture ownership admits the handler body to this function.
        # Native target recognition is independent of this ownership repair.
        cursor = start
        while cursor < end:
            owner = ida_funcs.get_func(cursor)
            if owner is not None:
                ida_funcs.del_func(owner.start_ea)
            insn = ida_ua.insn_t()
            assert ida_ua.decode_insn(insn, cursor) > 0
            ida_ua.create_insn(cursor)
            cursor += insn.size
        assert ida_funcs.add_func(start, end), name
        settle(start, end)
        site, handler = address(name + "_return"), address(name + "_handler")
        if targets(site) != {handler}:
            native = []
            cursor = start
            while cursor < end:
                insn = ida_ua.insn_t()
                assert ida_ua.decode_insn(insn, cursor) > 0
                ref = ida_xref.xrefblk_t()
                incoming = []
                ok = ref.first_to(cursor, ida_xref.XREF_ALL)
                while ok:
                    incoming.append(
                        {"from": int(ref.frm), "type": int(ref.type), "code": bool(ref.iscode)}
                    )
                    ok = ref.next_to()
                native.append(
                    {
                        "ea": cursor,
                        "size": insn.size,
                        "auxpref": insn.auxpref,
                        "flags": int(ida_bytes.get_flags(cursor)),
                        "owner": (
                            int(ida_funcs.get_func(cursor).start_ea)
                            if ida_funcs.get_func(cursor)
                            else None
                        ),
                        "refs": incoming,
                    }
                )
                cursor += insn.size
            records.append(
                {
                    "name": name,
                    "native": native,
                    "view": json.loads(idc.eval_idc(f"chernobog_native_evidence({start})")),
                }
            )
        assert targets(site) == {handler}, (name, targets(site), handler)
        view = json.loads(idc.eval_idc(f"chernobog_native_evidence({start})"))
        proof = next(row for row in view["records"] if row.get("kind") == "stack-stub")
        assert proof["fresh"] == "true" and proof["stack_delta_bytes"] == "-4", proof
        insns = microcode(name)
        ops = [row["opcode"] for row in insns]
        assert ida_hexrays.m_pop in ops and ida_hexrays.m_goto in ops, (name, insns)
        assert (ida_hexrays.m_add in ops) == ("_ret_" in name), (name, insns)
        records.append({"name": name, "proof": proof, "return_microcode": insns})
    name = "ss_eax_ret_0"
    root, site = address(name), address(name + "_return")
    handler, end = address(name + "_handler"), address(name + "_continuation") + 1
    assert ida_bytes.get_byte(root + 1) == 0x50
    ida_bytes.patch_byte(root + 1, 0x51)
    assert handler not in targets(site), "patch must revoke owned edge synchronously"
    ida_bytes.patch_byte(root + 1, 0x50)
    settle(root, end)
    assert targets(site) == {handler}, "restored bytes must recover proof"
    source = address("ss_ecx_ret_0")
    assert ida_xref.add_cref(source, root + 1, ida_xref.fl_JN | ida_xref.XREF_USER)
    assert handler not in targets(site), "interior entry must revoke proof"
    assert ida_hexrays.m_goto not in [
        row["opcode"] for row in microcode(name)
    ], "interior entry must disable lowering"
    ida_xref.del_cref(source, root + 1, False)
    settle(root, end)
    assert targets(site) == {handler}
    status, code = "PASS cases=84 patch_and_entry_revocation=2", 0
except Exception as error:
    status, code = "FAIL " + repr(error), 2
(Path(os.environ["IDAUSR"]).parent / "stack_stubs.json").write_text(
    json.dumps({"records": records, "status": status}, indent=2) + "\n"
)
line = "[chernobog][stack-stubs] " + status
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(code)
