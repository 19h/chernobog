"""Capture initial get-PC microcode and stack metadata for semantic auditing."""

import json
import os
from pathlib import Path

import ida_auto
import ida_funcs
import ida_hexrays
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_name
import ida_nalt
import ida_pro
import ida_ua
import ida_xref
import idautils
import idc


def address(name):
    for candidate in ("_" + name, name):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, candidate)
        if ea != ida_idaapi.BADADDR:
            return ea
    raise RuntimeError("missing " + name)


def operand(op):
    value = {"type": int(op.t), "size": int(op.size), "text": op.dstr()}
    if op.t == ida_hexrays.mop_r:
        value["register"] = int(op.r)
    elif op.t == ida_hexrays.mop_n:
        value["value"] = int(op.nnn.value)
    elif op.t == ida_hexrays.mop_d:
        value["instruction"] = instruction(op.d)
    elif op.t == ida_hexrays.mop_b:
        value["block"] = int(op.b)
    elif op.t == ida_hexrays.mop_v:
        value["address"] = int(op.g)
    elif op.t == ida_hexrays.mop_S:
        value["stack_offset"] = int(op.s.off)
    return value


def instruction(insn):
    return {
        "ea": int(insn.ea),
        "opcode": int(insn.opcode),
        "text": insn.dstr(),
        "left": operand(insn.l),
        "right": operand(insn.r),
        "destination": operand(insn.d),
    }


records, errors = [], []
try:
    ida_auto.auto_wait()
    assert ida_hexrays.init_hexrays_plugin(), "Hex-Rays initialization"
    names = (
        ("gp_call", "gp_adjust", "gp_materialize")
        if ida_ida.inf_is_64bit()
        else ("gp32_call", "gp32_materialize")
    )
    if os.environ.get("CHERNOBOG_MICROCODE_FUNCTIONS"):
        names = tuple(os.environ["CHERNOBOG_MICROCODE_FUNCTIONS"].split(","))
    for name in names:
        ea = address(name)
        caller_ea = ea
        callee_only = os.environ.get("CHERNOBOG_MICROCODE_CALLEE_ONLY") == "1"
        if callee_only:
            call = ida_ua.insn_t()
            assert ida_ua.decode_insn(call, ea) > 0
            ea = call.Op1.addr
        function = ida_funcs.get_func(ea)
        assert function is not None, "missing function " + name
        initial_function_flags = int(function.flags)
        if callee_only:
            assert not ida_funcs.function_contains(
                ea, caller_ea
            ), "callee control must exclude its caller"
        context = None
        if os.environ.get("CHERNOBOG_MICROCODE_ADMIT_GADGET") == "1" and name not in (
            "gp_materialize",
            "gp32_materialize",
        ):
            call = ida_ua.insn_t()
            assert ida_ua.decode_insn(call, ea) > 0
            entry = call.Op1.addr
            owner = ida_funcs.get_func(entry)
            if owner is not None and owner.start_ea != ea:
                assert owner.start_ea == entry and ida_funcs.del_func(entry)
            end = entry
            for _ in range(8):
                decoded = ida_ua.insn_t()
                assert ida_ua.decode_insn(decoded, end) > 0
                end += decoded.size
                if decoded.get_canon_mnem() == "retn":
                    break
            if not ida_funcs.function_contains(ea, entry):
                assert ida_funcs.append_func_tail(function, entry, end), "fixture tail admission"
            ida_auto.auto_wait()
            function = ida_funcs.get_func(ea)
            context = {
                "entry": int(entry),
                "return": int(decoded.ea),
                "return_size": int(decoded.size),
                "continuation": int(ea + call.size + (3 if name == "gp_adjust" else 0)),
                "boundary_delta": (
                    -(8 if ida_ida.inf_is_64bit() else 4) if name.endswith("nonzero") else 0
                ),
            }
            if os.environ.get("CHERNOBOG_MICROCODE_ALTERNATE_ENTRY") == "1":
                source = address("gp_wrongreg" if ida_ida.inf_is_64bit() else "gp32_unknown")
                ida_xref.add_cref(source, entry, ida_xref.fl_JN | ida_xref.XREF_USER)
                ida_auto.plan_and_wait(ea, ea + call.size)
                incoming = list(idautils.CodeRefsTo(entry, True))
                assert source in incoming and source != ea, "alternate entry was not installed"
                context["alternate_source"] = int(source)
        original_function_flags = int(ida_funcs.get_func(ea).flags)
        returning_contract = os.environ.get("CHERNOBOG_MICROCODE_RETURNING_CONTRACT") == "1"
        if returning_contract:
            # An explicit fixture contract, not a claim of automatic noret
            # recovery: these assembler-defined functions return integer 7.
            function = ida_funcs.get_func(ea)
            function.flags &= ~ida_funcs.FUNC_NORET
            assert ida_funcs.update_func(function)
        native = []
        for site in idautils.FuncItems(ea):
            decoded = ida_ua.insn_t()
            if ida_ua.decode_insn(decoded, site) > 0:
                native.append(
                    {
                        "ea": int(site),
                        "itype": int(decoded.itype),
                        "size": int(decoded.size),
                        "sp_delta_before": int(idc.get_spd(site)),
                        "text": idc.generate_disasm_line(site, 0),
                    }
                )
        failure = ida_hexrays.hexrays_failure_t()
        mba = ida_hexrays.gen_microcode(
            ida_hexrays.mba_ranges_t(function),
            failure,
            None,
            ida_hexrays.DECOMP_NO_CACHE | ida_hexrays.DECOMP_ALL_BLKS,
            ida_hexrays.MMAT_GENERATED,
        )
        assert mba is not None, "microcode failed: " + failure.desc()
        blocks = []
        for index in range(mba.qty):
            block = mba.get_mblock(index)
            items = []
            insn = block.head
            while insn is not None:
                items.append(instruction(insn))
                insn = insn.next
            blocks.append(
                {
                    "index": index,
                    "start": int(block.start),
                    "end": int(block.end),
                    "instructions": items,
                }
            )
        ctree = None
        if os.environ.get("CHERNOBOG_MICROCODE_DECOMPILE") == "1":
            cfunc = ida_hexrays.decompile(ea, failure, ida_hexrays.DECOMP_NO_CACHE)
            assert cfunc is not None, "decompilation failed: " + failure.desc()
            ctree = str(cfunc)
            if "return 7;" not in ctree:
                errors.append(name + ": expected returning constant-seven function")
        records.append(
            {
                "name": name,
                "entry_ea": int(ea),
                "context": context,
                "returning_contract": returning_contract,
                "callee_only": callee_only,
                "original_function_flags": original_function_flags,
                "initial_function_flags": initial_function_flags,
                "function_flags": int(ida_funcs.get_func(ea).flags),
                "noret_attribute": bool(ida_nalt.is_noret(ea)),
                "user_type": bool(ida_nalt.is_userti(ea)),
                "type": idc.get_type(ea),
                "native": native,
                "blocks": blocks,
                "ctree": ctree,
            }
        )
except BaseException as error:
    errors.append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "get_pc_microcode.json").write_text(
    json.dumps({"records": records, "errors": errors}, indent=2) + "\n"
)
message = "FAIL " + "; ".join(errors) if errors else "PASS captured_functions=%d" % len(records)
line = "[chernobog][get-pc-microcode] " + message
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
