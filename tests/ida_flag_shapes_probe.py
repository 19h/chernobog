"""Capture real SDK predicate value trees and proof admission counters."""

import json
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_hexrays as hx
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_loader
import ida_name
import ida_pro

NAMES = (
    "flags8",
    "flags16",
    "flags32",
    "flags64",
    "flag_parity_zero32",
    "flag_parity_one32",
    "flag_parity_compare32",
    "flag_overflow_zero8",
    "flag_overflow_one8",
)
opcodes = {
    getattr(hx, name): name
    for name in dir(hx)
    if name.startswith("m_") and isinstance(getattr(hx, name), int)
}


def evaluate(expression):
    result = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, expression)
    if result.vtype == ida_expr.VT_STR:
        return result.c_str()
    return result.i64 if result.vtype == ida_expr.VT_INT64 else result.num


def statistics():
    return {
        field: int(evaluate("chernobog_rule_stats()." + field))
        for field in (
            "total_matches",
            "successful_matches",
            "instance_verified",
            "instance_disproved",
            "instance_unsupported",
            "instance_unknown",
        )
    }


def operand(value):
    result = {
        "kind": int(value.t),
        "bytes": int(value.size),
        "properties": int(value.oprops),
        "value_number": int(value.valnum),
    }
    result["kind_name"] = next(
        (
            name
            for name in ("mop_z", "mop_r", "mop_n", "mop_d", "mop_S", "mop_v")
            if getattr(hx, name) == value.t
        ),
        "unsupported",
    )
    if value.t == hx.mop_d:
        result["instruction"] = instruction(value.d)
    elif value.t == hx.mop_n:
        result["value"] = int(value.nnn.value)
    elif value.t == hx.mop_r:
        result["register"] = int(value.r)
    elif value.t == hx.mop_S:
        result["offset"] = int(value.s.off)
    elif value.t == hx.mop_v:
        result["address"] = int(value.g)
    return result


def instruction(value):
    return {
        "opcode": opcodes.get(value.opcode, str(value.opcode)),
        "ea": int(value.ea),
        "properties": int(value.iprops),
        "left": operand(value.l),
        "right": operand(value.r),
        "destination": operand(value.d),
    }


records, errors, abi = [], [], {}
try:
    ida_auto.auto_wait()
    assert hx.init_hexrays_plugin(), "decompiler unavailable"
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"]), "plugin unavailable"
    abi = {
        name: int(hx.reg2mreg(ida_idp.str2reg(name)))
        for name in ("rax", "rdi", "rsi", "rdx", "rsp", "ds")
    }
    for name in NAMES:
        evaluate("chernobog_rule_reset_stats()")
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "_" + name)
        function = ida_funcs.get_func(ea)
        assert function is not None and function.start_ea == ea, "fixture owner missing"
        original = ida_bytes.get_bytes(ea, function.end_ea - ea)
        captures = []
        for maturity in (hx.MMAT_GENERATED, hx.MMAT_PREOPTIMIZED, hx.MMAT_LOCOPT, hx.MMAT_GLBOPT1):
            failure = hx.hexrays_failure_t()
            mba = hx.gen_microcode(
                hx.mba_ranges_t(function),
                failure,
                None,
                hx.DECOMP_NO_CACHE | hx.DECOMP_ALL_BLKS,
                maturity,
            )
            assert mba is not None, "microcode generation failed"
            blocks = []
            for index in range(mba.qty):
                block = mba.get_mblock(index)
                insns = []
                insn = block.head
                while insn is not None:
                    insns.append(instruction(insn))
                    insn = insn.next
                blocks.append({"index": index, "instructions": insns})
            captures.append(
                {"maturity": int(maturity), "blocks": blocks, "statistics": statistics()}
            )
        cfunc = hx.decompile(ea, None, hx.DECOMP_NO_CACHE)
        assert cfunc is not None, "decompilation failed"
        assert ida_bytes.get_bytes(ea, len(original)) == original, "native bytes changed"
        records.append(
            {
                "name": name,
                "entry": int(ea),
                "native_bytes_unchanged": True,
                "captures": captures,
                "ctree": str(cfunc),
                "statistics": statistics(),
            }
        )
except BaseException as error:
    errors.append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "flag_shapes.json").write_text(
    json.dumps({"abi": abi, "records": records, "errors": errors}, indent=2) + "\n"
)
line = "[chernobog][flag-shapes] " + ("FAIL" if errors else "PASS")
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
