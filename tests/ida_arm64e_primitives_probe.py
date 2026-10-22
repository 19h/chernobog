"""Check ARM64e intrinsics, pointer-origin proofs and native identity contracts."""

import ctypes
import json
import os
from pathlib import Path
import traceback

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_idp
import ida_lines
import ida_loader
import ida_name
import ida_pro
import ida_ua
import idautils
import idc

report = {"passed": False, "checks": [], "errors": [], "flows": [], "values": []}


def check(name, passed):
    report["checks"].append({"name": name, "passed": bool(passed)})
    if not passed:
        report["errors"].append(name)


def microcode(ea, maturity=ida_hexrays.MMAT_GLBOPT3):
    failure = ida_hexrays.hexrays_failure_t()
    mba = ida_hexrays.gen_microcode(
        ida_hexrays.mba_ranges_t(ida_funcs.get_func(ea)),
        failure,
        None,
        ida_hexrays.DECOMP_NO_CACHE,
        maturity,
    )
    if mba is None:
        raise RuntimeError(f"{failure.desc()} at {failure.errea:X}")
    return mba


class Instructions(ida_hexrays.minsn_visitor_t):
    def __init__(self):
        super().__init__()
        self.calls = []
        self.jumps = []

    def visit_minsn(self):
        ins = self.curins
        if ins.opcode in (ida_hexrays.m_call, ida_hexrays.m_icall):
            self.calls.append(
                {
                    "ea": ins.ea,
                    "opcode": ins.opcode,
                    "target": ins.l.g if ins.l.t == ida_hexrays.mop_v else None,
                    "helper": ins.l.helper if ins.l.t == ida_hexrays.mop_h else None,
                    "barrier": ins.is_mbarrier(),
                    "args": [a.size for a in ins.d.f.args] if ins.d.t == ida_hexrays.mop_f else [],
                }
            )
        if ins.opcode == ida_hexrays.m_ijmp:
            self.jumps.append(
                {"ea": ins.ea, "target": ins.d.g if ins.d.t == ida_hexrays.mop_v else None}
            )
        return 0


def instructions(mba):
    visitor = Instructions()
    mba.for_all_insns(visitor)
    return visitor


def native_instructions(ea):
    function = ida_funcs.get_func(ea)
    result = []
    for address in idautils.Heads(ea, function.end_ea):
        ins = ida_ua.insn_t()
        if ida_ua.decode_insn(ins, address):
            result.append((address, ins, idc.print_insn_mnem(address).lower()))
    return result


try:
    ida_auto.auto_wait()
    assert ida_hexrays.init_hexrays_plugin()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    bridge = ctypes.CDLL(os.environ["CHERNOBOG_ARM64E_SDK_BRIDGE"])
    bridge.chernobog_arm64e_identity.argtypes = [ctypes.c_uint64]
    bridge.chernobog_arm64e_identity.restype = ctypes.c_int
    for name in ("argument", "return"):
        function = getattr(bridge, f"chernobog_arm64e_{name}_register")
        function.restype = ctypes.c_int
        check(f"native {name} register is IDA X0", function() == ida_idp.str2reg("X0"))

    identities = {
        "plain": True,
        "mov64": True,
        "mov32": False,
        "bti_c": True,
        "bti_jc": True,
        "bti_j": False,
        "ia": True,
        "ib": True,
        "ia_explicit": True,
        "ib_explicit": True,
        "bti_ib": True,
        "wrong_key": False,
        "missing_auth": False,
        "unpaired_auth": False,
        "wrong_modifier": False,
        "other_return": False,
        "changed_result": False,
    }
    negative_flows = {
        "wrong_key",
        "wrong_modifier",
        "wrong_domain",
        "wrong_strip",
        "aut_wrong_key",
        "aut_wrong_modifier",
        "signed_plain",
        "call_barrier",
        "pacga_target",
        "nonpointer_roundtrip",
    }
    normalize = {
        "paciza": "pacia",
        "pacizb": "pacib",
        "pacdza": "pacda",
        "pacdzb": "pacdb",
        "autiza": "autia",
        "autizb": "autib",
        "autdza": "autda",
        "autdzb": "autdb",
        "pacia1716": "pacia",
        "pacib1716": "pacib",
        "ldraa": "load64",
        "ldrab": "load64",
        "ldraa_writeback": "load64",
        "ldrab_writeback": "load64",
        "load_discard": "load64",
    }
    names = {name: ea for ea, name in idautils.Names()}
    target = names["_flow_target"]
    assert idc.SetType(target, "unsigned long long __fastcall target(unsigned long long value);")
    assert idc.SetType(names["_barrier"], "void barrier(void);")
    for name, ea in names.items():
        if not name.startswith(("_value_", "_flow_", "_identity_")) or name == "_flow_target":
            continue
        if ida_funcs.get_func(ea) is None:
            assert ida_funcs.add_func(ea)
        owner = ida_funcs.get_func(ea)
        original = ida_bytes.get_bytes(ea, owner.end_ea - ea)
        end = owner.end_ea
        if name.startswith("_identity_"):
            suffix = name.removeprefix("_identity_")
            check(
                name + " identity", bool(bridge.chernobog_arm64e_identity(ea)) == identities[suffix]
            )
            continue
        # Most cases have a fixed public ABI; PACGA additionally exercises
        # automatic return-value inference in a fresh database.
        if name != "_value_pacga":
            assert idc.SetType(
                ea,
                f"unsigned long long __fastcall {name}(unsigned long long a, unsigned long long b, unsigned long long c);",
            )
        mba = microcode(ea)
        visitor = instructions(mba)
        if name.startswith("_value_"):
            suffix = name.removeprefix("_value_")
            expected = "__arm64e_" + normalize.get(suffix, suffix)
            calls = [call for call in visitor.calls if call["helper"] == expected]
            check(name + " explicit intrinsic", bool(calls) and all(c["barrier"] for c in calls))
            check(
                name + " typed operands", all(all(size == 8 for size in c["args"]) for c in calls)
            )
            cfunc = ida_hexrays.decompile(ea, flags=ida_hexrays.DECOMP_NO_CACHE)
            assert cfunc is not None
            pseudocode = "\n".join(
                ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()
            )
            check(name + " pseudocode retains intrinsic", expected in pseudocode)
            if suffix == "pacga":
                check(
                    "PACGA return inferred without a prototype",
                    "return __arm64e_pacga(" in pseudocode,
                )
            report["values"].append(
                {
                    "name": name,
                    "helpers": [c["helper"] for c in visitor.calls],
                    "pseudocode": pseudocode,
                }
            )
            if suffix in ("ldraa_writeback", "ldrab_writeback"):
                raw = microcode(ea, ida_hexrays.MMAT_GENERATED)
                load_site = native_instructions(ea)[0][0]
                emitted = []
                for index in range(raw.qty):
                    ins = raw.get_mblock(index).head
                    while ins:
                        if ins.ea == load_site:
                            emitted.append(ins)
                        ins = ins.next
                memory_index = next(
                    (
                        i
                        for i, ins in enumerate(emitted)
                        if ins.find_call(True)
                        and ins.find_call(True).l.t == ida_hexrays.mop_h
                        and ins.find_call(True).l.helper == "__arm64e_load64"
                    ),
                    -1,
                )
                base = ida_hexrays.reg2mreg(ida_idp.str2reg("X1"))
                writeback = next(
                    (
                        i
                        for i, ins in enumerate(emitted)
                        if ins.d.t == ida_hexrays.mop_r and ins.d.r == base
                    ),
                    -1,
                )
                check(
                    name + " writeback follows read", memory_index >= 0 and writeback > memory_index
                )
        else:
            suffix = name.removeprefix("_flow_")
            native = native_instructions(ea)
            transfer = next(
                address
                for address, _, mnemonic in reversed(native)
                if mnemonic
                in {"braa", "brab", "braaz", "brabz", "blraa", "blrab", "blraaz", "blrabz", "blr"}
            )
            resolved = any(
                c["ea"] == transfer and c["target"] == target and c["opcode"] == ida_hexrays.m_call
                for c in visitor.calls
            ) or any(j["ea"] == transfer and j["target"] == target for j in visitor.jumps)
            expected = suffix not in negative_flows
            check(name + " target provenance", resolved == expected)
            retained = [
                c for c in visitor.calls if c["helper"] and c["helper"].startswith("__arm64e_")
            ]
            check(
                name + " authentication effects retained",
                bool(retained) and all(c["barrier"] for c in retained),
            )
            cfunc = ida_hexrays.decompile(ea, flags=ida_hexrays.DECOMP_NO_CACHE)
            assert cfunc is not None
            pseudocode = "\n".join(
                ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()
            )
            check(name + " pseudocode retains authentication", "__arm64e_" in pseudocode)
            mnemonic = next(m for address, _, m in native if address == transfer)
            if mnemonic in {"braa", "brab", "braaz", "brabz", "blraa", "blrab", "blraaz", "blrabz"}:
                guard = "__arm64e_auth_branch_" + ("ib" if "ab" in mnemonic else "ia")
                check(
                    name + " combined branch guard retained",
                    any(c["helper"] == guard and c["barrier"] for c in retained)
                    and guard in pseudocode,
                )
            report["flows"].append(
                {
                    "name": name,
                    "expected_resolved": expected,
                    "resolved": resolved,
                    "calls": visitor.calls,
                    "jumps": visitor.jumps,
                }
            )
        check(name + " native bytes unchanged", ida_bytes.get_bytes(ea, end - ea) == original)
        check(
            name + " ownership unchanged",
            ida_funcs.get_func(ea).start_ea == ea and ida_funcs.get_func(ea).end_ea == end,
        )
    report["passed"] = not report["errors"]
except Exception as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))
    report["frames"] = [
        {"function": f.name, "line": f.lineno} for f in traceback.extract_tb(error.__traceback__)
    ]

(Path(os.environ["IDAUSR"]).parent / "arm64e_primitives.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print("[chernobog][arm64e-primitives] " + ("PASS" if report["passed"] else "FAIL"), flush=True)
ida_pro.qexit(0 if report["passed"] else 2)
