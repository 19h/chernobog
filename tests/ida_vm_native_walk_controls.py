"""Near/far transfer controls in a disposable IDA database; bytes restored."""

import json
import os
from pathlib import Path
import struct
import traceback

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_idaapi
import ida_loader
import ida_pro
import ida_segment
import idautils

checks, errors, captures = [], [], {}


def check(name, value):
    checks.append({"case": name, "passed": bool(value)})
    if not value:
        errors.append(name)


def api(ea, supplied=None, semantic=False):
    value = ida_expr.idc_value_t()
    request = json.dumps(
        json.dumps(supplied if supplied is not None else {"args": [], "objects": []})
    )
    function = "chernobog_vm_trace_check" if semantic else "chernobog_vm_trace_walk"
    assert not ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, f"{function}({ea}, 0, {request})")
    return json.loads(value.c_str())


original = None
try:
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    ida_auto.enable_auto(False)
    ea = int(json.loads(os.environ["CHERNOBOG_CORPUS_ENTRIES"])["corpus_transform"], 0)
    owner = ida_funcs.get_func(ea)
    assert owner and owner.start_ea == ea
    topology = (int(owner.flags), list(idautils.Chunks(ea)))
    mode = 64 if ida_segment.getseg(ea).bitness == 2 else 32
    original = ida_bytes.get_bytes(ea, 48)
    assert original and len(original) == 48

    def patch(data):
        ida_bytes.patch_bytes(ea, data + original[len(data) :])
        assert ida_bytes.get_bytes(ea, len(data)) == data

    for extra, code in ((0, b"\xc3"), (8, b"\xc2\x08\x00")):
        patch(code)
        trace = api(ea)
        name = "near_return_" + str(extra)
        captures[name] = trace
        check(
            name,
            trace["available"]
            and trace["ran"]
            and trace["reached_sentinel"]
            and trace["sp_valid"]
            and trace["sp_delta"] == mode // 8 + extra
            and len(trace["execution"]) == 1
            and not trace["native_admissions"],
        )
    far = {
        "far_return": b"\xcb",
        "far_return_adjusted": b"\xca\x08\x00",
        "interrupt_return": b"\xcf",
        "indirect_far_call": b"\xff\x18",
        "indirect_far_jump": b"\xff\x28",
        "immediate_far_call": b"\x9a\x00\x00\x00\x00\x00\x00",
        "immediate_far_jump": b"\xea\x00\x00\x00\x00\x00\x00",
    }
    for name, code in far.items():
        patch(code)
        trace = api(ea)
        captures[name] = trace
        check(
            name + " rejected before entry",
            not trace["available"]
            and trace["reason"] == "entry has no admissible native instruction",
        )
    prefix = (
        b"\x48\xb8" + struct.pack("<Q", ea + 32)
        if mode == 64
        else b"\xb8" + struct.pack("<I", ea + 32)
    ) + b"\xff\xe0"
    patch(prefix + b"\xcc" * (32 - len(prefix)) + b"\xcb")
    trace = api(ea)
    captures["observed_far_return_destination"] = trace
    check(
        "far destination remains rejected after observed transfer",
        trace["available"]
        and trace["ran"]
        and trace["region_boundary"]
        and not trace["reached_sentinel"]
        and len(trace["execution"]) == 2
        and len(trace["native_admissions"]) == 1
        and trace["native_admissions"][0]["admitted"] == "false"
        and trace["native_admissions"][0]["reason"] == "invalid_decode",
    )
    # Independently authored byte dispatch. The i386 setup loads its explicit
    # pointer argument before a fallthrough-only candidate entry; x64 enters the
    # candidate at the function root. The optional direct jump splits its path.
    for split in (False, True):
        setup = b"" if mode == 64 else b"\x8b\x74\x24\x04"
        load = b"\x0f\xb6\x06"  # movzx eax, byte ptr [r/e]si
        advance = b"\x48\x83\xc6\x01" if mode == 64 else b"\x83\xc6\x01"
        dispatch = b"\xff\x24\xc7" if mode == 64 else b"\xff\x24\x85" + struct.pack("<I", ea + 36)
        data = bytearray(original)
        beginning = setup + load
        if split:
            beginning += b"\xe9" + struct.pack("<i", 20 - (len(beginning) + 5))
            data[: len(beginning)] = beginning
            data[20 : 20 + len(advance + dispatch)] = advance + dispatch
        else:
            beginning += advance + dispatch
            data[: len(beginning)] = beginning
        data[32] = 0xC3
        if mode == 64:
            supplied = {
                "args": ["0x0", "0x0"],
                "objects": [
                    {"argument": 0, "offset": 0, "bytes": (struct.pack("<Q", ea + 32) * 3).hex()},
                    {"argument": 1, "offset": 0, "bytes": "02"},
                ],
            }
        else:
            data[36:48] = struct.pack("<I", ea + 32) * 3
            supplied = {"args": ["0x0"], "objects": [{"argument": 0, "offset": 0, "bytes": "02"}]}
        patch(bytes(data))
        trace = api(ea, supplied, semantic=True)
        name = "sampled_dispatch_split_" + str(int(split))
        captures[name] = trace
        check(
            name + " actual execution",
            trace["available"]
            and trace["ran"]
            and trace["reached_sentinel"]
            and trace["native_state_capture_complete"],
        )
        view = trace["native_observations"]
        check(
            name + " exact local transition",
            view["available"]
            and len(view["records"]) == 1
            and view["transition_attempts"] == 1
            and view["queries"] == 2
            and view["records"][0]["semantic_validation"] == "corroborated for captured transition"
            and int(view["records"][0]["site"], 0) == ea + len(setup),
        )
        check(
            name + " explicit incomplete VM identity",
            view["records"][0]["logical_state_complete"] == "false"
            and view["records"][0]["virtual_stack"] == "unknown"
            and not trace["function_evidence_published"],
        )
except Exception as error:
    errors.append(type(error).__name__)
    errors.extend(f.name + ":" + str(f.lineno) for f in traceback.extract_tb(error.__traceback__))
finally:
    if original is not None:
        ida_bytes.patch_bytes(ea, original)
        check("original bytes restored", ida_bytes.get_bytes(ea, 48) == original)
        check(
            "original function topology retained",
            (int(ida_funcs.get_func(ea).flags), list(idautils.Chunks(ea))) == topology,
        )

report = {"passed": not errors, "checks": checks, "errors": errors, "captures": captures}
(Path(os.environ["IDAUSR"]).parent / "vm_native_walk_controls.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print("[chernobog][vm-native-walk-controls] " + ("FAIL" if errors else "PASS"), flush=True)
ida_pro.qexit(2 if errors else 0)
