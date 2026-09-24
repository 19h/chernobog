"""Probe an explicit bounded call-argument byte use in the protected VMP hello."""

import hashlib
import json
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_expr
import ida_funcs
import ida_idaapi
import ida_loader
import ida_pro

ROOT = 0x100001440
SOURCE = 0x10000144D
TARGET = 0x100001456
LITERAL = 0x10000145C
WINDOW = Path(os.environ["CHERNOBOG_VMP_HELLO_WINDOW"])


def api(name, *args):
    result = ida_expr.idc_value_t()
    call = name + "(" + ",".join(str(value) for value in args) + ")"
    if ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, call):
        raise RuntimeError("IDC call failed: " + name)
    return json.loads(result.c_str())


def inventory():
    values = []
    for ea in range(ROOT, ROOT + 40):
        flags = ida_bytes.get_full_flags(ea)
        owner = ida_funcs.get_func(ea)
        values.append(
            [
                int(flags),
                bool(ida_bytes.is_loaded(ea)),
                None if owner is None else hex(owner.start_ea),
            ]
        )
    return hashlib.sha256(json.dumps(values).encode()).hexdigest()


def request(source=SOURCE, target=TARGET, register="rdi", maximum=32):
    return json.dumps(
        {
            "source": hex(source),
            "target": hex(target),
            "register": register,
            "max_bytes": maximum,
        },
        sort_keys=True,
    )


report = {"checks": [], "errors": []}


def check(label, passed):
    report["checks"].append({"case": label, "passed": bool(passed)})
    if not passed:
        report["errors"].append(label)


try:
    window = WINDOW.read_bytes()
    if len(window) != 40 or window[28:] != b"Hello World\0":
        raise RuntimeError("unexpected pinned runtime window")
    if not ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"]):
        raise RuntimeError("plugin load failed")
    ida_auto.auto_wait()
    before = inventory()
    path = json.dumps(str(WINDOW))
    report["baseline"] = api("chernobog_vm_trace_candidate_shadow", ROOT, 0, path)
    report["selected"] = api(
        "chernobog_vm_trace_candidate_shadow_use", ROOT, 0, path, json.dumps(request())
    )
    changed = bytearray(window)
    changed[28] ^= 1
    changed_path = Path(os.environ["IDAUSR"]).parent / "mutated-window.bin"
    changed_path.write_bytes(changed)
    report["mutated_window_sha256"] = hashlib.sha256(changed).hexdigest()
    report["mutated_shadow"] = api(
        "chernobog_vm_trace_candidate_shadow_use",
        ROOT,
        0,
        json.dumps(str(changed_path)),
        json.dumps(request()),
    )
    report["controls"] = {
        "wrong_source": api(
            "chernobog_vm_trace_candidate_shadow_use",
            ROOT,
            0,
            path,
            json.dumps(request(source=SOURCE - 2)),
        ),
        "wrong_target": api(
            "chernobog_vm_trace_candidate_shadow_use",
            ROOT,
            0,
            path,
            json.dumps(request(target=TARGET - 1)),
        ),
        "wrong_register": api(
            "chernobog_vm_trace_candidate_shadow_use",
            ROOT,
            0,
            path,
            json.dumps(request(register="rsi")),
        ),
        "short_bound": api(
            "chernobog_vm_trace_candidate_shadow_use",
            ROOT,
            0,
            path,
            json.dumps(request(maximum=11)),
        ),
        "invalid_register": api(
            "chernobog_vm_trace_candidate_shadow_use",
            ROOT,
            0,
            path,
            json.dumps(request(register="rsp")),
        ),
        "oversized_bound": api(
            "chernobog_vm_trace_candidate_shadow_use",
            ROOT,
            0,
            path,
            json.dumps(request(maximum=257)),
        ),
    }
    after = inventory()
    report["inventory_before"] = before
    report["inventory_after"] = after
    report["window_sha256"] = hashlib.sha256(window).hexdigest()
    selected = report["selected"]
    use = selected.get("shadow_use", {})
    check(
        "selected call and exact image bytes",
        selected["available"]
        and use.get("available")
        and use["source"] == hex(SOURCE)
        and use["target"] == hex(TARGET)
        and use["sequence"] == 7
        and use["register"] == "rdi"
        and use["pointer"] == hex(LITERAL)
        and bytes.fromhex(use["bytes"]) == window[28:]
        and use["payload_bytes"] == 11
        and use["synthetic_state"]
        and not use["callee_semantics_proved"],
    )
    check(
        "underlying native trace unchanged",
        all(
            selected[key] == report["baseline"][key]
            for key in ("heads", "execution", "edges", "states", "data", "frontiers")
        ),
    )
    changed_use = report["mutated_shadow"].get("shadow_use", {})
    check(
        "changed shadow byte changes only the selected use bytes",
        report["mutated_shadow"]["available"]
        and changed_use.get("available")
        and changed_use["pointer"] == use["pointer"]
        and bytes.fromhex(changed_use["bytes"]) == changed[28:]
        and changed_use["bytes"] != use["bytes"],
    )
    check(
        "wrong call, register and incomplete bytes abstain",
        all(
            not value["shadow_use"]["available"]
            for key, value in report["controls"].items()
            if key not in ("invalid_register", "oversized_bound")
        )
        and all(
            not report["controls"][key]["available"]
            for key in ("invalid_register", "oversized_bound")
        ),
    )
    check("IDA inventory unchanged", before == after)
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))

(Path(os.environ["IDAUSR"]).parent / "vmp_hello_use.json").write_text(
    json.dumps(report, indent=2, sort_keys=True) + "\n"
)
print("[chernobog][vmp-hello-use] " + ("FAIL" if report["errors"] else "PASS"), flush=True)
ida_pro.qexit(2 if report["errors"] else 0)
