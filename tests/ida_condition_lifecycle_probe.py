"""Capture current condition generation across persistent IDA state transitions."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import traceback

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays as hx
import ida_loader
import ida_pro
import ida_segment
import ida_undo


def load(name, variable):
    spec = importlib.util.spec_from_file_location(name, os.environ[variable])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


contract = load("condition_contract", "CHERNOBOG_CONDITION_CONTRACT")
stage = os.environ["CHERNOBOG_CONDITION_STAGE"]
directory = Path(os.environ["IDAUSR"]).parent
note = "analyst condition lifecycle witness"
patched_names = tuple(
    "rc_" + case + "_" + family for case in ("be_true", "a_false") for family in contract.families
)
report = {"stage": stage, "snapshots": {}, "errors": [], "checks": contract.report["checks"]}


def check(name, condition):
    contract.check(stage + " " + name, condition)
    assert condition, name


def settle():
    for name in contract.positive:
        root = contract.symbol(name)
        ida_auto.plan_range(root, contract.ends[name])
    ida_auto.auto_wait()


def capture(label, patched=False):
    result = {
        key: copy.deepcopy(contract.report[key]) for key in ("word_bytes", "registers", "opcodes")
    }
    result.update({"owned": {}, "microcode": {}, "patched": patched})
    for name in sorted(contract.controls, key=contract.symbol):
        contract.inspect_owner(name)
        before = contract.inventory(contract.sites[name])
        view = contract.api("chernobog_native_evidence", contract.symbol(name))
        result["owned"][name] = view
        invalid = patched and name in patched_names
        if invalid:
            check(label + " " + name + " unresolved", not contract.exact(view, name, True))
        else:
            contract.verify(name, view, True)
        check(
            label + " " + name + " query read-only",
            before == contract.inventory(contract.sites[name]),
        )
        if name in contract.positive:
            text = ida_bytes.get_cmt(contract.consumers[name], True) or ""
            check(label + " " + name + " user annotation", text.splitlines().count(note) == 1)
        if "_branch" not in name:
            result["microcode"][name + ("_patched" if invalid else "")] = contract.microcode(
                name, valid=not invalid
            )
    report["snapshots"][label] = result
    return result


def source_bytes():
    return {
        name: ida_bytes.get_bytes(
            contract.symbol(name), contract.ends[name] - contract.symbol(name)
        ).hex()
        for name in contract.controls
    }


def save():
    # Keep the checkpoint distinct from the opened database. IDA shutdown may
    # save the active database after plugin unload revokes its live artifacts.
    name = (
        "condition_rebased.i64"
        if stage in ("rebase", "rebase_nodes")
        else "condition_lifecycle.i64"
    )
    check("checkpoint saved", ida_loader.save_database(str(directory / name), 0))


def flag_sites():
    result = {}
    for name in patched_names:
        candidates = [
            site for site in contract.sites[name] if ida_bytes.get_bytes(site, 2) == b"\x6a\x03"
        ]
        assert len(candidates) == 1
        result[name] = candidates[0] + 1
    return result


def undo_controls():
    original = report["snapshots"]["loaded"]
    flags = flag_sites()
    instruction_bytes = {
        name: ida_bytes.get_bytes(
            contract.consumers[name], ida_bytes.get_item_size(contract.consumers[name])
        )
        for name in patched_names
    }
    check(
        "undo checkpoint",
        ida_undo.create_undo_point("condition-lifecycle", "eight predicate inputs"),
    )
    for name, site in flags.items():
        ida_bytes.patch_byte(site, 2)
        current = contract.api("chernobog_native_evidence", contract.symbol(name))
        check(name + " immediate revocation", not contract.exact(current, name, True))
        check(
            name + " stale UI result rejected",
            not contract.module.current_native_publications(original["owned"][name], current),
        )
        check(
            name + " note survives revocation",
            ida_bytes.get_cmt(contract.consumers[name], True) == note,
        )
    settle()
    capture("patched", True)
    check("undo succeeds", ida_undo.perform_undo())
    settle()
    check("undo restores inputs", all(ida_bytes.get_byte(site) == 3 for site in flags.values()))
    capture("undone")
    check("redo succeeds", ida_undo.perform_redo())
    settle()
    check(
        "redo restores disagreement", all(ida_bytes.get_byte(site) == 2 for site in flags.values())
    )
    capture("redone", True)
    for site in flags.values():
        ida_bytes.patch_byte(site, 3)
    settle()
    capture("restored")
    for name, data in instruction_bytes.items():
        site = contract.consumers[name]
        check(name + " consumer bytes retained", ida_bytes.get_bytes(site, len(data)) == data)


try:
    assert stage in ("write", "read", "rebase", "rebase_nodes", "read_rebased", "undo")
    ida_auto.auto_wait()
    assert hx.init_hexrays_plugin()
    contract.module = load("condition_view", "CHERNOBOG_VIEW_MODULE")
    ordered = contract.initialize_contract()
    if stage == "write":
        for name in ordered:
            contract.restore_owner(name)
        for name in contract.positive:
            site = contract.consumers[name]
            text = ida_bytes.get_cmt(site, True) or ""
            assert note not in text.splitlines()
            ida_bytes.set_cmt(site, text + "\n" + note, True)
    else:
        check(
            "receipt recovery occurred",
            "native ownership receipts;" in (directory / "ida.log").read_text(errors="replace"),
        )
    initial = source_bytes()
    report["initial_roots"] = {name: hex(contract.symbol(name)) for name in contract.controls}
    capture("loaded")
    if stage in ("rebase", "rebase_nodes"):
        roots = {name: contract.symbol(name) for name in contract.controls}
        flags = ida_segment.MSF_FIXONCE
        if stage == "rebase_nodes":
            flags |= ida_segment.MSF_NETNODES
        check("rebase succeeds", ida_segment.rebase_program(0x100000, flags) == 0)
        contract.initialize_contract()
        settle()
        check(
            "every root relocates",
            all(contract.symbol(name) == root + 0x100000 for name, root in roots.items()),
        )
        changed = capture("rebased")
        for name in contract.positive:
            check(
                name + " old UI result rejected after rebase",
                not contract.module.current_native_publications(
                    report["snapshots"]["loaded"]["owned"][name], changed["owned"][name]
                ),
            )
        save()
    elif stage == "undo":
        undo_controls()
    elif stage == "write":
        save()
    # Rebasing can legitimately update i386 absolute-address fixups.
    if stage not in ("rebase", "rebase_nodes"):
        check("fixture instruction bytes preserved", source_bytes() == initial)
    report["errors"] = contract.report["errors"]
except BaseException as error:
    report["errors"] = contract.report["errors"] + [type(error).__name__ + ": " + str(error)]
    report["exception"] = [
        {"function": frame.name, "line": frame.lineno}
        for frame in traceback.extract_tb(error.__traceback__)
    ]
(directory / "condition_lifecycle.json").write_text(json.dumps(report, indent=2) + "\n")
print("[chernobog][condition-lifecycle] " + ("FAIL" if report["errors"] else "PASS"), flush=True)
ida_pro.qexit(2 if report["errors"] else 0)
