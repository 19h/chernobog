"""Protected read-stream consensus, exact freshness and linked Qt inspection."""

import importlib.util
import json
import os
from pathlib import Path
import sys
import time

import ida_auto
import ida_bytes
import ida_expr
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_name
import ida_pro
import ida_segment

sys.dont_write_bytecode = True
records, errors = [], []
freshness_elapsed_ns = []
snapshot = {}


def api(name, *args):
    encoded = [json.dumps(arg) if isinstance(arg, str) else str(arg) for arg in args]
    value = ida_expr.idc_value_t()
    assert not ida_expr.eval_idc_expr(
        value, ida_idaapi.BADADDR, name + "(" + ",".join(encoded) + ")"
    )
    assert value.vtype == ida_expr.VT_STR
    return json.loads(value.c_str())


def check(label, condition):
    records.append({"case": label, "passed": bool(condition)})
    if not condition:
        errors.append(label)


try:
    ida_auto.auto_wait()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    snapshot_uses = os.environ.get("CHERNOBOG_SNAPSHOT_USES") == "1"
    target = (
        ida_name.get_name_ea(ida_idaapi.BADADDR, "_native_snapshot_strings")
        if snapshot_uses
        else int(os.environ["CHERNOBOG_STRING_ENTRY"], 0)
    )
    assert target != ida_idaapi.BADADDR
    bindings = []
    for name in ("_malloc", "_memset", "_free") + (("_strlen",) if snapshot_uses else ()):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
        assert ea != ida_idaapi.BADADDR
        bindings.append({"address": hex(ea), "name": name})
    request, models = json.dumps({"args": [], "objects": []}), json.dumps(bindings)
    before = api("chernobog_evidence_view", target)
    snapshot = api("chernobog_vm_temporal_strings", target, request, models)
    check(
        "separate native inspection",
        snapshot.get("available")
        and snapshot["scope"] == "native-region-strings"
        and not snapshot["function_evidence_published"]
        and not snapshot["vm_identity_proved"],
    )
    check(
        "four retained capture identities",
        len(snapshot["runs"]) == 4 and len({row["capture"] for row in snapshot["runs"]}) == 4,
    )
    expected = os.environ["CHERNOBOG_EXPECT_RETURN"] == "1"
    check("all-run admission", snapshot["consensus_available"] == expected)
    if expected:
        check(
            "both protected values",
            sorted(row["value"] for row in snapshot["observations"])
            == sorted(["second!", "secret!"] * (2 if snapshot_uses else 1)),
        )
        check(
            "complete witness table",
            len(snapshot["witnesses"]) == (16 if snapshot_uses else 8)
            and len(snapshot["fragments"]) == (16 if snapshot_uses else 64)
            and snapshot["observations_omitted"] == 0,
        )
        if snapshot_uses:
            check(
                "distinct snapshot producers",
                sorted(row["producer"] for row in snapshot["observations"])
                == ["executed-read", "executed-read", "modeled-argument", "modeled-argument"],
            )
        for observation in snapshot["observations"]:
            witnesses = [
                row for row in snapshot["witnesses"] if row["observation"] == observation["index"]
            ]
            check(
                "consensus preserves all scheduled runs",
                len(witnesses) == 4
                and observation["eligible_runs"] == "4"
                and {row["capture"] for row in witnesses}
                == {row["capture"] for row in snapshot["runs"]},
            )
            for witness in witnesses:
                fragments = [
                    row
                    for row in snapshot["fragments"]
                    if row["observation"] == observation["index"]
                    and row["capture"] == witness["capture"]
                ]
                raw = b"".join(bytes.fromhex(row["bytes"]) for row in fragments)
                modeled = observation["producer"] == "modeled-argument"
                fragment_count = 1 if snapshot_uses else 8
                check(
                    "exact original reads",
                    raw == observation["value"].encode() + b"\0"
                    and len(fragments) == int(witness["snapshot_count"]) == fragment_count
                    and int(witness["read_count"]) == (0 if modeled else fragment_count)
                    and witness["fragments_omitted"] == "0"
                    and all(
                        (
                            row["data_sequence"] == ""
                            if modeled
                            else int(row["data_sequence"]) == int(row["sequence"]) + 1
                        )
                        and row["producer"] == ("modeled-argument" if modeled else "executed-read")
                        for row in fragments
                    )
                    and (
                        not modeled or (witness["argument"] == "0" and witness["model_kind"] == "6")
                    ),
                )
    else:
        check(
            "partial executions cannot publish strings",
            not snapshot["observations"]
            and not snapshot["witnesses"]
            and not snapshot["fragments"]
            and all(row["complete"] == "false" for row in snapshot["runs"]),
        )
    ticket = snapshot["ticket"]

    def fresh():
        started = time.perf_counter_ns()
        value = api("chernobog_vm_temporal_string_state", ticket).get("fresh", False)
        freshness_elapsed_ns.append(time.perf_counter_ns() - started)
        return value

    check("fresh exact snapshot", fresh())
    key = ida_name.get_name_ea(
        ida_idaapi.BADADDR, "_native_snapshot_key" if snapshot_uses else "_native_read_key"
    )
    assert key != ida_idaapi.BADADDR
    original = ida_bytes.get_byte(key)
    ida_bytes.patch_byte(key, original ^ 1)
    check("data edit invalidates", not fresh())
    ida_bytes.patch_byte(key, original)
    check("exact data restoration revalidates", fresh())
    old_name = ida_name.get_name(target)
    assert ida_name.set_name(target, "_region_string_profile_changed")
    check("profile edit invalidates", not fresh())
    assert ida_name.set_name(target, old_name)
    check("exact profile restoration revalidates", fresh())
    callee = int(bindings[0]["address"], 0)
    assert ida_name.set_name(callee, "_region_string_model_changed")
    check("model name edit invalidates", not fresh())
    assert ida_name.set_name(callee, bindings[0]["name"])
    check("exact model restoration revalidates", fresh())
    segment = ida_segment.getseg(target)
    old_permission = segment.perm
    segment.perm = old_permission ^ ida_segment.SEGPERM_WRITE
    assert ida_segment.update_segm(segment)
    check("permission edit invalidates", not fresh())
    segment.perm = old_permission
    assert ida_segment.update_segm(segment)
    check("exact permission restoration revalidates", fresh())
    form = None
    if os.environ.get("CHERNOBOG_VIEW_MODULE") and expected:
        spec = importlib.util.spec_from_file_location(
            "region_string_view", os.environ["CHERNOBOG_VIEW_MODULE"]
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        witness = snapshot["witnesses"][0]
        selected, fragments = module.select_rows(
            snapshot, witness["observation"], witness["capture"]
        )
        check(
            "capture selection isolates witnesses",
            len(selected) == 4 and len(fragments) == (1 if snapshot_uses else 8),
        )
        if ida_kernwin.is_idaq():
            from PySide6 import QtWidgets

            form = module.TemporalStringForm(snapshot)
            form.Show("Protected region strings", options=ida_kernwin.PluginForm.WOPN_PERSIST)
            QtWidgets.QApplication.processEvents()
            selection = next(
                (
                    i
                    for i, row in enumerate(snapshot["observations"])
                    if row["producer"] == "modeled-argument"
                ),
                0,
            )
            form.tables["observations"].setCurrentItem(
                form.tables["observations"].topLevelItem(selection)
            )
            form.tables["witnesses"].setCurrentItem(form.tables["witnesses"].topLevelItem(0))
            form.tables["fragments"].setCurrentItem(form.tables["fragments"].topLevelItem(0))
            check(
                "Qt linked read witnesses",
                form.tables["observations"].topLevelItemCount() == (4 if snapshot_uses else 2)
                and form.tables["witnesses"].topLevelItemCount() == 4
                and form.tables["fragments"].topLevelItemCount() == (1 if snapshot_uses else 8)
                and form.jump.isEnabled(),
            )
            if snapshot_uses:
                check(
                    "Qt modeled snapshot has no invented read event",
                    form.tables["fragments"].topLevelItem(0).text(0).endswith(" / modeled")
                    and form.tables["fragments"].topLevelItem(0).text(4) == "modeled-argument"
                    and form.witness["read_count"] == "0",
                )
            ida_bytes.patch_byte(key, original ^ 1)
            form.poll()
            check(
                "Qt changed input disables navigation",
                not form.current and not form.jump.isEnabled(),
            )
            ida_bytes.patch_byte(key, original)
            form.poll()
            check("Qt exact restoration revalidates", form.current and form.jump.isEnabled())
            form.parent.window().resize(1350, 1000)
            QtWidgets.QApplication.processEvents()
            form.parent.grab().save(str(Path(os.environ["IDAUSR"]).parent / "region_strings.png"))
    replacement = api("chernobog_vm_temporal_strings", target, request, models)
    check(
        "replacement supersedes only old lease",
        not fresh()
        and replacement["ticket"] != ticket
        and api("chernobog_vm_temporal_string_state", replacement["ticket"])["fresh"],
    )
    if form:
        form.poll()
        check(
            "Qt superseded capture disables navigation",
            not form.current and not form.jump.isEnabled(),
        )
        form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
        QtWidgets.QApplication.processEvents()
        check("Qt close stops polling", form.closed and not form.timer.isActive())
    check("ordinary publication unchanged", api("chernobog_evidence_view", target) == before)
except BaseException as error:
    errors.append(type(error).__name__)

(Path(os.environ["IDAUSR"]).parent / "region_strings.json").write_text(
    json.dumps(
        {
            "records": records,
            "errors": errors,
            "snapshot": snapshot,
            "freshness_elapsed_ns": freshness_elapsed_ns,
        },
        indent=2,
    )
    + "\n"
)
line = "[chernobog][region-strings] " + ("FAIL" if errors else "PASS")
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
