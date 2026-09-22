"""Reopen a database and challenge native-string capture identity and freshness."""

import importlib.util
import json
import os
import re
from pathlib import Path
import sys

import ida_auto
import ida_bytes
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_name
import ida_pro
import ida_segment

sys.dont_write_bytecode = True
records, errors = [], []
snapshot = {}
root = Path(os.environ["IDAUSR"]).parent


def check(label, condition):
    records.append({"case": label, "passed": bool(condition)})
    if not condition:
        errors.append(label)


try:
    ida_auto.auto_wait()
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    spec = importlib.util.spec_from_file_location(
        "native_string_view", os.environ["CHERNOBOG_VIEW_MODULE"]
    )
    view = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(view)

    def state(capture):
        arguments = [capture["ticket"]]
        if "lease" in capture:
            arguments.append(capture["lease"])
        return view.api("chernobog_vm_temporal_string_state", *arguments)

    def capture():
        target = ida_name.get_name_ea(ida_idaapi.BADADDR, "_native_snapshot_strings")
        assert target != ida_idaapi.BADADDR
        bindings = [
            {"address": hex(ida_name.get_name_ea(ida_idaapi.BADADDR, name)), "name": name}
            for name in ("_malloc", "_memset", "_free", "_strlen")
        ]
        return view.api(
            "chernobog_vm_temporal_strings",
            target,
            json.dumps({"args": [], "objects": []}),
            json.dumps(bindings),
        )

    old = None
    if os.environ.get("CHERNOBOG_PRIOR_CAPTURE"):
        old = json.loads(Path(os.environ["CHERNOBOG_PRIOR_CAPTURE"]).read_text())["snapshot"]
        check("reopened database has no retained capture", not state(old).get("fresh", False))
        key = ida_name.get_name_ea(ida_idaapi.BADADDR, "_native_snapshot_key")
        assert key != ida_idaapi.BADADDR
        assert ida_bytes.patch_byte(key, ida_bytes.get_byte(key) ^ 1)
    snapshot = capture()
    check(
        "complete four-run snapshot",
        snapshot.get("consensus_available")
        and len(snapshot["runs"]) == 4
        and len(snapshot["observations"]) == 4,
    )
    check("current capture validates", view.current(snapshot, state(snapshot)))
    collision_expected = os.environ.get("CHERNOBOG_COLLISION_EXPECTED") == "1"
    if not collision_expected:
        check(
            "opaque nonzero lease identity",
            bool(re.fullmatch("[0-9a-f]{64}", snapshot.get("lease", "")))
            and snapshot["lease"] != "0" * 64,
        )
        for identity in ("", "0" * 64, snapshot["lease"][:-1], "g" * 64):
            check(
                "invalid lease cannot validate",
                not view.api(
                    "chernobog_vm_temporal_string_state", snapshot["ticket"], identity
                ).get("fresh", False),
            )
        check(
            "wrong ticket cannot validate",
            not view.api(
                "chernobog_vm_temporal_string_state", snapshot["ticket"] + 1, snapshot["lease"]
            ).get("fresh", False),
        )
        legacy = dict(snapshot)
        legacy.pop("lease")
        check(
            "legacy client snapshot remains historical", not view.current(legacy, state(snapshot))
        )
        foreign_database = dict(snapshot, database="foreign")
        check(
            "foreign database label cannot validate",
            not view.current(foreign_database, state(snapshot)),
        )
        rejected = False
        try:
            view.api("chernobog_vm_temporal_string_state", snapshot["ticket"])
        except RuntimeError:
            rejected = True
        check("numeric-only API request rejected", rejected)
        check("invalid requests preserve current lease", view.current(snapshot, state(snapshot)))
    if old:
        check("numeric tickets collide across processes", old["ticket"] == snapshot["ticket"])
        check(
            "new capture observes changed input",
            [x["value"] for x in old["observations"]]
            != [x["value"] for x in snapshot["observations"]],
        )
        check(
            "historical client state matches expected collision behavior",
            view.current(old, state(snapshot)) == collision_expected,
        )
        check(
            "historical API state matches expected collision behavior",
            bool(state(old).get("fresh")) == collision_expected,
        )
        for flags in (ida_segment.MSF_FIXONCE, ida_segment.MSF_FIXONCE | ida_segment.MSF_NETNODES):
            check("forward rebase succeeds", ida_segment.rebase_program(0x100000, flags) == 0)
            ida_auto.auto_wait()
            check("rebase invalidates navigation", not state(snapshot).get("fresh", False))
            check("reverse rebase succeeds", ida_segment.rebase_program(-0x100000, flags) == 0)
            ida_auto.auto_wait()
            check("exact rebase restoration revalidates", view.current(snapshot, state(snapshot)))
        if ida_kernwin.is_idaq():
            from PySide6 import QtWidgets

            form = view.TemporalStringForm(old)
            form.Show("Historical native capture", options=ida_kernwin.PluginForm.WOPN_PERSIST)
            QtWidgets.QApplication.processEvents()
            for name in ("observations", "witnesses", "fragments"):
                form.tables[name].setCurrentItem(form.tables[name].topLevelItem(0))
            form.poll()
            check(
                "historical Qt view cannot navigate", not form.current and not form.jump.isEnabled()
            )
            form.parent.window().resize(1350, 1000)
            QtWidgets.QApplication.processEvents()
            form.parent.grab().save(str(root / "historical_capture.png"))
            form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
            QtWidgets.QApplication.processEvents()
            check("historical Qt close stops timer", form.closed and not form.timer.isActive())
        target = ida_name.get_name_ea(ida_idaapi.BADADDR, "_native_snapshot_strings")
        invalid = view.api("chernobog_vm_temporal_strings", target, "{}", "[]")
        check(
            "failed recapture clears previous lease",
            not invalid.get("available") and not state(snapshot).get("fresh", False),
        )
    else:
        check("database checkpoint saved", ida_loader.save_database(str(root / "capture.i64"), 0))
except BaseException as error:
    errors.append(type(error).__name__)

(root / "string_lifecycle.json").write_text(
    json.dumps({"records": records, "errors": errors, "snapshot": snapshot}, indent=2) + "\n"
)
line = "[chernobog][string-lifecycle] " + ("FAIL" if errors else "PASS")
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
