"""Explicit native-region string inspection under caller-selected ABI models.

show(ea, bindings, input_request=None) executes four bounded seeded captures.
Polling revalidates the retained snapshot; it never reruns the program.
"""

import json

import ida_bytes
import ida_expr
import ida_idaapi
import ida_kernwin


def api(name, *arguments):
    encoded = [
        json.dumps(value) if isinstance(value, str) else str(int(value)) for value in arguments
    ]
    result = ida_expr.idc_value_t()
    error = ida_expr.eval_idc_expr(result, ida_idaapi.BADADDR, name + "(" + ",".join(encoded) + ")")
    if error or result.vtype != ida_expr.VT_STR:
        raise RuntimeError("native string API unavailable")
    return json.loads(result.c_str())


def current(snapshot, state):
    return bool(
        state.get("available")
        and state.get("fresh")
        and snapshot.get("ticket")
        and state.get("ticket") == snapshot["ticket"]
    )


def select_rows(snapshot, observation, capture=None):
    witnesses = [
        row for row in snapshot.get("witnesses", []) if row["observation"] == str(observation)
    ]
    fragments = [
        row
        for row in snapshot.get("fragments", [])
        if row["observation"] == str(observation) and row["capture"] == str(capture)
    ]
    return witnesses, fragments


try:
    from PySide6 import QtCore, QtWidgets
except ImportError:
    QtCore = QtWidgets = None


if QtWidgets is not None:

    class TemporalStringForm(ida_kernwin.PluginForm):
        def __init__(self, snapshot):
            super().__init__()
            self.snapshot = snapshot
            self.current = False
            self.closed = False
            self.observation = self.witness = self.fragment = None

        def OnCreate(self, form):
            self.parent = self.FormToPyQtWidget(form)
            layout = QtWidgets.QVBoxLayout(self.parent)
            self.status = QtWidgets.QLabel()
            self.status.setWordWrap(True)
            layout.addWidget(self.status)
            self.tables = {}
            for key, headers in (
                ("observations", ["Observed string", "Read source", "Agreeing runs"]),
                (
                    "witnesses",
                    ["Capture / seed", "Allocation / generation", "Use interval", "Reads"],
                ),
                ("fragments", ["Event / data event", "Read source", "Address", "Bytes"]),
            ):
                table = QtWidgets.QTreeWidget()
                table.setHeaderLabels(headers)
                table.setRootIsDecorated(False)
                table.setAlternatingRowColors(True)
                table.setUniformRowHeights(True)
                table.setMaximumHeight(
                    {"observations": 100, "witnesses": 140, "fragments": 220}[key]
                )
                table.currentItemChanged.connect(
                    lambda item, previous, name=key: self.selected(name, item)
                )
                self.tables[key] = table
                layout.addWidget(table)
            self.detail = QtWidgets.QPlainTextEdit()
            self.detail.setReadOnly(True)
            layout.addWidget(self.detail)
            self.jump = QtWidgets.QPushButton("Go to selected read")
            self.jump.clicked.connect(self.navigate)
            layout.addWidget(self.jump)
            self.populate("observations", self.snapshot.get("observations", []))
            self.timer = QtCore.QTimer(self.parent)
            self.timer.timeout.connect(self.poll)
            self.timer.start(2000)
            self.poll()

        def populate(self, key, rows):
            table = self.tables[key]
            table.clear()
            for row in rows:
                if key == "observations":
                    columns = [row["value"], row["site"], row["eligible_runs"]]
                elif key == "witnesses":
                    columns = [
                        row["capture"] + " / " + row["seed"],
                        row["allocation"] + " / " + row["generation"],
                        row["first_sequence"] + "–" + row["last_sequence"],
                        row["read_count"],
                    ]
                else:
                    columns = [
                        row["sequence"] + " / " + row["data_sequence"],
                        row["site"],
                        row["address"],
                        row["bytes"],
                    ]
                item = QtWidgets.QTreeWidgetItem(columns)
                item.setData(0, QtCore.Qt.ItemDataRole.UserRole, row)
                table.addTopLevelItem(item)
            for index in range(table.columnCount()):
                table.resizeColumnToContents(index)

        def selected(self, key, item):
            row = item.data(0, QtCore.Qt.ItemDataRole.UserRole) if item else None
            if key == "observations":
                self.observation, self.witness, self.fragment = row, None, None
                witnesses, _ = select_rows(self.snapshot, row["index"]) if row else ([], [])
                self.populate("witnesses", witnesses)
                self.populate("fragments", [])
            elif key == "witnesses":
                self.witness, self.fragment = row, None
                _, fragments = (
                    select_rows(self.snapshot, row["observation"], row["capture"])
                    if row
                    else ([], [])
                )
                self.populate("fragments", fragments)
            else:
                self.fragment = row
            self.update_detail()

        def update_detail(self):
            self.jump.setEnabled(self.current and bool(self.fragment))
            lead = "Select a string, then a capture and an original read.\n\n"
            if self.observation:
                lead = (
                    self.observation["value"] + "\nRead source: " + self.observation["site"] + "\n"
                )
                if self.witness:
                    lead += (
                        "Capture "
                        + self.witness["capture"]
                        + ", seed "
                        + self.witness["seed"]
                        + ": "
                        + self.witness["read_count"]
                        + " reads, allocation "
                        + self.witness["allocation"]
                        + ", generation "
                        + self.witness["generation"]
                        + "; omitted fragments: "
                        + self.witness["fragments_omitted"]
                        + "\n"
                    )
                lead += "\n"
            text = lead + json.dumps(
                {
                    "current_inputs": self.current,
                    "scope": self.snapshot["scope"],
                    "contract": self.snapshot["contract"],
                    "consensus_available": self.snapshot["consensus_available"],
                    "reason": self.snapshot["reason"],
                    "observations_omitted": self.snapshot["observations_omitted"],
                    "observation": self.observation,
                    "witness": self.witness,
                    "fragment": self.fragment,
                    "runs": self.snapshot["runs"],
                    "bindings": self.snapshot["bindings"],
                    "input_arguments": self.snapshot["input_arguments"],
                },
                indent=2,
            )
            if self.detail.toPlainText() != text:
                position = self.detail.verticalScrollBar().value()
                self.detail.setPlainText(text)
                self.detail.verticalScrollBar().setValue(position)

        def poll(self):
            if self.closed:
                return
            try:
                self.current = current(
                    self.snapshot,
                    api("chernobog_vm_temporal_string_state", self.snapshot["ticket"]),
                )
            except (RuntimeError, ValueError, KeyError):
                self.current = False
            prefix = (
                "CURRENT INPUT SNAPSHOT"
                if self.current
                else "HISTORICAL / CHANGED / SUPERSEDED CAPTURE"
            )
            message = (
                prefix
                + " | "
                + str(len(self.snapshot["observations"]))
                + " named-model string observations"
                + " | omitted: "
                + str(self.snapshot["observations_omitted"])
            )
            if not self.snapshot["consensus_available"]:
                message += " | Abstained: " + self.snapshot["reason"]
            self.status.setText(message)
            self.update_detail()

        def navigate(self):
            self.poll()
            if self.current and self.fragment:
                site = int(self.fragment["site"], 0)
                if ida_bytes.is_mapped(site):
                    ida_kernwin.jumpto(site)

        def OnClose(self, form):
            self.closed = True
            self.current = False
            if hasattr(self, "timer"):
                self.timer.stop()


_forms = []


def show(ea, bindings, input_request=None):
    """Explicit capture action; names/addresses are the analyst's ABI contract."""
    if QtWidgets is None:
        raise RuntimeError("Qt inspection unavailable")
    snapshot = api(
        "chernobog_vm_temporal_strings",
        ea,
        json.dumps(input_request or {"args": [], "objects": []}),
        json.dumps(bindings),
    )
    if not snapshot.get("available"):
        raise RuntimeError(snapshot.get("reason", "capture unavailable"))
    form = TemporalStringForm(snapshot)
    _forms[:] = [old for old in _forms if not old.closed]
    _forms.append(form)
    form.Show("Native region strings", options=ida_kernwin.PluginForm.WOPN_PERSIST)
    return form
