"""IDA companion: linked instruction-flow, event/lifetime and claim inspection.

The C++ plugin supplies a bounded immutable snapshot. This module never executes
the analyzed program, changes the database, or upgrades observations to proofs.
"""

import json

import ida_bytes
import ida_expr
import ida_funcs
import ida_idaapi
import ida_kernwin

ACTION = "chernobog:evidence_view"
REGION_ACTION = "chernobog:native_region_facts"
CANDIDATE_ACTION = "chernobog:native_candidate_region"


def api(name, ea):
    value = ida_expr.idc_value_t()
    error = ida_expr.eval_idc_expr(value, ida_idaapi.BADADDR, f"{name}({int(ea)})")
    if error or value.vtype != ida_expr.VT_STR:
        raise RuntimeError("evidence API unavailable")
    return json.loads(value.c_str())


def matching_events(snapshot, site=None, run=None, allocation=None, interval=None):
    """All filters retain run/seed and allocation generation identity."""
    return [
        row
        for row in snapshot.get("events", [])
        if (site is None or row.get("site") == site or row.get("target") == site)
        and (run is None or (row.get("run"), row.get("seed")) == run)
        and (interval is None or interval[0] <= int(row.get("sequence", "0"), 0) <= interval[1])
        and (
            allocation is None
            or tuple(row.get(key) for key in ("run", "seed", "allocation", "generation"))
            == allocation
        )
    ]


def current_snapshot(snapshot, state):
    return bool(
        state.get("available")
        and state.get("fresh")
        and snapshot.get("revision") not in (None, "0x0")
        and state.get("revision") == snapshot.get("revision")
        and state.get("database") == snapshot.get("database")
        and state.get("generation") == snapshot.get("generation")
    )


def current_native_publications(snapshot, state):
    """Exact record comparison; no hash equality or ownership receipt promotion."""
    if (
        not state.get("available")
        or state.get("database") != snapshot.get("database")
        or state.get("function") != snapshot.get("function")
    ):
        return set()
    current = {row["publication"]: row for row in state.get("records", [])}
    return {
        row["publication"]
        for row in snapshot.get("records", [])
        if row.get("publication") not in (None, "0x0")
        and row.get("fresh") == "true"
        and current.get(row["publication"]) == row
    }


def current_native_region(snapshot, state):
    """Exact recomputation of a scoped graph, not ordinary proof publication."""
    return bool(
        snapshot.get("available")
        and snapshot.get("context") not in (None, "0x0")
        and snapshot == state
    )


def current_solver_sources(snapshot, state):
    """Admits source navigation only, never current-IR applicability."""
    if (
        not state.get("available")
        or state.get("database") != snapshot.get("database")
        or state.get("function") != snapshot.get("function")
        or state.get("generation") != snapshot.get("generation")
    ):
        return set()
    current = {
        row["query_id"]
        for row in state.get("records", [])
        if row.get("source_bytes_current") == "true"
    }
    return {
        row["query_id"]
        for row in snapshot.get("records", [])
        if row.get("query_id") not in (None, "0x0") and row["query_id"] in current
    }


def load_inspection(ea):
    snapshot = api("chernobog_evidence_view", ea)
    native = api("chernobog_native_evidence", ea)
    if not snapshot.get("available"):
        snapshot = {
            "available": False,
            "fresh": False,
            "database": native["database"],
            "function": native["function"],
            "generation": "0x0",
            "revision": "0x0",
            "edges": [],
            "events": [],
            "lifetimes": [],
            "runs": [],
            "claims": [],
        }
    snapshot["native"] = native
    snapshot["vm"] = api("chernobog_vm_summaries", ea)
    snapshot["vm_states"] = api("chernobog_vm_transitions", ea)
    snapshot["solver"] = api("chernobog_solver_evidence", ea)
    return snapshot


def current_vm_candidates(snapshot, state):
    """Exact recomputed local recognition, not VM semantics or execution admission."""
    if (
        not state.get("available")
        or state.get("database") != snapshot.get("database")
        or state.get("function") != snapshot.get("function")
    ):
        return set()
    current = {row["vm_candidate"]: row for row in state.get("records", [])}
    return {
        row["vm_candidate"]
        for row in snapshot.get("records", [])
        if current.get(row["vm_candidate"]) == row
    }


if ida_kernwin.is_idaq():
    from PySide6 import QtCore, QtGui, QtWidgets

    class FlowNode(QtWidgets.QGraphicsRectItem):
        def __init__(self, owner, site, x, y):
            super().__init__(0, 0, 155, 40)
            self.owner, self.site = owner, site
            self.setPos(x, y)
            self.setBrush(QtGui.QColor("#e1e7ee"))
            self.setPen(QtGui.QPen(QtGui.QColor("#607185")))
            text = QtWidgets.QGraphicsSimpleTextItem(site, self)
            text.setBrush(QtGui.QColor("#172432"))
            text.setPos(8, 12)

        def mousePressEvent(self, event):
            self.owner.select_site(self.site)
            super().mousePressEvent(event)

    class FlowEdge(QtWidgets.QGraphicsPathItem):
        def __init__(self, owner, row, start, end):
            path = QtGui.QPainterPath(start)
            bend = max(40.0, abs(end.y() - start.y()) / 2)
            path.cubicTo(start + QtCore.QPointF(70, bend), end + QtCore.QPointF(-70, -bend), end)
            super().__init__(path)
            self.owner, self.row = owner, row
            color = {"witness": "#267db8", "native-proof": "#49a875"}.get(row["truth"], "#b67e2b")
            pen = QtGui.QPen(QtGui.QColor(color), 2)
            if row["truth"] in ("encoding", "conditional-byte-decode"):
                pen.setStyle(QtCore.Qt.PenStyle.DashLine)
            self.setPen(pen)
            self.setZValue(-1)
            self.setToolTip(row["kind"] + " " + row["site"] + " -> " + row["target"])
            arrow = QtWidgets.QGraphicsPolygonItem(
                QtGui.QPolygonF([end, end + QtCore.QPointF(-9, -4), end + QtCore.QPointF(-9, 4)]),
                self,
            )
            arrow.setBrush(QtGui.QColor(color))
            arrow.setPen(QtGui.QPen(QtCore.Qt.PenStyle.NoPen))

        def mousePressEvent(self, event):
            self.owner.select_site(self.row["site"])
            self.owner.select_record(self.row)
            super().mousePressEvent(event)

    class FlowView(QtWidgets.QGraphicsView):
        def wheelEvent(self, event):
            if event.modifiers() & QtCore.Qt.KeyboardModifier.ControlModifier:
                self.scale(
                    1.15 if event.angleDelta().y() > 0 else 1 / 1.15,
                    1.15 if event.angleDelta().y() > 0 else 1 / 1.15,
                )
            else:
                super().wheelEvent(event)

    class EvidenceForm(ida_kernwin.PluginForm):
        def __init__(self, ea, snapshot):
            super().__init__()
            self.ea, self.snapshot = ea, snapshot
            self.native = snapshot.get("native") or api("chernobog_native_evidence", ea)
            self.native_current = set()
            self.solver_sources_current = set()
            self.vm = snapshot.get("vm") or api("chernobog_vm_summaries", ea)
            self.vm_current = set()
            self.vm_states = snapshot.get("vm_states") or api("chernobog_vm_transitions", ea)
            self.vm_state_candidates = set()
            self.vm_states_current = False
            self.queries = snapshot.get("solver") or api("chernobog_solver_evidence", ea)
            self.site = self.run = self.allocation = None
            self.selected = {}
            self.current = False
            self.closed = False
            self.nodes = {}

        def OnCreate(self, form):
            # SDK 9.4's generic adapter uses shiboken6 despite the legacy name.
            self.parent = self.FormToPyQtWidget(form)
            self.parent.setMinimumSize(1000, 650)
            layout = QtWidgets.QVBoxLayout(self.parent)
            self.status = QtWidgets.QLabel()
            self.status.setWordWrap(True)
            layout.addWidget(self.status)
            controls = QtWidgets.QHBoxLayout()
            for title, callback in (
                ("Reload capture", self.reload),
                ("All events", self.clear_filters),
                ("Fit flow", self.fit_graph),
            ):
                button = QtWidgets.QPushButton(title)
                button.clicked.connect(callback)
                controls.addWidget(button)
            self.run_filter = QtWidgets.QComboBox()
            self.run_filter.currentIndexChanged.connect(self.filter_run)
            controls.addWidget(self.run_filter)
            self.jump = QtWidgets.QPushButton("Jump to source")
            self.jump.clicked.connect(self.jump_source)
            controls.addWidget(self.jump)
            layout.addLayout(controls)
            split = QtWidgets.QSplitter()
            self.scene = QtWidgets.QGraphicsScene(self.parent)
            self.graph = FlowView(self.scene)
            self.graph.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
            self.graph.setDragMode(QtWidgets.QGraphicsView.DragMode.ScrollHandDrag)
            self.graph.setResizeAnchor(QtWidgets.QGraphicsView.ViewportAnchor.AnchorViewCenter)
            self.graph.setTransformationAnchor(
                QtWidgets.QGraphicsView.ViewportAnchor.AnchorUnderMouse
            )
            self.graph.setMinimumWidth(340)
            split.addWidget(self.graph)
            right = QtWidgets.QSplitter(QtCore.Qt.Orientation.Vertical)
            self.tabs = QtWidgets.QTabWidget()
            self.tables = {}
            for key, title in (
                ("events", "Event order"),
                ("read_streams", "Read streams"),
                ("lifetimes", "Allocations"),
                ("runs", "Run stops"),
                ("claims", "Branch claims"),
                ("native", "Native proofs"),
                ("solver", "SMT queries"),
                ("vm", "VM candidates"),
                ("vm_states", "VM states"),
            ):
                table = QtWidgets.QTreeWidget()
                table.setHeaderLabels(
                    ["Role / result", "Query", "Source bytes", "Instruction"]
                    if key == "solver"
                    else (
                        ["Dispatch / direction", "Shape group", "Recognition", "Source"]
                        if key == "vm"
                        else (
                            ["VIP / key", "Run / seed", "Sequence / validity", "Native candidate"]
                            if key == "vm_states"
                            else (
                                ["Conclusion", "Publication", "Validation", "Source / target"]
                                if key == "native"
                                else [
                                    "Kind / state",
                                    "Run / seed",
                                    "Sequence / lifetime",
                                    "Source / address",
                                ]
                            )
                        )
                    )
                )
                table.setRootIsDecorated(False)
                # IDA themes can override the base brush without overriding
                # AlternateBase, producing unreadable light rows in dark mode.
                table.setAlternatingRowColors(False)
                table.itemSelectionChanged.connect(lambda k=key: self.table_selected(k))
                self.tables[key] = table
                self.tabs.addTab(table, title)
            right.addWidget(self.tabs)
            self.detail = QtWidgets.QPlainTextEdit()
            self.detail.setReadOnly(True)
            right.addWidget(self.detail)
            right.setSizes([420, 260])
            split.addWidget(right)
            split.setSizes([440, 680])
            layout.addWidget(split, 1)
            legend = QtWidgets.QLabel(
                "Blue: observed. Amber dashed: encoded. Green: locally proven native transfer. "
                "Dimmed: historical. Local proofs retain their stated assumptions. Ctrl+wheel: zoom."
            )
            legend.setWordWrap(True)
            layout.addWidget(legend)
            self.rebuild()
            self.timer = QtCore.QTimer(self.parent)
            self.timer.timeout.connect(self.poll)
            self.timer.start(1000)
            self.poll()

        def rebuild(self):
            self.scene.clear()
            self.nodes = {}
            self.edges = self.snapshot.get("edges", []) + [
                r for r in self.native.get("records", []) if r.get("edge") == "true"
            ]
            sites = sorted(
                {row[key] for row in self.edges for key in ("site", "target")}
                | {r["site"] for r in self.native.get("records", [])}
                | {r[key] for r in self.vm.get("records", []) for key in ("site", "dispatch")}
                | {
                    r["site"]
                    for r in self.queries.get("records", [])
                    if r["site"] != "0xffffffffffffffff"
                },
                key=lambda text: int(text, 0),
            )
            # A deterministic address layout; edges are directed evidence links,
            # not a claim that address order is execution order.
            for index, site in enumerate(sites):
                node = FlowNode(self, site, (index % 3) * 230, (index // 3) * 85)
                self.nodes[site] = node
                self.scene.addItem(node)
            for row in self.edges:
                start, end = self.nodes[row["site"]], self.nodes[row["target"]]
                self.scene.addItem(
                    FlowEdge(
                        self,
                        row,
                        start.pos() + QtCore.QPointF(155, 20),
                        end.pos() + QtCore.QPointF(0, 20),
                    )
                )
            self.run_filter.blockSignals(True)
            self.run_filter.clear()
            self.run_filter.addItem("All runs", None)
            for row in self.snapshot.get("runs", []):
                self.run_filter.addItem(row["run"] + " / " + row["seed"], (row["run"], row["seed"]))
            self.run_filter.blockSignals(False)
            self.clear_filters()
            for key in ("lifetimes", "runs", "claims", "read_streams"):
                self.populate(key, self.snapshot.get(key, []))
            self.populate("native", self.native.get("records", []))
            self.populate("solver", self.queries.get("records", []))
            self.populate("vm", self.vm.get("records", []))
            self.populate("vm_states", self.vm_states.get("states", []))
            self.show_detail(
                {"inspection": "Select a flow node, event, allocation, run stop or branch claim."}
            )

        def fit_graph(self):
            self.graph.fitInView(
                self.scene.itemsBoundingRect().adjusted(-20, -20, 20, 20),
                QtCore.Qt.AspectRatioMode.KeepAspectRatio,
            )

        def populate(self, key, rows):
            table = self.tables[key]
            table.blockSignals(True)
            table.clear()
            for row in rows:
                kind = row.get(
                    "kind", "allocation" if key == "lifetimes" else row.get("verdict", "run stop")
                )
                order = row.get("sequence", row.get("allocated", ""))
                if key == "lifetimes":
                    order += " .. " + ("live" if row["live"] == "true" else row["released"])
                if key == "read_streams":
                    order = row["first_sequence"] + " .. " + row["last_sequence"]
                columns = (
                    [
                        row["dispatch_kind"] + " / " + row["direction"],
                        row["shape_group"],
                        "candidate",
                        row["site"],
                    ]
                    if key == "vm"
                    else (
                        [
                            row["entry_vip"] + " / " + row["entry_key"],
                            row["run"] + " / " + row["seed"],
                            row["sequence"] + " / captured",
                            row["site"],
                        ]
                        if key == "vm_states"
                        else (
                            [
                                row["role"] + " / " + row["result"],
                                row["query_id"],
                                "captured",
                                row["site"],
                            ]
                            if key == "solver"
                            else (
                                [
                                    kind
                                    + (" (unresolved)" if row.get("truth") == "candidate" else ""),
                                    row["publication"],
                                    row["validation"],
                                    row["site"] + " " + row.get("target", ""),
                                ]
                                if key == "native"
                                else [
                                    kind,
                                    row.get("run", "") + " / " + row.get("seed", ""),
                                    order,
                                    row.get("site", "") + " " + row.get("address", ""),
                                ]
                            )
                        )
                    )
                )
                item = QtWidgets.QTreeWidgetItem(columns)
                item.setData(0, QtCore.Qt.ItemDataRole.UserRole, row)
                table.addTopLevelItem(item)
            for column in range(4):
                table.resizeColumnToContents(column)
            table.blockSignals(False)

        def update_events(self):
            self.populate(
                "events",
                matching_events(
                    self.snapshot,
                    self.site,
                    self.run,
                    self.allocation,
                    getattr(self, "interval", None),
                ),
            )

        def filter_run(self, _index):
            self.interval = None
            self.run = self.run_filter.currentData()
            if self.run is not None:
                self.run = tuple(self.run)
            self.update_events()

        def clear_filters(self):
            self.interval = None
            self.site = self.run = self.allocation = None
            self.run_filter.setCurrentIndex(0)
            self.update_events()

        def select_site(self, site):
            self.interval = None
            self.site, self.allocation = site, None
            self.update_events()
            self.select_record(
                {
                    "site": site,
                    "outgoing_edges": [r for r in self.edges if r["site"] == site],
                    "claims": [r for r in self.snapshot["claims"] if r["site"] == site],
                    "native_publications": [
                        r["publication"]
                        for r in self.native.get("records", [])
                        if site in (r.get("site"), r.get("target"))
                    ],
                    "solver_queries": [
                        r for r in self.queries.get("records", []) if r["site"] == site
                    ],
                    "vm_candidates": [
                        r for r in self.vm.get("records", []) if site in (r["site"], r["dispatch"])
                    ],
                    "vm_candidate_ids": [
                        r["vm_candidate"]
                        for r in self.vm.get("records", [])
                        if site in (r["site"], r["dispatch"])
                    ],
                }
            )

        def record_current(self, row):
            if "vm_state" in row:
                return self.vm_states_current and row["vm_candidate"] in self.vm_state_candidates
            if "vm_candidate" in row:
                return row["vm_candidate"] in self.vm_current
            if "query_id" in row:
                return row["query_id"] in self.solver_sources_current
            if "publication" in row:
                return row["publication"] in self.native_current
            return (
                self.current
                or bool(self.native_current.intersection(row.get("native_publications", [])))
                or bool(self.vm_current.intersection(row.get("vm_candidate_ids", [])))
            )

        def select_record(self, row):
            self.selected = row
            node = self.nodes.get(row.get("site"))
            for other in self.nodes.values():
                other.setBrush(QtGui.QColor("#bedff4" if other is node else "#e1e7ee"))
            if node is not None:
                self.graph.centerOn(node)
            self.show_detail(row)
            self.detail.verticalScrollBar().setValue(0)
            self.detail.horizontalScrollBar().setValue(0)
            self.jump.setEnabled(self.record_current(row) and int(row.get("site", "0"), 0) != 0)

        def table_selected(self, key):
            items = self.tables[key].selectedItems()
            if not items:
                return
            row = items[0].data(0, QtCore.Qt.ItemDataRole.UserRole)
            self.interval = None
            if key == "read_streams":
                self.site = self.allocation = None
                self.run = (row["run"], row["seed"])
                self.interval = (int(row["first_sequence"], 0), int(row["last_sequence"], 0) + 1)
                index = next(
                    (
                        i
                        for i in range(1, self.run_filter.count())
                        if tuple(self.run_filter.itemData(i)) == self.run
                    ),
                    0,
                )
                self.run_filter.blockSignals(True)
                self.run_filter.setCurrentIndex(index)
                self.run_filter.blockSignals(False)
                self.update_events()
            elif key == "lifetimes":
                self.site = self.run = None
                self.run_filter.setCurrentIndex(0)
                self.allocation = tuple(
                    row.get(k) for k in ("run", "seed", "allocation", "generation")
                )
                self.update_events()
            elif key in ("claims", "native", "solver", "vm"):
                self.site, self.run, self.allocation = row["site"], None, None
                self.run_filter.setCurrentIndex(0)
                self.update_events()
            elif key in ("runs", "vm_states"):
                self.site = self.allocation = None
                self.run = (row["run"], row["seed"])
                # Qt transports sequence user data as either a list or tuple.
                index = next(
                    (
                        i
                        for i in range(1, self.run_filter.count())
                        if tuple(self.run_filter.itemData(i)) == self.run
                    ),
                    0,
                )
                self.run_filter.blockSignals(True)
                self.run_filter.setCurrentIndex(index)
                self.run_filter.blockSignals(False)
                self.update_events()
            self.select_record(row)

        def show_detail(self, row):
            detail = {
                "current": self.record_current(row),
                "capture_current": self.current,
                "native_current_count": len(self.native_current),
                "native_scope": {
                    key: self.native.get(key) for key in ("database", "function", "omitted")
                },
                "scope": {
                    key: self.snapshot.get(key)
                    for key in (
                        "database",
                        "function",
                        "generation",
                        "revision",
                        "function_hash",
                        "image_hash",
                        "ticket",
                    )
                },
                "selected": row,
            }
            if "query_id" in row:
                detail.pop("current")
                detail["source_bytes_current"] = self.record_current(row)
                detail["query_applicability"] = (
                    "Recorded formula only; current IR applicability unverified"
                )
                detail["solver_scope"] = {
                    key: self.queries.get(key)
                    for key in (
                        "database",
                        "function",
                        "generation",
                        "omitted",
                        "evicted_functions",
                    )
                }
                # Keep the actual formula readable and the selected query's
                # interpretation visible before generic capture metadata.
                assignments = [
                    row[f"model_{i}_symbol"]
                    + " : "
                    + row[f"model_{i}_sort"]
                    + " = "
                    + row[f"model_{i}_value"]
                    for i in range(32)
                    if all(f"model_{i}_{field}" in row for field in ("symbol", "sort", "value"))
                ]
                text = (
                    row["role"]
                    + " / "
                    + row["result"]
                    + " / query "
                    + row["query_id"]
                    + "\nquery_applicability: "
                    + detail["query_applicability"]
                    + "\nsource_bytes_current: "
                    + str(detail["source_bytes_current"])
                    + "\n"
                    + row.get("model_interpretation", "")
                    + "\n\nCaptured assignments:\n"
                    + ("\n".join(assignments) or "None")
                    + "\n\nSMT-LIB ("
                    + row.get("formula_status", "unavailable")
                    + "):\n"
                    + row.get("formula", "No formula retained")
                    + "\n\nProvenance and diagnostics:\n"
                    + json.dumps(detail, indent=2)
                )
            elif row.get("kind") == "read-stream":
                captured = bytes.fromhex(row.get("bytes_hex", ""))
                preview = captured.split(b"\0", 1)[0].decode("utf-8", errors="ignore")
                text = (
                    "Observed native read stream\n"
                    + "UTF-8 preview: "
                    + json.dumps(preview, ensure_ascii=False)
                    + (" [display truncated]" if row.get("display_truncated") == "true" else "")
                    + "\nReads: "
                    + row["read_count"]
                    + " | Run / seed: "
                    + row["run"]
                    + " / "
                    + row["seed"]
                    + "\nSequence: "
                    + row["first_sequence"]
                    + " .. "
                    + row["last_sequence"]
                    + "\nSource / address: "
                    + row["site"]
                    + " / "
                    + row["address"]
                    + "\n"
                    + row["assumption"]
                    + "\nFragment references (source:sequence:bytes):\n"
                    + row["fragments"]
                    + "\nReferences omitted: "
                    + row["fragments_omitted"]
                    + "\n\nProvenance:\n"
                    + json.dumps(detail, indent=2)
                )
            else:
                text = json.dumps(detail, indent=2)
                if "vm_state" in row:
                    detail["state_scope"] = {
                        k: self.vm_states.get(k)
                        for k in (
                            "database",
                            "function",
                            "generation",
                            "revision",
                            "states_reason",
                            "states_omitted",
                        )
                    }
                    detail["transition_query_references"] = [
                        {k: q[k] for k in ("query_id", "role", "result")}
                        for q in self.queries.get("records", [])
                        if row.get("transition_check")
                        and q.get("transition_check") == row["transition_check"]
                        and q.get("capture_revision") == row["revision"]
                        and all(q.get(k) == row.get(k) for k in ("run", "seed", "sequence", "site"))
                    ]
                    state_identity = "Virtual stack, VM context and memory epoch: unknown"
                    if row.get("virtual_stack_register", "-1") != "-1":
                        state_identity = (
                            "Virtual stack register hypothesis GPR"
                            + row["virtual_stack_register"]
                            + ": entry "
                            + row.get("entry_virtual_stack", "unknown")
                            + ", output "
                            + row.get("output_virtual_stack", "unknown")
                            + "\nVM context and memory epoch: unknown"
                        )
                    text = (
                        "Captured VM-role observation / "
                        + row["path"]
                        + "\n"
                        + state_identity
                        + "\n"
                        + row["runtime_code_identity"]
                        + "\nSemantic validation: "
                        + row["semantic_validation"]
                        + "\n"
                        + row.get("transition_reason", "")
                        + "\n\n"
                        + json.dumps(detail, indent=2)
                    )
                elif "vm_candidate" in row:
                    binding = next(
                        (
                            b
                            for b in self.vm.get("summary_bindings", [])
                            if b["vm_candidate"] == row["vm_candidate"]
                        ),
                        {},
                    )
                    summary = next(
                        (
                            s
                            for s in self.vm.get("summaries", [])
                            if s["summary_id"] == binding.get("summary_id")
                        ),
                        {},
                    )
                    detail["local_effect_summary"] = {
                        "binding": binding,
                        "reference": summary,
                        "sources_current": (
                            row["vm_candidate"] in self.vm_current
                            and binding.get("reference_candidate") in self.vm_current
                        ),
                        "scope": "modeled normal-completion local effects; full VM/handler semantics unverified",
                    }
                    text = (
                        row["classification"]
                        + "\n"
                        + row["ownership"]
                        + "\nUnresolved: "
                        + row["unresolved"]
                        + "\nSyntax grouping: "
                        + row["summary_reuse"]
                        + "\nModeled local effects: "
                        + binding.get("status", "not retained")
                        + "\n"
                        + summary.get("contract", "")
                        + "\nCurrent local recognition: "
                        + str(self.record_current(row))
                        + "\n\n"
                        + json.dumps(detail["local_effect_summary"], indent=2)
                        + "\n\nCandidate provenance:\n"
                        + json.dumps(detail, indent=2)
                    )
            if self.detail.toPlainText() != text:
                vertical = self.detail.verticalScrollBar().value()
                horizontal = self.detail.horizontalScrollBar().value()
                self.detail.setPlainText(text)
                self.detail.verticalScrollBar().setValue(vertical)
                self.detail.horizontalScrollBar().setValue(horizontal)

        def poll(self):
            try:
                state = api("chernobog_evidence_state", self.ea)
                self.current = current_snapshot(self.snapshot, state)
                self.vm_states_current = current_snapshot(self.vm_states, state)
                reason = (
                    "CURRENT"
                    if self.current
                    else "STALE / SUPERSEDED / UNAVAILABLE — historical capture"
                )
                if not self.snapshot.get("available"):
                    reason = "NO EXECUTION CAPTURE LOADED"
            except (RuntimeError, ValueError):
                self.current, reason = False, "UNAVAILABLE — historical capture"
                self.vm_states_current = False
            try:
                self.native_current = current_native_publications(
                    self.native, api("chernobog_native_evidence", self.ea)
                )
            except (RuntimeError, ValueError):
                self.native_current = set()
            try:
                self.solver_sources_current = current_solver_sources(
                    self.queries, api("chernobog_solver_state", self.ea)
                )
            except (RuntimeError, ValueError):
                self.solver_sources_current = set()
            try:
                vm_status = api("chernobog_vm_regions", self.ea)
                self.vm_current = current_vm_candidates(self.vm, vm_status)
                self.vm_state_candidates = current_vm_candidates(self.vm_states, vm_status)
            except (RuntimeError, ValueError):
                self.vm_current = set()
                self.vm_state_candidates = set()
            state_table = self.tables["vm_states"]
            for index in range(state_table.topLevelItemCount()):
                item = state_table.topLevelItem(index)
                row = item.data(0, QtCore.Qt.ItemDataRole.UserRole)
                item.setText(
                    2,
                    row["sequence"]
                    + (" / current" if self.record_current(row) else " / historical"),
                )
            vm_table = self.tables["vm"]
            for index in range(vm_table.topLevelItemCount()):
                item = vm_table.topLevelItem(index)
                row = item.data(0, QtCore.Qt.ItemDataRole.UserRole)
                item.setText(
                    2,
                    (
                        "candidate (current)"
                        if row["vm_candidate"] in self.vm_current
                        else "historical / unavailable"
                    ),
                )
            solver_table = self.tables["solver"]
            for index in range(solver_table.topLevelItemCount()):
                item = solver_table.topLevelItem(index)
                row = item.data(0, QtCore.Qt.ItemDataRole.UserRole)
                item.setText(
                    2,
                    (
                        "match (historical query)"
                        if row["query_id"] in self.solver_sources_current
                        else "changed / unavailable"
                    ),
                )
            native_table = self.tables["native"]
            for index in range(native_table.topLevelItemCount()):
                item = native_table.topLevelItem(index)
                row = item.data(0, QtCore.Qt.ItemDataRole.UserRole)
                item.setText(
                    2,
                    (
                        "current"
                        if row["publication"] in self.native_current
                        else "historical / invalidated"
                    ),
                )
            self.status.setText(
                reason
                + " | native current "
                + str(len(self.native_current))
                + "/"
                + str(len(self.native.get("records", [])))
                + " (omitted "
                + str(self.native.get("omitted", 0))
                + ") | function "
                + self.snapshot["function"]
                + " | SMT queries "
                + str(len(self.queries.get("records", [])))
                + " (omitted "
                + str(self.queries.get("omitted", 0))
                + ")"
                + " | VM candidates "
                + str(len(self.vm.get("records", [])))
                + " (omitted "
                + str(self.vm.get("omitted", 0))
                + ", scan truncated "
                + str(
                    any(
                        self.vm.get(key, False)
                        for key in ("truncated", "path_scan_truncated", "reachability_truncated")
                    )
                )
                + ")"
                + " | local summary bindings "
                + str(len(self.vm.get("summary_bindings", [])))
                + " (omitted "
                + str(self.vm.get("summary_omitted", 0))
                + ")"
                + " | VM state samples "
                + str(len(self.vm_states.get("states", [])))
                + " (omitted "
                + str(self.vm_states.get("states_omitted", 0))
                + ")"
                + " | transition queries "
                + str(self.vm_states.get("transition_queries", 0))
                + " | omitted "
                + json.dumps(self.snapshot.get("omitted", {}))
                + " | static capture truncated: "
                + str(self.snapshot.get("static_truncated"))
            )
            for item in self.scene.items():
                if isinstance(item, FlowEdge):
                    item.setOpacity(1.0 if self.record_current(item.row) else 0.35)
                elif isinstance(item, FlowNode):
                    native_here = any(
                        r["publication"] in self.native_current
                        and item.site in (r.get("site"), r.get("target"))
                        for r in self.native.get("records", [])
                    )
                    vm_here = any(
                        r["vm_candidate"] in self.vm_current
                        and item.site in (r["site"], r["dispatch"])
                        for r in self.vm.get("records", [])
                    )
                    item.setOpacity(1.0 if self.current or native_here or vm_here else 0.45)
            self.jump.setEnabled(
                self.record_current(self.selected) and int(self.selected.get("site", "0"), 0) != 0
            )
            self.show_detail(self.selected)

        def reload(self):
            try:
                snapshot = load_inspection(self.ea)
                if snapshot.get("database") != self.snapshot.get("database"):
                    self.poll()
                    return
                self.snapshot = snapshot
                self.native = snapshot["native"]
                self.queries = snapshot["solver"]
                self.vm = snapshot["vm"]
                self.vm_states = snapshot["vm_states"]
                self.rebuild()
                self.poll()
            except (RuntimeError, ValueError):
                self.poll()

        def jump_source(self):
            self.poll()
            site = int(self.selected.get("site", "0"), 0)
            if self.record_current(self.selected) and site and ida_bytes.is_loaded(site):
                ida_kernwin.jumpto(site)

        def OnClose(self, _form):
            self.closed = True
            if hasattr(self, "timer"):
                self.timer.stop()

    class NativeRegionForm(ida_kernwin.PluginForm):
        """Root-scoped facts and decoded edges with exact recomputation guards."""

        def __init__(self, root, snapshot, api_name="chernobog_native_region_facts"):
            super().__init__()
            self.root, self.snapshot = root, snapshot
            self.api_name = api_name
            self.current = self.closed = False
            self.selected = {}

        def OnCreate(self, form):
            self.parent = self.FormToPyQtWidget(form)
            self.parent.setMinimumSize(1100, 700)
            layout = QtWidgets.QVBoxLayout(self.parent)
            self.status = QtWidgets.QLabel()
            self.status.setWordWrap(True)
            self.status.setSizePolicy(
                QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Maximum
            )
            layout.addWidget(self.status)
            self.scope = QtWidgets.QLabel(self.snapshot.get("scope", ""))
            self.scope.setWordWrap(True)
            self.scope.setSizePolicy(
                QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Maximum
            )
            layout.addWidget(self.scope)
            controls = QtWidgets.QHBoxLayout()
            self.reload_button = QtWidgets.QPushButton("Recompute graph")
            self.reload_button.clicked.connect(self.reload)
            controls.addWidget(self.reload_button)
            fit = QtWidgets.QPushButton("Fit graph")
            fit.clicked.connect(self.fit_graph)
            controls.addWidget(fit)
            self.jump = QtWidgets.QPushButton("Jump to source")
            self.jump.clicked.connect(self.jump_source)
            controls.addWidget(self.jump)
            controls.addStretch()
            layout.addLayout(controls)
            splitter = QtWidgets.QSplitter()
            self.graph = FlowView()
            self.scene = QtWidgets.QGraphicsScene(self.graph)
            self.graph.setScene(self.scene)
            self.graph.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
            splitter.addWidget(self.graph)
            right = QtWidgets.QSplitter(QtCore.Qt.Orientation.Vertical)
            self.tabs = QtWidgets.QTabWidget()
            self.facts = QtWidgets.QTableWidget()
            self.edges = QtWidgets.QTableWidget()
            self.tabs.addTab(self.facts, "Root-scoped facts")
            self.tabs.addTab(self.edges, "Decoded edges and frontiers")
            for table in (self.facts, self.edges):
                table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
                table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
                table.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
                table.itemSelectionChanged.connect(lambda t=table: self.select_table(t))
            right.addWidget(self.tabs)
            self.detail = QtWidgets.QPlainTextEdit()
            self.detail.setReadOnly(True)
            right.addWidget(self.detail)
            right.setSizes([280, 260])
            splitter.addWidget(right)
            splitter.setSizes([480, 620])
            layout.addWidget(splitter, 1)
            self.rebuild()
            self.poll()
            self.timer = QtCore.QTimer(self.parent)
            self.timer.timeout.connect(self.poll)
            self.timer.start(2000)

        def fill_table(self, table, columns, rows):
            table.blockSignals(True)
            table.clear()
            table.setColumnCount(len(columns))
            table.setHorizontalHeaderLabels([label for label, _ in columns])
            table.setRowCount(len(rows))
            for index, row in enumerate(rows):
                for column, (_, key) in enumerate(columns):
                    item = QtWidgets.QTableWidgetItem(str(row.get(key, "")))
                    item.setData(QtCore.Qt.ItemDataRole.UserRole, row)
                    table.setItem(index, column, item)
            table.resizeColumnsToContents()
            table.horizontalHeader().setStretchLastSection(True)
            table.blockSignals(False)

        def rebuild(self):
            self.selected = {}
            self.scene.clear()
            self.nodes = {}
            for index, row in enumerate(self.snapshot.get("nodes", [])):
                site = row["site"]
                node = FlowNode(self, site, (index % 3) * 210, (index // 3) * 95)
                node.setToolTip(json.dumps(row, indent=2, sort_keys=True))
                self.scene.addItem(node)
                self.nodes[site] = node
            displayed_edges = []
            for edge in self.snapshot.get("edges", []):
                row = dict(
                    edge,
                    site=edge["source"],
                    truth=(
                        "conditional-byte-decode"
                        if self.snapshot.get("candidate_decode")
                        else "encoding"
                    ),
                )
                displayed_edges.append(row)
                start, end = self.nodes.get(row["source"]), self.nodes.get(row["target"])
                if start is not None and end is not None:
                    self.scene.addItem(
                        FlowEdge(
                            self,
                            row,
                            start.sceneBoundingRect().center(),
                            end.sceneBoundingRect().center(),
                        )
                    )
            facts = [
                dict(row, result=row.get("outcome", row.get("target", "unknown")))
                for row in self.snapshot.get("records", [])
            ]
            self.fill_table(
                self.facts,
                [
                    ("Site", "site"),
                    ("Kind", "kind"),
                    ("Status", "status"),
                    ("Outcome / target", "result"),
                ],
                facts,
            )
            self.fill_table(
                self.edges,
                [
                    ("Source", "source"),
                    ("Target", "target"),
                    ("Kind", "kind"),
                    ("Basis", "truth"),
                    ("Frontier reason", "reason"),
                ],
                displayed_edges,
            )
            self.scope.setText(self.snapshot.get("scope", ""))
            self.fit_graph()
            self.show_detail()

        def fit_graph(self):
            if self.scene.items():
                self.graph.fitInView(
                    self.scene.itemsBoundingRect().adjusted(-20, -20, 20, 20),
                    QtCore.Qt.AspectRatioMode.KeepAspectRatio,
                )

        def select_table(self, table):
            if table.selectedItems():
                self.select_record(table.selectedItems()[0].data(QtCore.Qt.ItemDataRole.UserRole))

        def select_site(self, site):
            node = next((row for row in self.snapshot.get("nodes", []) if row["site"] == site), {})
            self.select_record(node)

        def select_record(self, row):
            self.selected = row
            self.poll()

        def show_detail(self):
            self.detail.setPlainText(
                json.dumps(
                    {
                        "root": self.snapshot.get("root"),
                        (
                            "current_conditional_graph"
                            if self.snapshot.get("candidate_decode")
                            else "current_exact_graph"
                        ): self.current,
                        "candidate_decode": self.snapshot.get("candidate_decode", False),
                        "flag_encoding": self.snapshot.get("flag_encoding"),
                        "published": False,
                        "scope": self.snapshot.get("scope"),
                        "reason": self.snapshot.get("reason"),
                        "limits": self.snapshot.get("limits"),
                        "selected": self.selected,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            self.jump.setEnabled(self.current and bool(self.selected.get("site")))

        def poll(self):
            try:
                state = api(self.api_name, self.root)
                self.current = current_native_region(self.snapshot, state)
            except (RuntimeError, ValueError):
                self.current = False
            self.status.setText(
                (
                    "Current conditional byte graph"
                    if self.current and self.snapshot.get("candidate_decode")
                    else (
                        "Current exact graph"
                        if self.current
                        else "Unavailable or stale graph; recompute"
                    )
                )
                + " | root "
                + self.snapshot.get("root", "unknown")
                + " | nodes "
                + str(len(self.snapshot.get("nodes", [])))
                + " | fixed point "
                + str(self.snapshot.get("converged", False))
                + " | truncated "
                + str(self.snapshot.get("truncated", False))
                + " | "
                + self.snapshot.get("reason", "")
            )
            self.show_detail()

        def reload(self):
            try:
                state = api(self.api_name, self.root)
                if (state.get("database"), state.get("context")) != (
                    self.snapshot.get("database"),
                    self.snapshot.get("context"),
                ):
                    self.poll()
                    return
                self.snapshot = state
                self.rebuild()
                self.poll()
            except (RuntimeError, ValueError):
                self.poll()

        def jump_source(self):
            self.poll()
            if self.current and self.selected.get("site"):
                site = int(self.selected["site"], 0)
                if ida_bytes.is_loaded(site):
                    ida_kernwin.jumpto(site)

        def OnClose(self, _form):
            self.closed = True
            if hasattr(self, "timer"):
                self.timer.stop()


class NativeRegionAction(ida_kernwin.action_handler_t):
    def __init__(self, owner, api_name="chernobog_native_region_facts"):
        super().__init__()
        self.owner = owner
        self.api_name = api_name

    def activate(self, context):
        root = context.cur_ea
        try:
            snapshot = api(self.api_name, root)
            if self.api_name == "chernobog_native_candidate_region" and not snapshot.get(
                "candidate_decode"
            ):
                raise ValueError("candidate result missing conditional marker")
            if self.api_name == "chernobog_native_candidate_region" and not snapshot.get(
                "available"
            ):
                raise ValueError("selected candidate root unavailable")
            key = (snapshot["database"], snapshot["context"], snapshot["root"], self.api_name)
            title = (
                "Chernobog candidate bytes "
                if snapshot.get("candidate_decode")
                else "Chernobog native region "
            ) + snapshot["root"]
            existing = self.owner.region_forms.get(key)
            if existing is not None and not existing.closed:
                existing.Show(
                    title,
                    options=ida_kernwin.PluginForm.WOPN_PERSIST,
                )
                return 1
            if len(self.owner.region_forms) >= 8:
                oldest = self.owner.region_forms.pop(next(iter(self.owner.region_forms)))
                if not oldest.closed:
                    oldest.Close(ida_kernwin.PluginForm.WCLS_SAVE)
            form = NativeRegionForm(root, snapshot, self.api_name)
            self.owner.region_forms[key] = form
            form.Show(
                title,
                options=ida_kernwin.PluginForm.WOPN_PERSIST,
            )
            return 1
        except (RuntimeError, ValueError, KeyError):
            ida_kernwin.msg("[chernobog] Native region inspection API unavailable.\n")
            return 0

    def update(self, _context):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET


class EvidenceAction(ida_kernwin.action_handler_t):
    def __init__(self, owner):
        super().__init__()
        self.owner = owner

    def activate(self, context):
        function = ida_funcs.get_func(context.cur_ea)
        if function is None:
            return 0
        try:
            snapshot = load_inspection(function.start_ea)
            if (
                not snapshot.get("available")
                and not snapshot["native"].get("records")
                and not snapshot["solver"].get("records")
                and not snapshot["vm"].get("records")
            ):
                ida_kernwin.msg("[chernobog] No captured evidence for this function.\n")
                return 0
            key = (snapshot["database"], snapshot["function"])
            existing = self.owner.forms.get(key)
            if existing is not None and not existing.closed:
                existing.Show(
                    "Chernobog evidence " + snapshot["function"],
                    options=ida_kernwin.PluginForm.WOPN_PERSIST,
                )
                return 1
            form = EvidenceForm(function.start_ea, snapshot)
            if len(self.owner.forms) >= 8:
                oldest = next(iter(self.owner.forms))
                previous = self.owner.forms.pop(oldest)
                if not previous.closed:
                    previous.Close(ida_kernwin.PluginForm.WCLS_SAVE)
            self.owner.forms[key] = form
            form.Show(
                "Chernobog evidence " + snapshot["function"],
                options=ida_kernwin.PluginForm.WOPN_PERSIST,
            )
            return 1
        except (RuntimeError, ValueError):
            ida_kernwin.msg("[chernobog] Evidence inspection API unavailable.\n")
            return 0

    def update(self, _context):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET


class EvidencePlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX
    comment = "Inspect Chernobog evidence"
    help = "Linked instruction flow, lifetimes and branch-claim evidence"
    wanted_name = "Chernobog evidence"
    wanted_hotkey = ""

    def init(self):
        if not ida_kernwin.is_idaq():
            return ida_idaapi.PLUGIN_SKIP
        self.forms = {}
        self.region_forms = {}
        self.action = EvidenceAction(self)
        if not ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                ACTION,
                "Chernobog evidence",
                self.action,
                None,
                "Inspect current-function evidence",
                -1,
            )
        ):
            return ida_idaapi.PLUGIN_SKIP
        ida_kernwin.attach_action_to_menu("View/Open subviews/", ACTION, ida_kernwin.SETMENU_APP)
        self.region_action = NativeRegionAction(self)
        self.region_registered = ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                REGION_ACTION,
                "Chernobog native region facts",
                self.region_action,
                None,
                "Inspect a bounded graph from the exact selected ownerless instruction",
                -1,
            )
        )
        if self.region_registered:
            ida_kernwin.attach_action_to_menu(
                "View/Open subviews/", REGION_ACTION, ida_kernwin.SETMENU_APP
            )
        self.candidate_action = NativeRegionAction(self, "chernobog_native_candidate_region")
        self.candidate_registered = ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                CANDIDATE_ACTION,
                "Chernobog candidate byte region",
                self.candidate_action,
                None,
                "Inspect conditional bytes from the selected executable data head",
                -1,
            )
        )
        if self.candidate_registered:
            ida_kernwin.attach_action_to_menu(
                "View/Open subviews/", CANDIDATE_ACTION, ida_kernwin.SETMENU_APP
            )
        return ida_idaapi.PLUGIN_KEEP

    def run(self, _argument):
        ida_kernwin.process_ui_action(ACTION)

    def term(self):
        for form in getattr(self, "region_forms", {}).values():
            if not form.closed:
                form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
        if getattr(self, "region_registered", False):
            ida_kernwin.unregister_action(REGION_ACTION)
        if getattr(self, "candidate_registered", False):
            ida_kernwin.unregister_action(CANDIDATE_ACTION)
        for form in getattr(self, "forms", {}).values():
            if not form.closed:
                form.Close(ida_kernwin.PluginForm.WCLS_SAVE)
        ida_kernwin.unregister_action(ACTION)


def PLUGIN_ENTRY():
    return EvidencePlugin()
