"""GUI lifecycle smoke test for first-view rax string materialization.

Run under the graphical IDA executable. The caller supplies
CHERNOBOG_SMOKE_EA and CHERNOBOG_PLUGIN_PATH. The selected function must be
the Aldaz Frida-check fixture used by the integration test.
"""

import hashlib
import os

import ida_auto
import ida_bytes
import ida_hexrays
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_loader
import ida_pro
import ida_segment


EXPECTED_LITERALS = (
    '"WARNING"',
    '"frida"',
    '"python"',
    '"27042"',
    '"lsof -i :%@"',
    '"frida-server"',
    '"Proceso sospechoso detectado: %@"',
    '"27020"',
    '"pgrep %@"',
    '"Frida detectado en puerto %@"',
    '"frida-trace"',
)


def image_digest():
    digest = hashlib.sha256()
    segment_ea = ida_segment.get_first_segment_ea()
    while segment_ea != ida_idaapi.BADADDR:
        segment = ida_segment.getseg(segment_ea)
        if segment is None:
            break
        digest.update(int(segment.start_ea).to_bytes(8, "little"))
        digest.update(int(segment.end_ea).to_bytes(8, "little"))
        size = int(segment.end_ea - segment.start_ea)
        contents = ida_bytes.get_bytes(segment.start_ea, size)
        if contents is not None:
            digest.update(contents)
        segment_ea = ida_segment.get_next_segment_ea(segment.start_ea)
    return digest.digest()


class MutationHooks(ida_idp.IDB_Hooks):
    def __init__(self):
        super().__init__()
        self.byte_patches = 0
        self.comments = 0

    def byte_patched(self, ea, old_value):
        self.byte_patches += 1
        return 0

    def cmt_changed(self, ea, is_repeatable):
        self.comments += 1
        return 0


class CtreeCommentHooks(ida_hexrays.Hexrays_Hooks):
    def __init__(self):
        super().__init__()
        self.comments = 0

    def cmt_changed(self, cfunc, location, comment):
        self.comments += 1
        return 0


state = {
    "timer": None,
    "widget": None,
    "view": None,
    "idb_hooks": None,
    "ctree_hooks": None,
    "baseline": None,
    "ticks": 0,
    "function_ea": 0,
}


def finish(code, message):
    line = "[chernobog][gui-lifecycle-smoke] %s" % message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)
    if state["idb_hooks"] is not None:
        state["idb_hooks"].unhook()
    if state["ctree_hooks"] is not None:
        state["ctree_hooks"].unhook()
    ida_pro.qexit(code)
    return -1


def current_view():
    widget = state["widget"]
    if widget is not None:
        view = ida_hexrays.get_widget_vdui(widget)
        if view is not None and view.cfunc is not None:
            state["view"] = view
            return view
    return None


def missing_literals(view=None):
    if view is None:
        view = current_view()
    if view is None or view.cfunc is None:
        return list(EXPECTED_LITERALS)
    pseudocode = str(view.cfunc)
    return [value for value in EXPECTED_LITERALS if value not in pseudocode]


def lifecycle_tick():
    try:
        state["ticks"] += 1
        if state["ticks"] == 1:
            function_ea = state["function_ea"]
            ida_kernwin.jumpto(function_ea)
            state["view"] = ida_hexrays.open_pseudocode(function_ea, 0)
            if state["view"] is None or state["view"].cfunc is None:
                return finish(
                    4, "first pseudocode view failed at 0x%X" % function_ea
                )
            state["widget"] = state["view"].ct
            first_missing = missing_literals(state["view"])
            if first_missing:
                return finish(
                    5,
                    "runtime literals absent from first view: %s"
                    % first_missing,
                )
            state["baseline"] = image_digest()
            state["idb_hooks"] = MutationHooks()
            state["ctree_hooks"] = CtreeCommentHooks()
            state["idb_hooks"].hook()
            state["ctree_hooks"].hook()
            return 250

        if image_digest() != state["baseline"]:
            return finish(6, "IDB bytes changed after the first pseudocode view")

        # Force the same deep refresh a user-visible pseudocode rebuild uses.
        # The refreshed cfunc must reuse the display projection without a
        # second exploration or any persistent IDB mutation.
        if state["ticks"] == 3:
            view = current_view()
            if view is None:
                return finish(7, "pseudocode view became unavailable")
            view.refresh_view(True)
            view = current_view()
            missing = missing_literals(view)
            if missing:
                return finish(
                    8,
                    "runtime literals absent after deep refresh: %s" % missing,
                )
            if image_digest() != state["baseline"]:
                return finish(9, "deep refresh changed IDB bytes")

        if state["ticks"] >= 9:
            idb_hooks = state["idb_hooks"]
            ctree_hooks = state["ctree_hooks"]
            if idb_hooks.byte_patches != 0:
                return finish(
                    10,
                    "observed %d post-view byte patch notifications"
                    % idb_hooks.byte_patches,
                )
            if idb_hooks.comments != 0 or ctree_hooks.comments != 0:
                return finish(
                    11,
                    "observed post-view comment mutations (IDB=%d, ctree=%d)"
                    % (idb_hooks.comments, ctree_hooks.comments),
                )
            return finish(
                0,
                "PASS function=0x%X first_view_literals=%d refreshes=1"
                % (state["function_ea"], len(EXPECTED_LITERALS)),
            )
        return 250
    except BaseException as error:
        return finish(12, "timer exception: %r" % (error,))


try:
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        finish(2, "Hex-Rays initialization failed")

    plugin_path = os.environ["CHERNOBOG_PLUGIN_PATH"]
    plugin = ida_loader.load_plugin(plugin_path)
    if plugin is None:
        finish(3, "plugin load failed: %s" % plugin_path)

    function_ea = int(os.environ["CHERNOBOG_SMOKE_EA"], 0)
    state["function_ea"] = function_ea
    os.environ["CHERNOBOG_RAX_BATCH_EA"] = hex(function_ea)
    state["timer"] = ida_kernwin.register_timer(250, lifecycle_tick)
    if state["timer"] is None:
        finish(13, "timer registration failed")
except BaseException as error:
    finish(14, "setup exception: %r" % (error,))
