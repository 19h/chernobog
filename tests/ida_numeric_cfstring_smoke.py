"""Verify address-preserving runtime CFString display on a benign ARM64 fixture.

Compile runtime_strings/numeric_cfstring_fixture.{c,S}; run with
run_ida_smoke.py --enable-rax. Explicit header edits affect only the disposable
IDB and are restored. This probe never creates xrefs, changes permissions, or
injects plaintext.
"""
import hashlib
import json
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_loader
import ida_name
import ida_pro
import ida_segment
import ida_ua
import ida_xref
import idautils

CASES = (
    "good_one", "good_two", "bad_flags", "bad_length", "bad_class",
    "no_fact", "mov_only", "arithmetic", "alt_entry", "narrow",
)
SYMBOL_SIZES = {
    "cf_projection_good_one": 32, "cf_projection_good_two": 32,
    "cf_projection_bad_flags": 32, "cf_projection_bad_length": 32,
    "cf_projection_bad_class": 32, "cf_projection_no_fact": 32,
    "cf_projection_store_offsets": 40, "cf_projection_key": 1,
    "cf_projection_delta": 8, "cf_projection_selector": 4,
    "cf_projection_output_one": 15, "cf_projection_output_two": 15,
    "cf_projection_stores": 80, "cf_projection_not_class": 8,
    "cf_projection_stores_ptr": 8, "cf_projection_encoded_one": 15,
    "cf_projection_encoded_two": 15, "cf_projection_no_fact_bytes": 15,
}
OP_NAMES = {
    getattr(ida_hexrays, name): name
    for name in dir(ida_hexrays) if name.startswith("cot_")
    and isinstance(getattr(ida_hexrays, name), int)
}
PREFIX = "IDB CFString "
report = {"stages": {}, "errors": [], "probe_mutations": []}
retained_cfuncs = []


def check(condition, message):
    if not condition:
        report["errors"].append(message)


def save_report():
    output.joinpath("numeric_cfstring_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")


def finish(code, message):
    line = "[chernobog][numeric-cfstring-smoke] %s" % message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)
    ida_pro.qexit(code)


def symbol(name):
    for spelling in (name, "_" + name):
        address = ida_name.get_name_ea(ida_idaapi.BADADDR, spelling)
        if address != ida_idaapi.BADADDR:
            return address
    raise RuntimeError("missing fixture symbol: " + name)


def digest(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def metadata_snapshot():
    """Include bytes, names and comments, including descriptor interiors."""
    ranges = []
    for name, address, size in monitored_ranges:
        data = ida_bytes.get_bytes(address, size)
        if data is None or len(data) != size:
            raise RuntimeError("unreadable monitored range: " + name)
        metadata = []
        for current in range(address, address + size):
            entry = (current, ida_name.get_name(current),
                     ida_bytes.get_cmt(current, False),
                     ida_bytes.get_cmt(current, True))
            if any(entry[1:]):
                metadata.append(entry)
        ranges.append((name, address, data.hex(), metadata))
    comments = ida_hexrays.restore_user_cmts(function)
    saved_count = 0 if comments is None else comments.size()
    return {
        "ranges_sha256": digest(ranges), "saved_ctree_comments": saved_count,
        "range_components": {
            name: {"bytes_sha256": hashlib.sha256(bytes.fromhex(data)).hexdigest(),
                   "names_comments": metadata}
            for name, address, data, metadata in ranges},
        "function_comments": [
            ida_funcs.get_func_cmt(ida_funcs.get_func(function), repeatable)
            for repeatable in (False, True)],
    }


def scalar_type(expression):
    return {"text": expression.type.dstr(),
            "bytes": expression.type.get_size(),
            "signed": expression.type.is_signed()}


def char_number(value):
    return ord(value) if isinstance(value, str) else int(value)


def shape(expression):
    result = {"op": OP_NAMES.get(expression.op, str(expression.op)),
              "ea": expression.ea, "type": scalar_type(expression)}
    if expression.op == ida_hexrays.cot_num:
        nf = expression.n.nf
        result.update(value=expression.numval(), number_format={
            "flags": nf.flags, "props": char_number(nf.props),
            "opnum": char_number(nf.opnum),
            "org_nbytes": char_number(nf.org_nbytes)})
    elif expression.op == ida_hexrays.cot_obj:
        result["object"] = expression.obj_ea
    elif expression.op in (ida_hexrays.cot_cast, ida_hexrays.cot_ref):
        result["child"] = shape(expression.x)
    elif expression.op == ida_hexrays.cot_add:
        result["left"], result["right"] = shape(expression.x), shape(expression.y)
    return result


def address_identity(expression):
    """Require cast/reference/object AST, not a substituted string pointer."""
    if expression.op != ida_hexrays.cot_cast or expression.x is None:
        return None
    reference = expression.x
    if reference.op != ida_hexrays.cot_ref or reference.x is None:
        return None
    obj = reference.x
    return obj.obj_ea if obj.op == ida_hexrays.cot_obj else None


class Stores(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
        self.assignments = {}

    def visit_expr(self, expression):
        if (expression.op == ida_hexrays.cot_asg
                and expression.ea in store_names):
            self.assignments[store_names[expression.ea]] = expression
        return 0


def read_stage(name, expected_one):
    before = metadata_snapshot()
    cfunc = ida_hexrays.decompile(function, None, ida_hexrays.DECOMP_NO_CACHE)
    if cfunc is None:
        raise RuntimeError("decompilation failed in " + name)
    retained_cfuncs.append(cfunc)
    text = str(cfunc)
    lines = [ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()]
    stores = Stores()
    stores.apply_to(cfunc.body, None)
    stage = {"stores": {}, "metadata_before": before,
             "overlay_lines": [line for line in lines if PREFIX in line]}
    check(set(stores.assignments) == set(CASES),
          name + ": expected every native store in ctree")
    for case in CASES:
        assignment = stores.assignments.get(case)
        if assignment is None:
            continue
        coords = cfunc.find_item_coords(assignment)
        line = (lines[coords[1]] if coords is not None
                and 0 <= coords[1] < len(lines) else None)
        rhs = assignment.y
        row = {"assignment_ea": assignment.ea, "lhs": shape(assignment.x),
               "rhs": shape(rhs), "address_identity": address_identity(rhs),
               "coordinates": coords, "line": line}
        stage["stores"][case] = row
        check(line is not None, name + ": missing coordinates for " + case)
        check(rhs.op != ida_hexrays.cot_str,
              name + ": object address became cot_str in " + case)
        if case in ("good_one", "good_two"):
            expected = expected_one if case == "good_one" else (
                symbols["cf_projection_output_two"], "projection-two")
            object_address = symbols["cf_projection_" + case]
            if expected is not None:
                check(row["address_identity"] == object_address,
                      name + ": address AST missing/changed for " + case)
                check(rhs.type.get_size() == 8 and rhs.type.is_signed()
                      and assignment.x.type.get_size() == 8,
                      name + ": signed 64-bit store type changed in " + case)
                annotation = (
                    'IDB CFString 0x%X -> bytes 0x%X; rax-final: "%s"'
                    % (object_address, expected[0], expected[1]))
                check(line is not None and annotation in line,
                      name + ": exact use-site relation absent in " + case)
            else:
                check(line is not None and PREFIX not in line,
                      name + ": invalid descriptor retained overlay")
                check(rhs.op == ida_hexrays.cot_num
                      and rhs.numval() == object_address,
                      name + ": invalid descriptor reformatted")
        else:
            check(line is not None and PREFIX not in line,
                  name + ": negative use-site annotated: " + case)
            if case in ("bad_flags", "bad_length", "bad_class", "no_fact", "mov_only"):
                object_case = "good_one" if case == "mov_only" else case
                check(rhs.op == ida_hexrays.cot_num
                      and rhs.numval() == symbols["cf_projection_" + object_case],
                      name + ": rejected numeric use changed: " + case)
            elif case == "arithmetic":
                check(rhs.op == ida_hexrays.cot_add,
                      name + ": arithmetic expression changed")
                if rhs.op == ida_hexrays.cot_add:
                    check(any(e.op == ida_hexrays.cot_num
                              and e.numval() == symbols["cf_projection_good_one"]
                              for e in (rhs.x, rhs.y)),
                          name + ": arithmetic address numeral changed")
            elif case == "narrow":
                check(assignment.x.type.get_size() == 4 and rhs.type.get_size() == 4,
                      name + ": narrow store widened")
    check(len(stage["overlay_lines"]) == 1 + (expected_one is not None),
          name + ": unexpected overlay line count")
    check(str(cfunc) == text, name + ": repeated direct AST printing changed")
    second_lines = [
        ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()]
    check(second_lines == lines,
          name + ": repeated displayed pseudocode changed/duplicated overlays")
    active = cfunc.user_cmts
    stage["active_ctree_comments"] = 0 if active is None else active.size()
    check(stage["active_ctree_comments"] == 0,
          name + ": overlay entered saveable ctree comments")
    stage["metadata_after"] = metadata_snapshot()
    check(stage["metadata_after"] == before,
          name + ": decompilation/display changed IDB bytes, names or comments")
    report["stages"][name] = stage
    output.joinpath("numeric_cfstring_" + name + ".txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8")
    output.joinpath("numeric_cfstring_" + name + "_ast.txt").write_text(
        text, encoding="utf-8")
    save_report()
    return cfunc


def mutate_header(offset, value, name, expected):
    address = symbols["cf_projection_good_one"] + offset
    original = ida_bytes.get_bytes(address, 8)
    changed = value.to_bytes(8, "little")
    report["probe_mutations"].append({
        "name": name, "address": address,
        "original": original.hex(), "replacement": changed.hex()})
    try:
        ida_bytes.patch_bytes(address, changed)
        read_stage(name, expected)
    finally:
        ida_bytes.patch_bytes(address, original)
    check(ida_bytes.get_bytes(address, 8) == original,
          name + ": explicit header edit was not restored")


try:
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        finish(2, "Hex-Rays initialization failed")
    output = Path(os.environ["IDAUSR"]).parent
    plugin = ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    if plugin is None:
        finish(3, "plugin load failed")
    function = symbol("numeric_cfstring_fixture")
    symbols = {name: symbol(name) for name in SYMBOL_SIZES}
    descriptor_class = symbol("__CFConstantStringClassReference")
    native_function = ida_funcs.get_func(function)
    monitored_ranges = [("function", function, native_function.end_ea - function)]
    monitored_ranges += [(name, symbols[name], size)
                         for name, size in SYMBOL_SIZES.items()]
    store_sites = {
        case: function + ida_bytes.get_dword(
            symbols["cf_projection_store_offsets"] + 4 * index)
        for index, case in enumerate(CASES)}
    store_names = {address: case for case, address in store_sites.items()}
    report.update(function=function, symbols=symbols, native_sites={})
    for case, address in store_sites.items():
        native = ida_ua.insn_t()
        if ida_ua.decode_insn(native, address) != 4:
            raise RuntimeError("native store did not decode: " + case)
        owner = ida_funcs.get_func(address)
        if owner is None or owner.start_ea != function:
            raise RuntimeError("store split into another function: " + case)
        row = {
            "address": address, "instruction": ida_lines.tag_remove(
                ida_lines.generate_disasm_line(address, 0) or ""),
            "window_bytes": ida_bytes.get_bytes(address - 8, 12).hex(),
            "code_xrefs": [{"from": xref.frm, "type": xref.type}
                           for xref in idautils.XrefsTo(address, ida_xref.XREF_ALL)
                           if xref.iscode],
            "store_bytes": ida_ua.get_dtype_size(native.ops[0].dtype)}
        report["native_sites"][case] = row
        check(native.get_canon_mnem().upper() == "STR",
              "fixture site is not native STR: " + case)
        check(row["store_bytes"] == (4 if case == "narrow" else 8),
              "fixture native store width differs: " + case)
    check(any((entry["type"] & ida_xref.XREF_MASK) != ida_xref.fl_F
              for entry in report["native_sites"]["alt_entry"]["code_xrefs"]),
          "alternate-entry fixture lacks nonfallthrough code reference")
    report["descriptors"] = {}
    for case in CASES[:6]:
        address = symbols["cf_projection_" + case]
        if not all(ida_bytes.is_loaded(address + i) for i in range(32)):
            raise RuntimeError("descriptor not fully loaded: " + case)
        slots = [ida_bytes.get_qword(address + 8 * i) for i in range(4)]
        report["descriptors"][case] = {
            "address": address, "slots": slots,
            "segment_permissions": ida_segment.getseg(address).perm}
        check(slots[0] == (symbols["cf_projection_not_class"]
                           if case == "bad_class" else descriptor_class),
              "fixture descriptor class mismatch: " + case)
        check(slots[1] == (0x7D0 if case == "bad_flags" else 0x7C8),
              "fixture descriptor flags mismatch: " + case)
        check(slots[3] == (13 if case == "bad_length" else 14),
              "fixture descriptor length mismatch: " + case)
    # RAX's analysis action creates data references, which can make IDA expose
    # automatic unk_ names at byte-array interiors. Complete that independently
    # before attributing any later metadata changes to decompilation/display.
    report["before_exploration"] = metadata_snapshot()
    os.environ["CHERNOBOG_RAX_BATCH_EA"] = hex(function)
    ida_kernwin.jumpto(function)
    if not ida_loader.run_plugin(plugin, 0x524158):
        raise RuntimeError("current-function runtime exploration failed")
    ida_auto.auto_wait()
    initial_snapshot = metadata_snapshot()
    report["after_exploration"] = initial_snapshot
    for name in SYMBOL_SIZES:
        check(report["before_exploration"]["range_components"][name]["bytes_sha256"]
              == initial_snapshot["range_components"][name]["bytes_sha256"],
              "runtime exploration changed fixture data bytes: " + name)
    check(initial_snapshot["saved_ctree_comments"] == 0,
          "fresh fixture has saved ctree comments")
    original_one = (symbols["cf_projection_output_one"], "projection-one")
    read_stage("initial", original_one)
    read_stage("repeated", original_one)
    mutate_header(16, symbols["cf_projection_output_two"], "retargeted", (
        symbols["cf_projection_output_two"], "projection-two"))
    mutate_header(24, 13, "length_rejected", None)
    mutate_header(16, symbols["cf_projection_no_fact_bytes"], "no_fact_rejected", None)
    read_stage("restored", original_one)
    check(metadata_snapshot() == initial_snapshot,
          "final IDB state differs after restoring explicit probe edits")
    save_report()
    if report["errors"]:
        finish(6, "FAIL " + "; ".join(report["errors"]))
    finish(0, "PASS preserved-addresses=2 rejected-use-sites=8 header-mutations=3 transient-overlay=verified")
except BaseException as error:
    report["exception"] = repr(error)
    if "output" in globals():
        save_report()
    finish(99, "exception: %r" % (error,))
