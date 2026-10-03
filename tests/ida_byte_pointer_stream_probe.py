"""Inspect exact LEA and loaded-global byte-pointer loops in Hex-Rays."""

import json
import os
from pathlib import Path

import ida_allins
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

records, checks, errors = [], [], []


def check(label, result):
    checks.append({"case": label, "passed": bool(result)})
    if not result:
        errors.append(label)


def symbol(name):
    for spelling in ("_" + name, name):
        address = ida_name.get_name_ea(ida_idaapi.BADADDR, spelling)
        if address != ida_idaapi.BADADDR:
            return address
    return ida_idaapi.BADADDR


def display(cfunc):
    return [ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()]


def annotations(cfunc):
    return [line for line in display(cfunc) if "rot32-xor[" in line]


class Shapes(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
        self.expressions = []

    def visit_expr(self, expression):
        if expression.op in (ida_hexrays.cot_postinc, ida_hexrays.cot_ptr):
            self.expressions.append(
                {
                    "op": "postinc" if expression.op == ida_hexrays.cot_postinc else "ptr",
                    "ea": int(expression.ea),
                    "type": str(expression.type),
                    "size": int(expression.type.get_size()),
                }
            )
        return 0


try:
    ida_auto.auto_wait()
    assert ida_hexrays.init_hexrays_plugin(), "Hex-Rays unavailable"
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"]), "plugin unavailable"
    source = symbol("byte_pointer_source")
    pointer = symbol("byte_pointer_global")
    assert source != ida_idaapi.BADADDR and pointer != ida_idaapi.BADADDR
    check("global initially names immutable source", ida_bytes.get_qword(pointer) == source)
    check("native cipher first byte loaded", ida_bytes.is_loaded(source))
    for name, expected_itype in (
        ("byte_pointer_stream", ida_allins.NN_lea),
        ("byte_pointer_loaded_global", ida_allins.NN_mov),
    ):
        entry = symbol(name)
        assert entry != ida_idaapi.BADADDR
        native = ida_funcs.get_func(entry)
        assert native is not None and native.start_ea == entry
        original_code = ida_bytes.get_bytes(entry, native.end_ea - entry)
        instruction = ida_ua.insn_t()
        assert ida_ua.decode_insn(instruction, entry) > 0
        check(name + " initializer instruction", instruction.itype == expected_itype)
        cfunc = ida_hexrays.decompile(entry, None, ida_hexrays.DECOMP_NO_CACHE)
        assert cfunc is not None
        shapes = Shapes()
        shapes.apply_to(cfunc.body, None)
        text = str(cfunc)
        rows = annotations(cfunc)
        check(
            name + " pointer stride shape",
            "*result++" in text
            and sum(item["op"] == "postinc" for item in shapes.expressions) == 1
            and sum(item["op"] == "ptr" for item in shapes.expressions) >= 1,
        )
        positive = name == "byte_pointer_stream"
        if positive:
            check(
                name + " exact plaintext candidate",
                len(rows) == 1
                and "8-bit units, key=0xA17E395B, units=9" in rows[0]
                and 'UTF-8 candidate "VMP byte"' in rows[0],
            )
            original_cipher = ida_bytes.get_byte(source)
            ida_bytes.patch_byte(source, original_cipher ^ 1)
            cfunc.refresh_func_ctext()
            check(name + " source byte revokes", not annotations(cfunc))
            ida_bytes.patch_byte(source, original_cipher)
            cfunc.refresh_func_ctext()
            check(name + " source restoration", len(annotations(cfunc)) == 1)
            segment = ida_segment.getseg(source)
            permission = segment.perm
            segment.perm |= ida_segment.SEGPERM_WRITE
            assert ida_segment.update_segm(segment)
            cfunc.refresh_func_ctext()
            check(name + " writable source revokes", not annotations(cfunc))
            segment.perm = permission
            assert ida_segment.update_segm(segment)
            cfunc.refresh_func_ctext()
            check(name + " permission restoration", len(annotations(cfunc)) == 1)
            first = ida_bytes.get_byte(entry)
            ida_bytes.patch_byte(entry, first ^ 1)
            cfunc.refresh_func_ctext()
            check(name + " code byte revokes", not annotations(cfunc))
            ida_bytes.patch_byte(entry, first)
            cfunc.refresh_func_ctext()
            check(name + " code restoration", len(annotations(cfunc)) == 1)
        else:
            check(name + " mutable pointer value abstains", not rows)
        saved = ida_hexrays.restore_user_cmts(entry)
        check(name + " no saved comments", saved is None or saved.size() == 0)
        check(
            name + " native bytes unchanged",
            ida_bytes.get_bytes(entry, len(original_code)) == original_code,
        )
        records.append(
            {
                "name": name,
                "entry": hex(entry),
                "initializer_itype": int(instruction.itype),
                "source": hex(source),
                "pointer_global": hex(pointer),
                "text": text,
                "display": display(cfunc),
                "expressions": shapes.expressions,
            }
        )
except BaseException as error:
    errors.append(type(error).__name__)

(Path(os.environ["IDAUSR"]).parent / "byte_pointer_stream.json").write_text(
    json.dumps({"records": records, "checks": checks, "errors": errors}, indent=2) + "\n"
)
line = "[chernobog][byte-pointer-stream] " + (
    "FAIL " + "; ".join(errors) if errors else "PASS records=%d" % len(records)
)
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
