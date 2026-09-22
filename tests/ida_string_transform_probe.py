"""Capture actual decompiler loop shapes for the typed-transform fixtures."""

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

records, errors = [], []
checks = []
names = (
    "transform_bytes",
    "transform_words",
    "transform_byte_utf16",
    "transform_wrong_rotate",
    "transform_wrong_index",
    "transform_unknown_key",
    "transform_missing_terminator",
    "transform_narrow_rotate",
    "transform_word_byte_index",
    "transform_mutable",
    "transform_alias",
    "transform_extra_write",
)
op_names = {
    getattr(ida_hexrays, name): name
    for name in dir(ida_hexrays)
    if name.startswith(("cot_", "cit_")) and isinstance(getattr(ida_hexrays, name), int)
}


def check(label, condition):
    checks.append({"case": label, "passed": bool(condition)})
    if not condition:
        errors.append(label)


def display(cfunc):
    return [ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()]


def symbol(name):
    for spelling in ("_" + name, name):
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, spelling)
        if ea != ida_idaapi.BADADDR:
            return ea
    return ida_idaapi.BADADDR


class Shapes(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
        self.expressions = []
        self.instructions = []

    def visit_expr(self, expression):
        item = {
            "op": op_names.get(expression.op, str(expression.op)),
            "ea": int(expression.ea),
            "type": str(expression.type),
            "size": int(expression.type.get_size()),
        }
        if expression.op == ida_hexrays.cot_var:
            item["variable"] = expression.v.idx
        elif expression.op == ida_hexrays.cot_num:
            item["value"] = int(expression.numval())
        elif expression.op == ida_hexrays.cot_obj:
            item["address"] = int(expression.obj_ea)
        elif expression.op == ida_hexrays.cot_helper:
            item["helper"] = str(expression.helper)
        self.expressions.append(item)
        return 0

    def visit_insn(self, instruction):
        self.instructions.append(
            {"op": op_names.get(instruction.op, str(instruction.op)), "ea": int(instruction.ea)}
        )
        return 0


try:
    ida_auto.auto_wait()
    assert ida_hexrays.init_hexrays_plugin(), "Hex-Rays unavailable"
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"]), "plugin unavailable"
    for name in names:
        ea = symbol(name)
        assert ea != ida_idaapi.BADADDR, "fixture symbol missing"
        native = ida_funcs.get_func(ea)
        native_bytes = ida_bytes.get_bytes(ea, native.end_ea - ea)
        cfunc = ida_hexrays.decompile(ea, None, ida_hexrays.DECOMP_NO_CACHE)
        assert cfunc is not None, "fixture decompilation failed"
        shapes = Shapes()
        shapes.apply_to(cfunc.body, None)
        lines = display(cfunc)
        records.append(
            {
                "name": name,
                "entry": int(ea),
                "text": str(cfunc),
                "display": lines,
                "expressions": shapes.expressions,
                "instructions": shapes.instructions,
            }
        )
        if os.environ.get("CHERNOBOG_EXPECT_STRING_TRANSFORMS") != "1":
            continue
        expected = {
            "transform_bytes": (8, 9, "UTF-8", "VMP byte"),
            "transform_words": (16, 5, "UTF-16LE", "VMP\u03a9"),
            "transform_byte_utf16": (8, 10, "UTF-16LE", "Wide"),
        }.get(name)
        annotations = [line for line in lines if "rot32-xor[" in line]
        if expected:
            bits, units, encoding, text = expected
            check(
                name + " proven unit/key/bound/encoding",
                len(annotations) == 1
                and f"{bits}-bit units, key=0xA17E395B, units={units}]" in annotations[0]
                and f'{encoding} candidate "{text}"' in annotations[0],
            )
            source = symbol(name + "_source")
            assert source != ida_idaapi.BADADDR, "cipher source missing"
            original = ida_bytes.get_byte(source)
            ida_bytes.patch_byte(source, original ^ 1)
            cfunc.refresh_func_ctext()
            check(
                name + " cipher patch invalidates",
                not any("rot32-xor[" in line for line in display(cfunc)),
            )
            ida_bytes.patch_byte(source, original)
            cfunc.refresh_func_ctext()
            check(
                name + " exact cipher restoration",
                sum("rot32-xor[" in line for line in display(cfunc)) == 1,
            )
            segment = ida_segment.getseg(source)
            permission = segment.perm
            segment.perm |= ida_segment.SEGPERM_WRITE
            assert ida_segment.update_segm(segment), "permission control failed"
            cfunc.refresh_func_ctext()
            check(
                name + " mutable source rejected",
                not any("rot32-xor[" in line for line in display(cfunc)),
            )
            segment.perm = permission
            assert ida_segment.update_segm(segment), "permission restoration failed"
            code_byte = ida_bytes.get_byte(ea)
            ida_bytes.patch_byte(ea, code_byte ^ 1)
            cfunc.refresh_func_ctext()
            check(
                name + " native patch invalidates",
                not any("rot32-xor[" in line for line in display(cfunc)),
            )
            ida_bytes.patch_byte(ea, code_byte)
            cfunc.refresh_func_ctext()
            check(
                name + " exact native restoration",
                sum("rot32-xor[" in line for line in display(cfunc)) == 1,
            )
        else:
            check(name + " abstains", not annotations)
        active = cfunc.user_cmts
        saved = ida_hexrays.restore_user_cmts(ea)
        check(
            name + " no saved/saveable comments",
            (active is None or active.size() == 0) and (saved is None or saved.size() == 0),
        )
        check(
            name + " unchanged native bytes",
            ida_bytes.get_bytes(ea, len(native_bytes)) == native_bytes,
        )
except BaseException as error:
    errors.append(type(error).__name__)

(Path(os.environ["IDAUSR"]).parent / "string_transforms.json").write_text(
    json.dumps({"records": records, "checks": checks, "errors": errors}, indent=2) + "\n"
)
line = "[chernobog][string-transforms] " + (
    "FAIL " + "; ".join(errors) if errors else "PASS captures=%d" % len(records)
)
print(line, flush=True)
ida_kernwin.msg("%s\n" % line)
ida_pro.qexit(2 if errors else 0)
