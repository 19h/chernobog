"""Run the runtime_strings/utf8_fixture.c fixture in a disposable IDB.

Use run_ida_smoke.py --enable-rax. The fixture runs with default analysis
settings and checks first/repeated ctree literals, IDB encoding, protected
metadata, unchanged payload bytes, and invalidation after a decoder-key edit.
"""
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_hexrays
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_name
import ida_nalt
import ida_pro


def finish(code, message):
    line = "[chernobog][utf8-smoke] %s" % message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)
    ida_pro.qexit(code)


def symbol(name):
    for spelling in (name, "_" + name):
        address = ida_name.get_name_ea(ida_idaapi.BADADDR, spelling)
        if address != ida_idaapi.BADADDR:
            return address
    raise RuntimeError("missing fixture symbol: %s" % name)


class LiteralCollector(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
        self.values = []

    def visit_expr(self, expression):
        if expression.op == ida_hexrays.cot_str:
            value = expression.string
            if isinstance(value, bytes):
                value = value.decode("utf-8")
            self.values.append(value)
        return 0


try:
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        finish(2, "Hex-Rays initialization failed")
    plugin = ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    if plugin is None:
        finish(3, "plugin load failed")
    function = symbol("utf8_fixture")
    output = symbol("utf8_output")
    existing = symbol("utf8_existing")
    named = symbol("utf8_named")
    commented = symbol("utf8_commented")
    key = symbol("utf8_key")
    expected = "Gr\u00fc\u00dfe \u4e16\u754c"
    payload = expected.encode("utf-8") + b"\0"
    original_output = ida_bytes.get_bytes(output, len(payload))
    original_existing = ida_bytes.get_bytes(existing, len(payload))
    if original_existing != payload:
        finish(4, "fixture plaintext bytes differ")
    # The production bridge deliberately preserves named or already typed data.
    if not ida_bytes.del_items(existing, ida_bytes.DELIT_SIMPLE, len(payload)):
        finish(4, "could not clear fixture data type")
    if not ida_name.set_name(existing, "", ida_name.SN_NOWARN):
        finish(4, "could not clear fixture data name")
    protected_name = ida_name.get_name(named)
    ida_bytes.del_items(named, ida_bytes.DELIT_SIMPLE, len(payload))
    ida_bytes.del_items(commented, ida_bytes.DELIT_SIMPLE, len(payload))
    ida_name.set_name(commented, "", ida_name.SN_NOWARN)
    protected_comment = "UTF-8 fixture: preserve this interior comment"
    ida_bytes.set_cmt(commented + 2, protected_comment, False)
    os.environ["CHERNOBOG_RAX_BATCH_EA"] = hex(function)
    ida_kernwin.jumpto(function)
    if not ida_loader.run_plugin(plugin, 0x524158):
        finish(5, "current-function exploration failed")
    if (ida_bytes.get_bytes(output, len(payload)) != original_output
            or ida_bytes.get_bytes(existing, len(payload)) != original_existing
            or ida_bytes.get_bytes(named, len(payload)) != payload
            or ida_bytes.get_bytes(commented, len(payload)) != payload):
        finish(6, "rax exploration changed database bytes")
    if (ida_bytes.is_strlit(ida_bytes.get_full_flags(named))
            or ida_name.get_name(named) != protected_name
            or ida_bytes.is_strlit(ida_bytes.get_full_flags(commented))
            or ida_bytes.get_cmt(commented + 2, False) != protected_comment):
        finish(6, "runtime string projection changed protected metadata")
    if not ida_bytes.is_strlit(ida_bytes.get_full_flags(existing)):
        for offset in range(len(payload)):
            current = existing + offset
            print("utf8 range +%d: flags=%X unknown=%s loaded=%s name=%r" % (
                offset, ida_bytes.get_full_flags(current),
                ida_bytes.is_unknown(ida_bytes.get_full_flags(current)),
                ida_bytes.is_loaded(current), ida_name.get_name(current)), flush=True)
        finish(7, "matching UTF-8 bytes were not classified as a string")
    encoding_index = ida_nalt.get_str_encoding_idx(ida_nalt.get_str_type(existing))
    encoding = ida_nalt.get_encoding_name(encoding_index)
    if not encoding or encoding.upper().replace("-", "") != "UTF8":
        finish(8, "string lacks explicit UTF-8 encoding: %r" % encoding)
    cfunc = ida_hexrays.decompile(function, None, ida_hexrays.DECOMP_NO_CACHE)
    if cfunc is None:
        finish(9, "fixture decompilation failed")
    literals = LiteralCollector()
    literals.apply_to(cfunc.body, None)
    (Path(os.environ["IDAUSR"]).parent / "utf8_pseudocode.txt").write_text(
        str(cfunc), encoding="utf-8")
    if expected not in literals.values:
        finish(10, "UTF-8 runtime literal absent from ctree: %r" % literals.values)
    second = ida_hexrays.decompile(function, None, ida_hexrays.DECOMP_NO_CACHE)
    if second is None:
        finish(11, "second uncached decompilation failed")
    repeated_literals = LiteralCollector()
    repeated_literals.apply_to(second.body, None)
    if expected not in repeated_literals.values:
        finish(11, "UTF-8 literal disappeared on repeated decompilation")
    if (ida_bytes.get_bytes(output, len(payload)) != original_output
            or ida_bytes.get_bytes(existing, len(payload)) != original_existing
            or ida_bytes.get_bytes(named, len(payload)) != payload
            or ida_bytes.get_bytes(commented, len(payload)) != payload):
        finish(12, "transient literal materialization changed database bytes")
    # A change to consumed global context must invalidate the previous display
    # fact even though the selected function's instruction bytes are unchanged.
    original_key = ida_bytes.get_byte(key)
    try:
        ida_bytes.patch_byte(key, original_key ^ 3)
        changed = ida_hexrays.decompile(function, None, ida_hexrays.DECOMP_NO_CACHE)
        changed_literals = LiteralCollector()
        if changed is not None:
            changed_literals.apply_to(changed.body, None)
    finally:
        ida_bytes.patch_byte(key, original_key)
    if changed is None or expected in changed_literals.values:
        finish(13, "changed decoder context retained the old runtime literal")
    finish(0, "PASS function=0x%X encoding=%s literal=%s" % (function, encoding, expected))
except BaseException as error:
    finish(99, "exception: %r" % error)
