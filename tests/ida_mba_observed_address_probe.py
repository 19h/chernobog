"""Test a copied live SDK-produced address operand through the MBA matcher."""

import ctypes
import hashlib
import json
import os
from pathlib import Path

import ida_auto
import ida_funcs
import ida_hexrays as hx
import ida_kernwin
import ida_pro


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def find_address(operand, depth=0):
    if depth > 32:
        return None
    if operand.t == hx.mop_a and operand.a is not None:
        return operand
    if operand.t == hx.mop_d and operand.d is not None:
        for child in (operand.d.l, operand.d.r, operand.d.d):
            found = find_address(child, depth + 1)
            if found is not None:
                return found
    return None


ida_auto.auto_wait()
assert hx.init_hexrays_plugin(), "decompiler unavailable"
bridge = Path(os.environ["CHERNOBOG_MBA_OBSERVED_ADDRESS_BRIDGE"])
plugin = Path(os.environ["CHERNOBOG_PLUGIN_PATH"])
ctypes.CDLL(str(plugin), mode=ctypes.RTLD_GLOBAL)
library = ctypes.CDLL(str(bridge))
function = library.chernobog_mba_observed_address_bridge
function.argtypes = (ctypes.c_char_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t)
function.restype = ctypes.c_int
function_ea = 0x806F37B
owner = ida_funcs.get_func(function_ea)
assert owner is not None and owner.start_ea == function_ea, "fixture owner"
found = None
for maturity in (hx.MMAT_GENERATED, hx.MMAT_PREOPTIMIZED, hx.MMAT_LOCOPT, hx.MMAT_GLBOPT1):
    failure = hx.hexrays_failure_t()
    mba = hx.gen_microcode(
        hx.mba_ranges_t(owner),
        failure,
        None,
        hx.DECOMP_NO_CACHE | hx.DECOMP_ALL_BLKS,
        maturity,
    )
    assert mba is not None, "microcode generation failed"
    for index in range(mba.qty):
        instruction = mba.get_mblock(index).head
        while instruction is not None:
            for operand in (instruction.l, instruction.r, instruction.d):
                source = find_address(operand)
                if source is not None:
                    found = (mba, source, instruction.ea, maturity)
                    break
            if found is not None:
                break
            instruction = instruction.next
        if found is not None:
            break
    if found is not None:
        break
assert found is not None, "no SDK address operand in fixture"
mba, source, source_ea, maturity = found
buffer = ctypes.create_string_buffer(2048)
status = function(os.fsencode(plugin), int(source.this), buffer, len(buffer))
result = json.loads(buffer.value)
result.update(
    schema=1,
    status=status,
    function_ea=function_ea,
    source_ea=int(source_ea),
    maturity=int(maturity),
    bridge_sha256=digest(bridge),
    plugin_sha256=digest(plugin),
    source_sha256=digest(Path(__file__)),
)
(Path(__file__).resolve().parent.parent / "mba_observed_address.json").write_text(
    json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
)
ida_kernwin.msg("[chernobog][mba-observed-address] %s\n" % ("PASS" if status == 0 else "FAIL"))
ida_pro.qexit(0 if status == 0 else 1)
