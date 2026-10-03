"""Run the nested AST-cache collision through the loaded IDA/Hex-Rays SDK."""

import ctypes
import hashlib
import json
import os
from pathlib import Path

import ida_kernwin
import ida_pro


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


bridge = Path(os.environ["CHERNOBOG_MBA_COLLISION_BRIDGE"])
plugin = Path(os.environ["CHERNOBOG_PLUGIN_PATH"])
library = ctypes.CDLL(str(bridge))
function = library.chernobog_mba_collision_bridge
function.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t)
function.restype = ctypes.c_int
buffer = ctypes.create_string_buffer(2048)
status = function(os.fsencode(plugin), buffer, len(buffer))
result = json.loads(buffer.value)
result.update(
    schema=1,
    status=status,
    bridge_sha256=digest(bridge),
    plugin_sha256=digest(plugin),
    source_sha256=digest(Path(__file__)),
)
(Path(__file__).resolve().parent.parent / "mba_collision.json").write_text(
    json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
)
ida_kernwin.msg("[chernobog][mba-collision] %s\n" % ("PASS" if status == 0 else "FAIL"))
ida_pro.qexit(0 if status == 0 else 1)
