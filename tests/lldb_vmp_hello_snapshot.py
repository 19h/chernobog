"""Run inside LLDB after the supplied hello-world process stops at printf."""

import json
import os
from pathlib import Path

import lldb


def capture():
    debugger = lldb.debugger
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    if not target.IsValid() or not process.IsValid():
        raise RuntimeError("missing LLDB target or process")
    if process.GetState() != lldb.eStateStopped:
        raise RuntimeError("process did not stop")
    thread = process.GetSelectedThread()
    if not thread.IsValid() or thread.GetStopReason() != lldb.eStopReasonBreakpoint:
        raise RuntimeError("process did not stop at a breakpoint")
    frame = thread.GetFrameAtIndex(0)
    function = frame.GetFunctionName() or ""
    if "printf" not in function:
        raise RuntimeError("breakpoint is not at printf")
    module = target.GetModuleAtIndex(0)
    image_header = module.GetObjectFileHeaderAddress()
    loaded_base = image_header.GetLoadAddress(target)
    preferred_base = image_header.GetFileAddress()
    if loaded_base == lldb.LLDB_INVALID_ADDRESS or preferred_base != 0x100000000:
        raise RuntimeError("unexpected main-image base")
    slide = loaded_base - preferred_base

    def read(address, size):
        error = lldb.SBError()
        data = process.ReadMemory(address, size, error)
        if not error.Success() or len(data) != size:
            raise RuntimeError("failed to read stopped process memory")
        return bytes(data).hex()

    text_address = int(os.environ["CHERNOBOG_HELLO_TEXT_ADDRESS"], 0) + slide
    text_size = int(os.environ["CHERNOBOG_HELLO_TEXT_SIZE"])
    string_address = int(os.environ["CHERNOBOG_HELLO_STRING_ADDRESS"], 0) + slide
    string_size = int(os.environ["CHERNOBOG_HELLO_STRING_SIZE"])
    format_pointer = frame.FindRegister("rdi").GetValueAsUnsigned()
    report = {
        "schema": 1,
        "target_name": target.GetExecutable().GetFilename(),
        "stop_reason": "breakpoint",
        "function": function,
        "preferred_base": hex(preferred_base),
        "loaded_base": hex(loaded_base),
        "slide": hex(slide),
        "pc": hex(frame.GetPC()),
        "format_pointer": hex(format_pointer),
        "text_address": hex(text_address),
        "text_hex": read(text_address, text_size),
        "string_address": hex(string_address),
        "string_hex": read(string_address, string_size),
        "window_hex": read(text_address, string_address + string_size - text_address),
    }
    if format_pointer != string_address:
        raise RuntimeError("printf format pointer does not address the captured string")
    Path(os.environ["CHERNOBOG_HELLO_SNAPSHOT_OUTPUT"]).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    print("[chernobog][hello-snapshot] captured printf use")


capture()
