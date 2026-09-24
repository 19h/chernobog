"""Capture the supplied protected hello after initializer restoration."""

import hashlib
import json
import os
from pathlib import Path

import lldb

ENTRY_STUB = 0x100001436
MAIN = 0x100001440
WINDOW_LENGTH = 40
GPRS = (
    "rax",
    "rcx",
    "rdx",
    "rbx",
    "rsp",
    "rbp",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
)


def capture():
    debugger = lldb.debugger
    debugger.SetAsync(False)
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    if not target.IsValid() or not process.IsValid() or process.GetState() != lldb.eStateStopped:
        raise RuntimeError("process is not stopped at dyld entry")
    module = target.GetModuleAtIndex(0)
    header = module.GetObjectFileHeaderAddress()
    preferred = header.GetFileAddress()
    loaded = header.GetLoadAddress(target)
    if preferred != 0x100000000 or loaded == lldb.LLDB_INVALID_ADDRESS:
        raise RuntimeError("unexpected main-image base")
    slide = loaded - preferred

    def frame():
        thread = process.GetSelectedThread()
        if not thread.IsValid() or process.GetState() != lldb.eStateStopped:
            raise RuntimeError("process did not stop after instruction")
        current = thread.GetFrameAtIndex(0)
        if not current.IsValid():
            raise RuntimeError("stopped process has no frame")
        return thread, current

    def read(address, size):
        error = lldb.SBError()
        data = process.ReadMemory(address, size, error)
        if not error.Success() or len(data) != size:
            raise RuntimeError("failed to read stopped-process memory")
        return bytes(data)

    def registers():
        _, current = frame()
        result = {}
        for name in GPRS:
            value = current.FindRegister(name)
            if not value.IsValid():
                raise RuntimeError("missing register " + name)
            result[name] = hex(value.GetValueAsUnsigned())
        flags = current.FindRegister("rflags")
        if not flags.IsValid():
            flags = current.FindRegister("eflags")
        if not flags.IsValid():
            raise RuntimeError("missing RFLAGS")
        result["eflags"] = hex(flags.GetValueAsUnsigned())
        result["rip"] = hex(current.GetPC())
        return result

    def stop_at(preferred_address):
        address = preferred_address + slide
        breakpoint = target.BreakpointCreateByAddress(address)
        if not breakpoint.IsValid() or breakpoint.GetNumLocations() != 1:
            raise RuntimeError("breakpoint did not resolve")
        error = process.Continue()
        if not error.Success():
            raise RuntimeError("process continue failed: " + error.GetCString())
        thread, current = frame()
        if thread.GetStopReason() != lldb.eStopReasonBreakpoint or current.GetPC() != address:
            raise RuntimeError("process did not stop at requested address")
        target.BreakpointDelete(breakpoint.GetID())
        return address

    stub = stop_at(ENTRY_STUB)
    stub_window = read(MAIN + slide, WINDOW_LENGTH)
    main = stop_at(MAIN)
    main_window = read(main, WINDOW_LENGTH)
    if stub_window != main_window:
        raise RuntimeError("restored window changed between stub and main")
    entry = registers()
    sp = int(entry["rsp"], 16)
    above = read(sp, 128)
    samples = []
    for _ in range(6):
        state = registers()
        pc = int(state["rip"], 16)
        samples.append(
            {
                "registers": state,
                "bytes_16_hex": read(pc, 16).hex(),
                "stack_16_hex": read(int(state["rsp"], 16), 16).hex(),
            }
        )
        thread, _ = frame()
        thread.StepInstruction(False)
    successor = registers()
    executable = target.GetExecutable()
    binary_path = Path(executable.GetDirectory()) / executable.GetFilename()
    report = {
        "schema": 1,
        "debugger_version": debugger.GetVersionString(),
        "binary_sha256": hashlib.sha256(binary_path.read_bytes()).hexdigest(),
        "preferred_base": hex(preferred),
        "loaded_base": hex(loaded),
        "slide": hex(slide),
        "entry_stub_pc": hex(stub),
        "main_pc": hex(main),
        "runtime_window_hex": main_window.hex(),
        "entry_registers": entry,
        "entry_stack_above_hex": above.hex(),
        "samples": samples,
        "successor_registers": successor,
        "successor_stack_16_hex": read(int(successor["rsp"], 16), 16).hex(),
    }
    Path(os.environ["CHERNOBOG_HELLO_MAIN_STATES_OUTPUT"]).write_text(
        json.dumps(report, indent=2) + "\n"
    )
    print("[chernobog][hello-main-states] captured six entered instructions")


capture()
