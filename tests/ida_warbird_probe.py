"""Diagnostic job lifecycle and IDB non-mutation on the ci corpus copy."""

import hashlib
import json
import os
import time

import ida_auto
import ida_bytes
import ida_funcs
import ida_nalt
import ida_segment
import idautils
import idc


def invoke(expression):
    value = idc.eval_idc(expression)
    return json.loads(value)


def identity():
    digest = hashlib.sha256()
    for start in idautils.Segments():
        segment = ida_segment.getseg(start)
        digest.update(str((segment.start_ea, segment.end_ea, segment.perm)).encode())
        data = ida_bytes.get_bytes(segment.start_ea, segment.end_ea - segment.start_ea)
        if data is not None:
            digest.update(data)
    digest.update(str(tuple(idautils.Functions())).encode())
    return digest.hexdigest()


ida_auto.auto_wait()
profiles = invoke("chernobog_warbird_profiles()")
assert sum(profile["key_count"] for profile in profiles) == 11
profile = int(os.environ.get("CHERNOBOG_TEST_PROFILE", "0"))
function_rva = int(os.environ.get("CHERNOBOG_TEST_FUNCTION_RVA", "86888"), 16)
key = os.environ.get("CHERNOBOG_TEST_KEY", "faf1d7c599a70add")
function = ida_funcs.get_func(ida_nalt.get_imagebase() + function_rva)
assert function is not None
before = identity()
start = invoke(f'chernobog_warbird_start({function.start_ea}, {profile}, "{key}")')
if os.environ.get("CHERNOBOG_RAX_DISABLE") == "1":
    assert start.get("ok") is False, start
    assert identity() == before
    print("[chernobog][warbird] PASS disabled")
    idc.qexit(0)
assert start.get("ok"), start
deadline = time.monotonic() + 70
while True:
    result = invoke("chernobog_warbird_poll()")
    if result.get("state") != "running":
        break
    assert time.monotonic() < deadline, result
    time.sleep(0.01)
assert result.get("pseudocode_eligible") is False, result
assert result.get("semantic_equivalence_checked") is False, result
assert result.get("model_version", 0) >= 4, result
allocation_import = [
    entry
    for entry in result["imports"]
    if entry["module"] == "ntoskrnl.exe" and entry["symbol"] == "ExAllocatePoolWithTag"
]
assert len(allocation_import) == 1, allocation_import
assert allocation_import[0]["loaded_mask"] == 0, allocation_import
assert result["frontiers"], result
if os.environ.get("CHERNOBOG_TEST_VECTOR") == "1":
    assert result.get("vector_operations", 0) > 0, result
    assert not any(
        entry["native"] == hex(ida_nalt.get_imagebase() + 0x29E30)
        and "SMIR lift unavailable" in entry["reason"]
        for entry in result["frontiers"]
    ), result
if os.environ.get("CHERNOBOG_TEST_GUARDED_TABLE") == "1":
    assert result.get("write_guard_splits", 0) > 0, result
    assert len(result["keys"]) > 1, result
assert identity() == before, "diagnostic job modified IDB bytes or functions"
# An IDB notification invalidates the lease even when executable bytes and
# function ownership do not change. Restore the comment in this disposable IDB.
old_comment = ida_bytes.get_cmt(function.start_ea, False)
start = invoke(f'chernobog_warbird_start({function.start_ea}, {profile}, "{key}")')
assert start.get("ok"), start
assert ida_bytes.set_cmt(function.start_ea, "warbird lease invalidation probe", False)
deadline = time.monotonic() + 70
while True:
    result = invoke("chernobog_warbird_poll()")
    if result.get("state") != "running":
        break
    assert time.monotonic() < deadline
    time.sleep(0.01)
assert result.get("ok") is False and result.get("reason") == "stale result discarded", result
ida_bytes.set_cmt(function.start_ea, old_comment or "", False)
assert identity() == before
print("[chernobog][warbird] PASS")
idc.qexit(0)
