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
function = ida_funcs.get_func(ida_nalt.get_imagebase() + 0x86888)
assert function is not None
before = identity()
start = invoke(f'chernobog_warbird_start({function.start_ea}, 0, "faf1d7c599a70add")')
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
assert result["frontiers"], result
assert identity() == before, "diagnostic job modified IDB bytes or functions"
# An IDB notification invalidates the lease even when executable bytes and
# function ownership do not change. Restore the comment in this disposable IDB.
old_comment = ida_bytes.get_cmt(function.start_ea, False)
start = invoke(f'chernobog_warbird_start({function.start_ea}, 0, "faf1d7c599a70add")')
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
