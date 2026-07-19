"""Dump recurrent-switch transition microcode for the reference CFF sample.

This is a diagnostic probe: it does not load Chernobog and never mutates the
database or the generated microcode.
"""

import os
from collections import deque

import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_nalt
import ida_pro
import ida_xref


TARGET_EA = int(os.environ.get("CHERNOBOG_SMOKE_EA", "0x82AF0"), 0)
DISPATCH_EA = int(os.environ.get("CHERNOBOG_DISPATCH_EA", "0x82C65"), 0)


def emit(message):
    line = "[chernobog][cff-transition-probe] %s" % message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)


def finish(code, message):
    emit(message)
    ida_pro.qexit(code)


def block_lines(block):
    lines = []
    instruction = block.head
    while instruction is not None:
        lines.append("%X: %s" % (instruction.ea, instruction.dstr()))
        instruction = instruction.next
    return lines


try:
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        finish(2, "Hex-Rays initialization failed")

    function = ida_funcs.get_func(TARGET_EA)
    if function is None:
        finish(3, "function not found at 0x%X" % TARGET_EA)

    ranges = ida_hexrays.mba_ranges_t(function)
    failure = ida_hexrays.hexrays_failure_t()
    mba = ida_hexrays.gen_microcode(
        ranges,
        failure,
        None,
        ida_hexrays.DECOMP_NO_CACHE,
        ida_hexrays.MMAT_LOCOPT,
    )
    if mba is None:
        finish(4, "microcode generation failed: %s" % failure.desc())

    dispatch = None
    switch = None
    for index in range(mba.qty):
        block = mba.get_mblock(index)
        if block.start <= DISPATCH_EA < block.end:
            dispatch = block
        if block.nsucc() >= 8 and (switch is None or block.nsucc() > switch.nsucc()):
            switch = block
    if dispatch is None or switch is None:
        finish(5, "dispatcher or switch microblock not found")

    switch_ea = switch.tail.ea
    switch_info = ida_nalt.get_switch_info(switch_ea)
    if switch_info is None:
        finish(6, "IDA switch metadata not found at 0x%X" % switch_ea)

    cases_and_targets = ida_xref.calc_switch_cases(switch_ea, switch_info)
    emit(
        "mba=%d dispatcher=blk%d switch=blk%d switch_ea=%X api_type=%s"
        % (mba.qty, dispatch.serial, switch.serial, switch_ea,
           type(cases_and_targets).__name__)
    )
    emit("api_repr=%r" % (cases_and_targets,))
    emit("api_dir=%r" % (dir(cases_and_targets),))
    for attribute in ("cases", "targets"):
        value = getattr(cases_and_targets, attribute, None)
        emit("api_%s_type=%s repr=%r" % (attribute, type(value).__name__, value))
        if value is not None:
            try:
                emit("api_%s_len=%d values=%r" % (attribute, len(value), list(value)))
            except BaseException as error:
                emit("api_%s_iter_error=%r" % (attribute, error))
    for index, target_ea in enumerate(cases_and_targets.targets):
        values = [int(value) for value in cases_and_targets.cases[index]]
        target_block = -1
        for block_index in range(mba.qty):
            block = mba.get_mblock(block_index)
            if block.start <= target_ea < block.end:
                target_block = block_index
                break
        emit(
            "case index=%d values=%s target_ea=%X target=blk%d"
            % (index, ",".join("0x%X" % (value & 0xFFFFFFFFFFFFFFFF) for value in values),
               target_ea, target_block)
        )

    # Shortest-path provenance from every decoded switch target to the
    # dispatcher.  The predecessor chosen for a block is retained so each
    # emitted path is reproducible.
    target_blocks = sorted({switch.succ(i) for i in range(switch.nsucc())})
    path_records = []
    relevant = {dispatch.serial, switch.serial}
    for target in target_blocks:
        queue = deque([target])
        parent = {target: None}
        found = False
        while queue and len(parent) <= 2048:
            current = queue.popleft()
            if current == dispatch.serial:
                found = True
                break
            if len(parent) > 32 * max(1, len(target_blocks)):
                break
            block = mba.get_mblock(current)
            for successor_index in range(block.nsucc()):
                successor = block.succ(successor_index)
                if successor not in parent:
                    parent[successor] = current
                    queue.append(successor)
        if not found:
            continue
        reverse_path = []
        current = dispatch.serial
        while current is not None:
            reverse_path.append(current)
            current = parent[current]
        path = list(reversed(reverse_path))
        path_records.append((target, path))
        relevant.update(path)

    emit("returning_paths=%d target_blocks=%d" % (len(path_records), len(target_blocks)))
    for target, path in path_records:
        emit("path target=blk%d route=%s" % (target, ",".join(map(str, path))))

    micro_cases = switch.tail.r.c
    emit("micro_cases=%r" % (dir(micro_cases),))
    block_to_keys = {}
    for index, target in enumerate(micro_cases.targets):
        block_to_keys.setdefault(int(target), []).extend(
            int(value) for value in micro_cases.values[index]
        )
    emit(
        "micro_mapping=%s"
        % ";".join(
            "blk%d:%s" % (target, ",".join("0x%X" % value for value in values))
            for target, values in sorted(block_to_keys.items())
        )
    )

    frontier_origins = {}
    edge_origins = {}
    target_set = set(block_to_keys)
    for origin, keys in block_to_keys.items():
        queue = deque([(origin, 0)])
        seen = {origin}
        while queue:
            current, depth = queue.popleft()
            if depth > 32:
                continue
            block = mba.get_mblock(current)
            for successor_index in range(block.nsucc()):
                successor = block.succ(successor_index)
                edge_origins.setdefault((current, successor), set()).update(keys)
                if successor == dispatch.serial:
                    frontier_origins.setdefault(current, set()).update(keys)
                    continue
                if successor in (switch.serial,) or (
                    successor in target_set and successor != origin
                ):
                    continue
                if successor not in seen:
                    seen.add(successor)
                    queue.append((successor, depth + 1))
    for frontier, keys in sorted(frontier_origins.items()):
        emit(
            "frontier blk%d origins=%s preds=%s"
            % (
                frontier,
                ",".join("0x%X" % key for key in sorted(keys)),
                list(mba.get_mblock(frontier).predset),
            )
        )
        if len(keys) > 1:
            for predecessor in mba.get_mblock(frontier).predset:
                predecessor_keys = edge_origins.get((int(predecessor), frontier), set())
                emit(
                    "frontier_edge blk%d->blk%d origins=%s"
                    % (
                        predecessor,
                        frontier,
                        ",".join("0x%X" % key for key in sorted(predecessor_keys)),
                    )
                )

    path_counts = {}
    truncated_origins = []
    for origin in block_to_keys:
        if not block_to_keys[origin]:
            continue
        completed = 0
        stack = [(origin, (origin,))]
        truncated = False
        while stack:
            current, route = stack.pop()
            if len(route) > 33 or completed > 256:
                truncated = True
                break
            block = mba.get_mblock(current)
            for successor_index in range(block.nsucc()):
                successor = block.succ(successor_index)
                if successor == dispatch.serial:
                    completed += 1
                    continue
                if successor == switch.serial or (
                    successor in target_set and successor != origin
                ):
                    continue
                if successor in route:
                    truncated = True
                    continue
                stack.append((successor, route + (successor,)))
        path_counts[origin] = completed
        if truncated:
            truncated_origins.append(origin)
    emit(
        "path_count total=%d max=%d histogram=%r truncated=%s"
        % (
            sum(path_counts.values()),
            max(path_counts.values()) if path_counts else 0,
            sorted({count: list(path_counts.values()).count(count) for count in set(path_counts.values())}.items()),
            ",".join("blk%d" % origin for origin in truncated_origins),
        )
    )

    # Include all dispatcher predecessors (the exact rewrite frontier) and all
    # blocks mentioning the encoded state operands seen in the dispatcher.
    relevant.update(int(index) for index in dispatch.predset)
    relevant.update(range(0, min(23, mba.qty)))
    needles = ("var_7D0", "var_7CC", "r12d", "r14d")
    for index in range(mba.qty):
        block = mba.get_mblock(index)
        lines = block_lines(block)
        if any(needle in line for needle in needles for line in lines):
            relevant.add(index)

    for index in sorted(relevant):
        block = mba.get_mblock(index)
        emit(
            "BLOCK blk%d [%X,%X) type=%d pred=%s succ=%s"
            % (
                index,
                block.start,
                block.end,
                block.type,
                list(block.predset),
                [block.succ(i) for i in range(block.nsucc())],
            )
        )
        for line in block_lines(block):
            emit("  %s" % line)

    finish(0, "PASS")
except BaseException as error:
    finish(9, "exception: %r" % (error,))
