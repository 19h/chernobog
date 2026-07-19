"""Headless probe for switch-dispatch CFF topology in the reference ELF."""

import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_pro
from collections import Counter, deque


TARGET_EA = 0x82AF0
DISPATCH_EA = 0x82C65


def finish(code, message):
    line = "[chernobog][cff-switch-probe] %s" % message
    print(line, flush=True)
    ida_kernwin.msg("%s\n" % line)
    ida_pro.qexit(code)


try:
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        finish(2, "Hex-Rays initialization failed")

    function = ida_funcs.get_func(TARGET_EA)
    if function is None or function.start_ea != TARGET_EA:
        finish(3, "reference function 0x%X was not discovered" % TARGET_EA)

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

    dispatch_block = None
    switch_block = None
    high_fanout = []
    for index in range(mba.qty):
        block = mba.get_mblock(index)
        if block.start <= DISPATCH_EA < block.end:
            dispatch_block = block
        if block.nsucc() >= 8:
            high_fanout.append(
                (index, block.start, block.end, block.npred(), block.nsucc())
            )
            if switch_block is None or block.nsucc() > switch_block.nsucc():
                switch_block = block

    if dispatch_block is None:
        finish(5, "dispatcher address 0x%X has no microblock" % DISPATCH_EA)
    if switch_block is None:
        finish(6, "no high-fanout switch microblock")

    def distance_to_dispatch(start, max_hops=32):
        queue = deque([(start, 0)])
        seen = {start}
        while queue:
            index, distance = queue.popleft()
            if index == dispatch_block.serial:
                return distance
            if distance >= max_hops:
                continue
            block = mba.get_mblock(index)
            for successor_index in range(block.nsucc()):
                successor = block.succ(successor_index)
                if successor not in seen:
                    seen.add(successor)
                    queue.append((successor, distance + 1))
        return None

    distances = [
        distance_to_dispatch(switch_block.succ(index))
        for index in range(switch_block.nsucc())
    ]
    returning = [distance for distance in distances if distance is not None]
    histogram = Counter(returning)
    dispatch_instructions = []
    dispatch_text = []
    instruction = dispatch_block.head
    while instruction is not None:
        dispatch_instructions.append(
            (
                instruction.opcode,
                instruction.l.t,
                instruction.r.t,
                instruction.d.t,
            )
        )
        dispatch_text.append(instruction.dstr())
        instruction = instruction.next

    finish(
        0,
        "PASS qty=%d dispatcher=blk%d[%X,%X) pred=%d succ=%d "
        "tail=%d switch=blk%d[%X,%X) switch_succ=%d returning=%d/%d "
        "distance_histogram=%r dispatch_insns=%r dispatch_text=%r "
        "high_fanout=%r"
        % (
            mba.qty,
            dispatch_block.serial,
            dispatch_block.start,
            dispatch_block.end,
            dispatch_block.npred(),
            dispatch_block.nsucc(),
            dispatch_block.tail.opcode if dispatch_block.tail else -1,
            switch_block.serial,
            switch_block.start,
            switch_block.end,
            switch_block.nsucc(),
            len(returning),
            len(distances),
            sorted(histogram.items()),
            dispatch_instructions,
            dispatch_text,
            high_fanout,
        ),
    )
except BaseException as error:
    finish(9, "exception: %r" % (error,))
