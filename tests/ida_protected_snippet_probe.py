"""Inspect bounded raw-code snippets without creating function owners."""

import hashlib
import json
import os
from pathlib import Path
import sys

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays as hx
import ida_ida
import ida_idaapi
import ida_loader
import ida_pro
import ida_range
import ida_segment
import ida_ua
import idautils

sys.dont_write_bytecode = True


def inventory():
    digest = hashlib.sha256()
    total = heads = references = 0

    def add(value):
        digest.update(json.dumps(value, separators=(",", ":")).encode())
        digest.update(b"\n")

    for index in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(index)
        size = int(segment.end_ea - segment.start_ea)
        total += size
        assert total <= 64 * 1024 * 1024
        add((int(segment.start_ea), int(segment.end_ea), int(segment.bitness), int(segment.perm)))
        for part in ida_bytes.get_bytes_and_mask(segment.start_ea, size) or (b"unloaded",):
            digest.update(part)
        for ea in idautils.Heads(segment.start_ea, segment.end_ea):
            heads += 1
            assert heads <= 1048576
            function = ida_funcs.get_func(ea)
            add(
                (
                    ea,
                    int(ida_bytes.get_full_flags(ea)),
                    int(ida_bytes.get_item_end(ea)),
                    None if function is None else int(function.start_ea),
                    ida_bytes.get_cmt(ea, True),
                    ida_bytes.get_cmt(ea, False),
                )
            )
            refs = sorted(
                (int(r.frm), int(r.to), int(r.type), bool(r.iscode), bool(r.user))
                for r in idautils.XrefsFrom(ea)
            )
            references += len(refs)
            assert references <= 2097152
            add(refs)
    functions = list(idautils.Functions())
    assert len(functions) <= 4096
    for ea in functions:
        add((ea, list(idautils.Chunks(ea))))
    add(list(idautils.Names()))
    return {
        "sha256": digest.hexdigest(),
        "heads": heads,
        "references": references,
        "functions": len(functions),
        "segment_bytes": total,
    }


report = {
    "schema": 1,
    "passed": False,
    "errors": [],
    "entries": [],
    "scope": "bounded linear prefixes; existing code heads and SDK source sites; not whole-body, value, flag or fault equivalence",
}
try:
    assert ida_loader.load_plugin(os.environ["CHERNOBOG_PLUGIN_PATH"])
    ida_auto.auto_wait()
    ida_auto.auto_wait()
    assert hx.init_hexrays_plugin()
    report["architecture"] = "x86_64" if ida_ida.inf_is_64bit() else "i386"
    entries = json.loads(os.environ["CHERNOBOG_MBA_CORPUS_ENTRIES"])
    assert set(entries) == {"corpus_transform", "corpus_branch"}
    report["inventory_before"] = inventory()
    for name, raw in entries.items():
        entry = int(raw, 0)
        ins = ida_ua.insn_t()
        assert ida_ua.decode_insn(ins, entry) > 0
        assert ins.get_canon_mnem() != "jmp" or ins.Op1.type == ida_ua.o_near
        target = int(ins.Op1.addr) if ins.get_canon_mnem() == "jmp" else entry
        cursor, native = target, []
        for _ in range(16):
            ins = ida_ua.insn_t()
            size = ida_ua.decode_insn(ins, cursor)
            if not 0 < size <= 15 or cursor + size - target > 128:
                break
            mnemonic = ins.get_canon_mnem()
            flags = ida_bytes.get_full_flags(cursor)
            native.append(
                {
                    "ea": cursor,
                    "bytes": ida_bytes.get_bytes(cursor, size).hex(),
                    "size": size,
                    "mnemonic": mnemonic,
                    "code_head": bool(ida_bytes.is_code(flags) and ida_bytes.is_head(flags)),
                }
            )
            cursor += size
            if mnemonic.startswith(("j", "ret", "call")):
                break
        assert cursor > target
        function = ida_funcs.get_func(target)
        row = {
            "name": name,
            "entry": entry,
            "target": target,
            "end": cursor,
            "owner": None if function is None else int(function.start_ea),
            "native": native,
            "stages": [],
        }
        report["entries"].append(row)
        for maturity in [hx.MMAT_GENERATED, hx.MMAT_PREOPTIMIZED, hx.MMAT_LOCOPT, hx.MMAT_GLBOPT1]:
            ranges = hx.mba_ranges_t()
            ranges.ranges.push_back(ida_range.range_t(target, cursor))
            failure = hx.hexrays_failure_t()
            mba = hx.gen_microcode(
                ranges, failure, None, hx.DECOMP_NO_CACHE | hx.DECOMP_ALL_BLKS, maturity
            )
            stage = {"maturity": int(maturity), "blocks": []}
            row["stages"].append(stage)
            if mba is None:
                stage.update(
                    status="sdk_refused", error_code=int(failure.code), error_ea=int(failure.errea)
                )
                continue
            mba.verify(True)
            for index in range(mba.qty):
                block, items = mba.get_mblock(index), []
                instruction = block.head
                while instruction is not None:
                    items.append([int(instruction.ea), instruction.dstr()])
                    instruction = instruction.next
                stage["blocks"].append({"index": index, "instructions": items})
            stage["status"] = "captured"
            stage["source_eas"] = sorted({i[0] for b in stage["blocks"] for i in b["instructions"]})
        row["native_code_heads"] = sum(n["code_head"] for n in native)
        row["native_bytes_unchanged"] = all(
            ida_bytes.get_bytes(n["ea"], n["size"]).hex() == n["bytes"] for n in native
        )
        assert row["native_bytes_unchanged"]
    report["inventory_after"] = inventory()
    assert report["inventory_before"] == report["inventory_after"], "snippet changed inventory"
    report["passed"] = True
except BaseException as error:
    report["errors"].append(type(error).__name__ + ": " + str(error))
(Path(os.environ["IDAUSR"]).parent / "protected_snippet.json").write_text(
    json.dumps(report, indent=2) + "\n"
)
print("[chernobog][protected-snippet] " + ("PASS" if report["passed"] else "FAIL"), flush=True)
ida_pro.qexit(0 if report["passed"] else 2)
