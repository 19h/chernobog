"""Compare constant SDK flag operations with independent native status bits."""

import hashlib
import json
import os
from pathlib import Path

import ida_auto
import ida_hexrays as hx
import ida_idaapi
import ida_pro


def cases():
    for x in range(256):
        for y in range(256):
            yield 1, x, y
    for width in (2, 4, 8):
        mask = (1 << (width * 8)) - 1
        sign = 1 << (width * 8 - 1)
        corners = (0, 1, 2, sign - 1, sign, sign + 1, mask - 1, mask)
        for x in corners:
            for y in corners:
                yield width, x, y


def main():
    output = Path(os.environ["IDAUSR"]).parent
    result = {"passed": False, "checks": 0, "errors": []}
    try:
        ida_auto.auto_wait()
        assert hx.init_hexrays_plugin()
        native = Path(os.environ["CHERNOBOG_FLAG_NATIVE_VALUES"]).read_bytes()
        result["native_sha256"] = hashlib.sha256(native).hexdigest()
        operations = (hx.m_cfadd, hx.m_ofadd, hx.m_seto, hx.m_setp)
        names = ("cfadd", "ofadd", "seto", "setp")
        observed = bytearray()
        compared_native = bytearray()
        result["unfolded"] = {name: 0 for name in names}
        result["unfolded_examples"] = {name: [] for name in names}
        assert len(native) == 262912
        pairs = 0
        for width, x, y in cases():
            for index, opcode in enumerate(operations):
                instruction = hx.minsn_t(ida_idaapi.BADADDR)
                instruction.opcode = opcode
                instruction.l.make_number(x, width)
                instruction.r.make_number(y, width)
                instruction.d.size = 1
                for _ in range(8):
                    changed = instruction.optimize_solo()
                    if not changed or instruction.opcode == hx.m_mov:
                        break
                offset = pairs * 4 + index
                if instruction.opcode == opcode:
                    assert instruction.l.t == hx.mop_n and instruction.r.t == hx.mop_n
                    assert int(instruction.l.nnn.value) == x and int(instruction.r.nnn.value) == y
                    assert instruction.l.size == instruction.r.size == width
                    assert instruction.d.size == 1 and instruction.iprops == 0
                    name = names[index]
                    result["unfolded"][name] += 1
                    if len(result["unfolded_examples"][name]) < 8:
                        result["unfolded_examples"][name].append(
                            {"width": width, "left": x, "right": y, "sdk": instruction.dstr()}
                        )
                    continue
                assert instruction.opcode == hx.m_mov and instruction.l.t == hx.mop_n, (
                    "SDK did not fold constant flag",
                    opcode,
                    width,
                    x,
                    y,
                    int(instruction.opcode),
                    instruction.dstr(),
                )
                value = int(instruction.l.nnn.value)
                assert value in (0, 1)
                assert value == native[offset], (
                    "SDK/native flag mismatch",
                    opcode,
                    width,
                    x,
                    y,
                    value,
                    native[offset],
                )
                observed.append(value)
                compared_native.append(native[offset])
                result["checks"] += 1
            pairs += 1
        assert observed == compared_native and len(native) == 262912 and pairs == 65728
        assert result["checks"] + sum(result["unfolded"].values()) == len(native)
        result["sdk_sha256"] = hashlib.sha256(observed).hexdigest()
        result["compared_native_sha256"] = hashlib.sha256(compared_native).hexdigest()
        result["passed"] = True
    except Exception as error:
        result["errors"].append(type(error).__name__ + ": " + str(error))
    (output / "flag_values.json").write_text(json.dumps(result, indent=2) + "\n")
    print("[chernobog][flag-values] " + ("PASS" if result["passed"] else "FAIL"), flush=True)
    ida_pro.qexit(0 if result["passed"] else 1)


main()
