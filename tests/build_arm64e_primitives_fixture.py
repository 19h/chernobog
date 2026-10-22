"""Build synthetic ARM64e value, pointer-origin, control-flow and frame fixtures."""

import argparse
from pathlib import Path
import subprocess

VALUE_OPERATIONS = {
    **{
        name: f"{name} x0, x1"
        for name in ("pacia", "pacib", "pacda", "pacdb", "autia", "autib", "autda", "autdb")
    },
    **{
        name: f"{name} x0"
        for name in (
            "paciza",
            "pacizb",
            "pacdza",
            "pacdzb",
            "autiza",
            "autizb",
            "autdza",
            "autdzb",
            "xpaci",
            "xpacd",
        )
    },
    "pacga": "pacga x0, x1, x2",
    "pacia1716": "mov x17, x0\nmov x16, x1\npacia1716\nautia1716\nmov x0, x17",
    "pacib1716": "mov x17, x0\nmov x16, x1\npacib1716\nautib1716\nmov x0, x17",
    "ldraa": "ldraa x0, [x1, #8]",
    "ldrab": "ldrab x0, [x1, #-8]!",
    "ldraa_writeback": "ldraa x8, [x1, #8]!\nmov x0, x1",
    "ldrab_writeback": "ldrab x8, [x1, #-8]!\nmov x0, x1",
    "load_discard": "ldraa xzr, [x1]",
}

IDENTITIES = {
    "plain": ("ret", True),
    "mov64": ("mov x0, x0\nret", True),
    "mov32": ("mov w0, w0\nret", False),
    "bti_c": ("bti c\nret", True),
    "bti_jc": ("bti jc\nret", True),
    "bti_j": ("bti j\nret", False),
    "ia": ("paciasp\nretaa", True),
    "ib": ("pacibsp\nretab", True),
    "ia_explicit": ("paciasp\nautiasp\nret", True),
    "ib_explicit": ("pacibsp\nautibsp\nret", True),
    "bti_ib": ("bti c\npacibsp\nretab", True),
    "wrong_key": ("paciasp\nretab", False),
    "missing_auth": ("pacibsp\nret", False),
    "unpaired_auth": ("autibsp\nret", False),
    "wrong_modifier": ("paciaz\nretaa", False),
    "other_return": ("ret x8", False),
    "changed_result": ("pacibsp\nadd x0, x0, #1\nretab", False),
}


def flows():
    result = {}
    for name in ("braa", "brab", "braaz", "brabz", "blraa", "blrab", "blraaz", "blrabz"):
        bank_b = "ab" in name or name.startswith("brab")
        zero = name.endswith("z")
        sign = (
            ("pacizb" if bank_b else "paciza") + " x8"
            if zero
            else ("pacib" if bank_b else "pacia") + " x8, x17"
        )
        transfer = f"{name} x8" + ("" if zero else ", x17")
        result[name] = (sign, transfer, True)
    result.update(
        {
            "aut_ia": ("pacia x8, x17\nautia x8, x17", "blr x8", True),
            "aut_ib": ("pacib x8, x17\nautib x8, x17", "blr x8", True),
            "aut_da": ("pacda x8, x17\nautda x8, x17", "blr x8", True),
            "aut_db": ("pacdb x8, x17\nautdb x8, x17", "blr x8", True),
            "strip_i": ("pacia x8, x17\nxpaci x8", "blr x8", True),
            "strip_d": ("pacda x8, x17\nxpacd x8", "blr x8", True),
            "wrong_key": ("pacia x8, x17", "blrab x8, x17", False),
            "wrong_modifier": ("pacia x8, x17\nmov x17, #0x5678", "blraa x8, x17", False),
            "wrong_domain": ("pacda x8, x17", "blraa x8, x17", False),
            "wrong_strip": ("pacda x8, x17\nxpaci x8", "blr x8", False),
            "aut_wrong_key": ("pacia x8, x17\nautib x8, x17", "blr x8", False),
            "aut_wrong_modifier": (
                "pacia x8, x17\nmov x17, #0x5678\nautia x8, x17",
                "blr x8",
                False,
            ),
            "signed_plain": ("pacia x8, x17", "blr x8", False),
            "call_barrier": (
                "pacia x8, x17\nmov x19, x8\nbl _barrier\nmov x8, x19",
                "blraa x8, x17",
                False,
            ),
            "pacga_target": ("pacga x8, x8, x17", "blr x8", False),
            "nonpointer_roundtrip": (
                "mov x9, x8\nmovz x8, #0x1234, lsl #48\npacia x8, x17\nautia x8, x17\nmovz x10, #0x1234, lsl #48\neor x8, x8, x10\nadd x8, x8, x9",
                "blr x8",
                False,
            ),
            "veneer_ia": (
                "mov x16, x17\nmov x17, x8\npacia1716\nmov x8, x17\nmov x17, x16",
                "blraa x8, x17",
                True,
            ),
            "veneer_ib": (
                "mov x16, x17\nmov x17, x8\npacib1716\nmov x8, x17\nmov x17, x16",
                "blrab x8, x17",
                True,
            ),
        }
    )
    for bank in ("a", "b"):
        for offset in (-4096, -8, 0, 8, 4088):
            for writeback in (False, True):
                name = f"ldr{bank}_{'m' if offset < 0 else 'p'}{abs(offset)}_{int(writeback)}"
                body = (
                    f"adrp x9, _load_center@PAGE\nadd x9, x9, _load_center@PAGEOFF\npacd{'za' if bank == 'a' else 'zb'} x9\nldr{'aa' if bank == 'a' else 'ab'} x8, [x9, #{offset}]"
                    + ("!" if writeback else "")
                )
                body += "\npacia x8, x17"
                result[name] = (body, "blraa x8, x17", True)
    return result


def assembly():
    text = [".text\n.globl _main\n_main:\nmov w0, #0\nret"]

    def function(name, body):
        text.append(f".p2align 2\n.globl _{name}\n_{name}:\n{body}")

    for name, body in VALUE_OPERATIONS.items():
        function("value_" + name, body + "\nret")
    for name, (body, _) in IDENTITIES.items():
        function("identity_" + name, body)
    for name, (body, transfer, _) in flows().items():
        leaf_tail = transfer.startswith("br")
        prologue = (
            ""
            if leaf_tail
            else "pacibsp\nstp x29, x30, [sp, #-32]!\nmov x29, sp\nstr x19, [sp, #16]\n"
        )
        epilogue = "" if leaf_tail else "\nldr x19, [sp, #16]\nldp x29, x30, [sp], #32\nretab"
        function(
            "flow_" + name,
            prologue
            + "adrp x8, _flow_target@PAGE\nadd x8, x8, _flow_target@PAGEOFF\nmov x17, #0x1234\n"
            + body
            + "\n"
            + transfer
            + epilogue,
        )
    function("flow_target", "add x0, x0, #1\nret")
    function("barrier", "ret")
    text.append(
        ".section __DATA_CONST,__const\n.p2align 3\n.rept 512\n.quad _flow_target\n.endr\n.globl _load_center\n_load_center:\n.rept 513\n.quad _flow_target\n.endr"
    )
    return "\n".join(text) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    source = args.output.with_suffix(".s")
    source.write_text(assembly())
    subprocess.run(
        ["xcrun", "clang", "-arch", "arm64e", str(source), "-o", str(args.output)], check=True
    )


if __name__ == "__main__":
    main()
