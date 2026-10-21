"""Compile captured CFG replacements and independently check their result values.

Random input bounds [-10000, 10000] avoid signed C overflow in retained source
arithmetic. The SDK trace certificates cover the full typed bit-vector domain.
The helper/TEB fixture uses a controlled readable object, never a native TEB.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ARITY = {
    "abc_f6_add_dispatch": 1,
    "abc_f6_sub_dispatch": 1,
    "abc_f6_xor_dispatch": 1,
    "abc_f6_or_dispatch": 1,
    "abc_f6_nested": 2,
    "abc_f6_64bit_pattern": 1,
    "abc_or_dispatch": 1,
    "abc_mixed_dispatch": 2,
    "nested_simple": 1,
    "single_iteration_simple": 1,
    "single_iteration_complex": 2,
    "single_iteration_conditional": 1,
    "single_iteration_nested": 2,
    "single_iteration_residual": 1,
    "single_iteration_magic": 1,
    "single_iteration_multi_pred": 1,
    "single_iteration_chained": 1,
    "single_iteration_boundary": 1,
    "single_iteration_state_machine": 1,
    "while_switch_flattened": 0,
}
REFERENCES = {
    "abc_f6_add_dispatch": "uint32_t(2*a <= 50 ? -2*a : 2*a)",
    "abc_f6_sub_dispatch": "uint32_t((a+10)*3 <= 100 ? ((a+10)*3)/2 : (a+10)*3)",
    "abc_f6_xor_dispatch": "uint32_t((uint32_t(a)^255u)+32u)",
    "abc_f6_or_dispatch": "uint32_t(a)|255u",
    "abc_f6_nested": "uint32_t(a>0 ? (b>0 ? a+b : a-b) : (b>0 ? b-a : b+a))",
    "abc_f6_64bit_pattern": "uint32_t((uint32_t(a)+1u)*2u)",
    "abc_or_dispatch": "uint32_t((uint32_t(a)+10u)*3u-5u)",
    "abc_mixed_dispatch": "b ? (uint32_t(a)|0x87654321u) : ((uint32_t(a)^0x12345678u)|0x87654321u)",
    "nested_simple": "uint32_t(a+75)",
    "single_iteration_simple": "uint32_t(a)+10u",
    "single_iteration_complex": "uint32_t(2*(a+b)-5)",
    "single_iteration_conditional": "uint32_t(a+(a<=0 ? 200 : 100))",
    "single_iteration_nested": "uint32_t(a<=0 ? a*b : b<=0 ? a-b : a+b)",
    "single_iteration_residual": "uint32_t((a+5)*2)",
    "single_iteration_magic": "uint32_t(a)+777u",
    "single_iteration_multi_pred": "uint32_t(10*a)",
    "single_iteration_chained": "uint32_t((a+10)*2)",
    "single_iteration_boundary": "uint32_t(a)+42u",
    "single_iteration_state_machine": "uint32_t(a>0 ? a+999 : 0)",
}


def types(text):
    for before, after in (
        ("unsigned __int64", "uint64_t"),
        ("unsigned __int32", "uint32_t"),
        ("__int64", "int64_t"),
        ("__int32", "int32_t"),
        ("_DWORD", "uint32_t"),
        ("_QWORD", "uint64_t"),
        ("_BOOL8", "bool"),
        ("__fastcall", ""),
    ):
        text = text.replace(before, after)
    return re.sub(r"//[^\n]*", "", text)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("captures", nargs="*", type=Path)
    parser.add_argument("--sdk", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cxx", default=os.environ.get("CXX", "c++"))
    args = parser.parse_args()
    source = r"""
#include <cstdint>
#include <cstdio>
uint64_t __ROL8__(uint64_t x,unsigned n) { return (x<<n)|(x>>(64-n)); }
uint64_t mock_value;
uint64_t *mock_pointer=&mock_value;
void *NtCurrentTeb_0() { return &mock_pointer; }
void *NtCurrentTeb() { return &mock_pointer; }
uintptr_t controlled_teb_base(unsigned offset) { return uintptr_t(&mock_pointer)-offset; }
"""
    checks = []
    hashes = []
    fixtures = 0
    for capture in args.captures:
        raw = capture.read_bytes()
        captured = json.loads(raw)
        hashes.append({"binary": captured["binary"], "sha256": hashlib.sha256(raw).hexdigest()})
        for function in captured["functions"]:
            name = function["name"]
            if name not in ARITY:
                continue
            for profile, result in function["captures"].items():
                if profile not in ("normal", "deep"):
                    continue
                text = result["text"]
                if any(re.search(r"\b" + op + r"\s*\(", text) for op in ("while", "for", "switch")):
                    raise RuntimeError("Unresolved required CFG fixture: " + name)
                emitted = "captured_" + str(fixtures)
                text = re.sub(r"\b" + name + r"\b", emitted, types(text))
                if name == "while_switch_flattened":
                    text = re.sub(
                        r"sub_[0-9A-Fa-f]+\(\)\s*\+\s*(\d+)", r"controlled_teb_base(\1) + \1", text
                    )
                source += text + "\n"
                fixtures += 1
                arity = ARITY[name]
                call = emitted + "(" + ",".join(("a", "b")[:arity]) + ")"
                if name == "while_switch_flattened":
                    # A sign-extended 32-bit negative word must reach the wide
                    # XOR unchanged. Set the observed value to the exact result.
                    reference = "1u"
                    # Frozen inputs have distinct global XOR constants. The
                    # PE input uses 0xCC8CAC2CD812A432; Mach-O uses
                    # 0xCD455C2CD812A432. Bind the readable object accordingly.
                    expected = {
                        "libobfuscated.dll": 0x842DBD9A,
                        "libobfuscated.dylib": 0x6E2DBD9A,
                    }.get(captured["binary"])
                    if expected is None:
                        raise RuntimeError("Unknown opaque-helper reference input")
                    setup = f"mock_value={expected}u;"
                else:
                    reference = REFERENCES[name]
                    setup = ""
                checks.append(f"""{setup}
 if(uint64_t({call})!=uint64_t({reference})) {{
 std::fprintf(stderr,"Mismatch {name}/{profile} a=%d b=%d\\n",a,b);return 1;}}
 ++checked;""")
    literals = []
    if args.sdk:
        raw = args.sdk.read_bytes()
        hashes.append({"sdk_sha256": hashlib.sha256(raw).hexdigest()})
        literals = json.loads(raw).get("literals", [])
        if len(literals) != 3 or any(row["code"] for row in literals):
            raise RuntimeError("Missing dual-proved SDK literal probes")
        for row in literals:
            checks.append(f"""if(uint64_t({types(row['text'])})!=UINT64_C({row['expected64']}))
 {{std::fprintf(stderr,"Incorrect signed literal widening\\n");return 1;}} ++checked;""")
    if not checks:
        raise RuntimeError("No emitted output to validate")
    source += "\nint main(){unsigned checked=0;uint64_t random=0x5214B1C6u;\n"
    source += "for(unsigned sample=0;sample<512;++sample){\n"
    source += "random=random*6364136223846793005ull+1;int a=int((random>>16)%20001)-10000;\n"
    source += "random=random*6364136223846793005ull+1;int b=int((random>>16)%20001)-10000;\n"
    source += "\n".join(checks)
    source += '\n}std::printf("checks=%u\\n",checked);return 0;}\n'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=args.output.parent) as directory:
        cpp, executable = Path(directory) / "oracle.cpp", Path(directory) / "oracle"
        cpp.write_text(source)
        subprocess.run(
            [
                args.cxx,
                "-std=c++17",
                "-O1",
                "-fsanitize=undefined",
                "-fno-sanitize-recover=undefined",
                str(cpp),
                "-o",
                str(executable),
            ],
            check=True,
        )
        result = subprocess.run([str(executable)], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
    report = {
        "inputs": hashes,
        "fixtures": fixtures,
        "signed_literals": len(literals),
        "input_min": -10000,
        "input_max": 10000,
        "ubsan": True,
        "oracle_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "result": result.stdout.strip(),
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
