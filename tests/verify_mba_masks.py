"""Compile captured flag updates and check values, stores, aliases and observer effects."""

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

FUNCTIONS = (
    "mba_mask_value",
    "mba_mask_overlap",
    "mba_mask_shift_signs",
    "mba_mask_store",
    "mba_mask_volatile_store",
)

ADAPTERS = """
static uint32_t captured_value(uint32_t flags, int8_t input)
{
    return mba_mask_value(flags, input);
}

static uint32_t captured_overlap(uint32_t flags, int8_t input)
{
    return mba_mask_overlap(flags, input);
}

static uint32_t captured_shifts(uint32_t value, int8_t input)
{
    return mba_mask_shift_signs(value, input);
}

static void captured_store(uint32_t *flags, int8_t input)
{
    mba_mask_store(flags, input);
}

static void captured_volatile_store(volatile uint32_t *flags, int8_t input)
{
    mba_mask_volatile_store(flags, input);
}

int main(void)
{
    return verify_functions(captured_value, captured_overlap, captured_shifts,
                            captured_store, captured_volatile_store);
}
"""


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    arguments = parser.parse_args()
    capture = json.loads(arguments.capture.read_text())
    if capture["errors"]:
        raise RuntimeError("The IDA capture contains validation errors")
    functions = {entry["name"]: entry["captures"] for entry in capture["functions"]}
    if set(functions) != set(FUNCTIONS):
        raise RuntimeError("The capture does not contain all masked flag fixtures")

    output = arguments.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    fixture = Path(__file__).resolve().parent / "vmp_native/mba_masks.c"
    compiler = (
        ["xcrun", "--sdk", "macosx", "clang"]
        if sys.platform == "darwin"
        else shlex.split(os.environ.get("CC", "cc"))
    )
    if sys.platform == "win32":
        import platform

        compiler = [
            "clang",
            "--target="
            + (
                "aarch64-pc-windows-msvc"
                if platform.machine().lower() in ("arm64", "aarch64")
                else "x86_64-pc-windows-msvc"
            ),
        ]
    if sys.platform == "win32":
        # Trap instrumentation avoids a dependency on architecture-specific
        # compiler-rt DLLs while preserving fatal checks on native Windows.
        compiler += ["-fsanitize-trap=undefined"]
    prefix = ["#define __fastcall", "#define __int8 char", "#define __int64 long long"]
    prefix.extend(f"#define {name} reference_{name}" for name in FUNCTIONS)
    prefix.extend(("#define main reference_main", f'#include "{os.path.relpath(fixture, output)}"'))
    prefix.extend(f"#undef {name}" for name in FUNCTIONS)
    prefix.append("#undef main")

    results = []
    for profile in ("normal", "deep"):
        source = output / f"{profile}.c"
        binary = output / f"{profile}.bin"
        definitions = [functions[name][profile] for name in FUNCTIONS]
        # IDA may print signed char as plain char. The adapters keep C function
        # pointer types exact; -fsigned-char preserves the captured byte values.
        source.write_text("\n".join(prefix + definitions) + ADAPTERS, encoding="utf-8")
        build = subprocess.run(
            compiler
            + [
                "-std=c11",
                "-fsigned-char",
                "-O1",
                "-fsanitize=undefined",
                "-fno-sanitize-recover=undefined",
                source.name,
                "-o",
                binary.name,
            ],
            cwd=output,
            capture_output=True,
            text=True,
        )
        (output / f"{profile}-build.log").write_text(build.stdout + build.stderr)
        build.check_returncode()
        execution = subprocess.run([str(binary)], capture_output=True, text=True)
        (output / f"{profile}-run.log").write_text(execution.stdout + execution.stderr)
        execution.check_returncode()
        match = re.search(r"Mask update comparisons: (\d+)", execution.stdout)
        if not match:
            raise RuntimeError("Missing comparison count")
        results.append(
            {
                "profile": profile,
                "comparisons": int(match[1]),
                "sanitizers": ["undefined"],
                "source_sha256": sha256(source),
                "binary_sha256": sha256(binary),
            }
        )
    report = {
        "capture_sha256": sha256(arguments.capture),
        "fixture_sha256": sha256(fixture),
        "results": results,
    }
    (output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
