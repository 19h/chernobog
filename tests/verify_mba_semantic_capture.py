"""Compile captured semantic pseudocode and execute the original exhaustive oracle."""

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
    "mba_smt_semantic32",
    "mba_smt_quadratic",
    "mba_smt_alias",
    "mba_transform_2",
    "mba_transform_1",
    "opaque_predicate_2",
    "opaque_predicate_1",
)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    fixture = root / "tests/vmp_native/mba_smt.c"
    capture = json.loads(arguments.capture.read_text())
    if capture["errors"]:
        raise RuntimeError("The IDA capture contains validation errors")
    functions = {
        entry["name"]: {
            "normal": entry["normal_pseudocode"],
            "deep": entry["pseudocode"],
            "restored": entry["restored_pseudocode"],
        }
        for entry in capture["functions"]
    }
    missing = set(FUNCTIONS) - functions.keys()
    if missing:
        raise RuntimeError("Missing captured functions: " + ", ".join(sorted(missing)))

    output = arguments.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
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
    prefix = ["#include <stdbool.h>", "#define __fastcall", "#define __int8 char"]
    prefix.extend(("#define __int16 short", "#define __int32 int", "#define __int64 long long"))
    prefix.extend(
        (
            "typedef unsigned char _BYTE;",
            "typedef unsigned short _WORD;",
            "typedef unsigned int _DWORD;",
            "typedef unsigned long long _QWORD;",
        )
    )
    prefix.extend(f"#define {name} reference_{name}" for name in FUNCTIONS)
    prefix.extend(("#define main reference_main", f'#include "{os.path.relpath(fixture, output)}"'))
    prefix.extend(f"#undef {name}" for name in FUNCTIONS)
    prefix.append("#undef main")
    results = []
    for profile in ("normal", "deep", "restored"):
        source = output / f"{profile}.c"
        binary = output / f"{profile}.bin"
        definitions = [functions[name][profile] for name in FUNCTIONS]
        source.write_text(
            "\n".join(prefix + definitions)
            + "\nint main(void)"
            + fixture.read_text().split("int main(void)", 1)[1],
            encoding="utf-8",
        )
        build = subprocess.run(
            compiler
            + [
                "-std=c11",
                "-fsigned-char",
                "-O1",
                "-fsanitize=undefined",
                "-fno-sanitize-recover=all",
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
        match = re.search(r"MBA SMT native comparisons: (\d+)", execution.stdout)
        if not match:
            raise RuntimeError("The compiled capture did not report its comparison count")
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
        "functions": list(FUNCTIONS),
        "results": results,
    }
    (output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
