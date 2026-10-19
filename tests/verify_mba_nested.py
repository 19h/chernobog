"""Compile captured nested MBA pseudocode and check its full-width return values."""

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
    "mba_nested_1",
    "mba_nested_2",
    "mba_nested_3",
    "mba_nested_combined",
    "mba_nested_solve",
    "mba_nested_caller",
)


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
        raise RuntimeError("The capture does not contain all six nested MBA fixtures")

    output = arguments.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    fixture = Path(__file__).resolve().parent / "vmp_native/mba_nested.c"
    compiler = (
        ["xcrun", "--sdk", "macosx", "clang"]
        if sys.platform == "darwin"
        else shlex.split(os.environ.get("CC", "cc"))
    )
    prefix = ["#define __fastcall", "#define __int64 long long"]
    prefix.extend(f"#define {name} reference_{name}" for name in FUNCTIONS)
    prefix.extend(("#define main reference_main", f'#include "{os.path.relpath(fixture, output)}"'))
    prefix.extend(f"#undef {name}" for name in FUNCTIONS)
    prefix.append("#undef main")
    harness = (
        "\nint main(void)\n{\n"
        "    const mba_function functions[] = {" + ", ".join(FUNCTIONS) + "};\n"
        "    return verify_functions(functions);\n}\n"
    )

    results = []
    for profile in ("normal", "deep"):
        source = output / f"{profile}.c"
        binary = output / f"{profile}.bin"
        definitions = [functions[name][profile] for name in FUNCTIONS]
        source.write_text("\n".join(prefix + definitions) + harness, encoding="utf-8")
        build = subprocess.run(
            compiler + ["-std=c11", "-O1", source.name, "-o", binary.name],
            cwd=output,
            capture_output=True,
            text=True,
        )
        (output / f"{profile}-build.log").write_text(build.stdout + build.stderr)
        build.check_returncode()
        execution = subprocess.run([str(binary)], capture_output=True, text=True)
        (output / f"{profile}-run.log").write_text(execution.stdout + execution.stderr)
        execution.check_returncode()
        match = re.search(r"Nested MBA comparisons: (\d+)", execution.stdout)
        if not match:
            raise RuntimeError("Missing differential comparison count")
        results.append(
            {
                "profile": profile,
                "comparisons": int(match[1]),
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
