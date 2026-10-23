#!/usr/bin/env python3
"""Compile and execute original and recovered aliased-dispatch fixture code."""

import argparse
import json
from pathlib import Path
import platform
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ida", required=True, type=Path)
    parser.add_argument("--plugin", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--cc")
    parser.add_argument("--stack-alias-objects", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    fixture = output / "fixture"
    reference = output / "reference"
    source = root / "tests/hikari_dispatch_fixture.c"
    cc = args.cc
    if cc is None:
        cc = (
            subprocess.check_output(["xcrun", "--find", "clang"], text=True).strip()
            if platform.system() == "Darwin"
            else "clang"
        )
    compiler = [cc, "-O0", "-fwrapv", "-fno-stack-protector"]
    if platform.system() == "Darwin":
        sdk = subprocess.check_output(
            ["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True
        ).strip()
        compiler += ["-isysroot", sdk]
    subprocess.run(compiler + [str(source), "-o", str(reference)], check=True)
    target = ["-arch", "x86_64"] if platform.system() == "Darwin" else []
    subprocess.run(compiler + target + [str(source), "-o", str(fixture)], check=True)
    run = output / "ida"
    command = [
        sys.executable,
        str(root / "tests/run_ida_smoke.py"),
        "--ida",
        str(args.ida),
        "--plugin",
        str(args.plugin),
        "--output-dir",
        str(run),
        str(fixture),
        str(root / "tests/ida_hikari_dispatch_probe.py"),
    ]
    if args.stack_alias_objects:
        command += ["--set", "CHERNOBOG_STACK_ALIAS_OBJECTS=1"]
    subprocess.run(command, check=True, cwd=root)
    recovered = output / "recovered"
    subprocess.run(compiler + [str(run / "recovered.c"), "-o", str(recovered)], check=True)
    expected = subprocess.check_output([str(reference)], text=True)
    actual = subprocess.check_output([str(recovered)], text=True, timeout=10)
    assert expected == actual, "recovered pseudocode changed fixture outcomes"
    report = json.loads((run / "hikari_dispatch.json").read_text())
    report["native_outcomes_equal"] = True
    report["input_cases"] = len(actual.splitlines())
    report["outcomes"] = actual.splitlines()
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: recovered C matches all %d input cases" % len(actual.splitlines()))


if __name__ == "__main__":
    main()
