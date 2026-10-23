#!/usr/bin/env python3
"""Compare native and reconstructed table-argument code over the complete byte domain."""

import argparse
from pathlib import Path
import platform
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ida", required=True, type=Path)
    parser.add_argument("--plugin", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = root / "tests/finite_table_arguments_fixture.c"
    compiler = ["clang", "-O0", "-fno-stack-protector"]
    if platform.system() == "Darwin":
        compiler[0] = subprocess.check_output(["xcrun", "--find", "clang"], text=True).strip()
        sdk = subprocess.check_output(
            ["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True
        ).strip()
        compiler += ["-isysroot", sdk]
    fixture = output / "fixture"
    reference = output / "reference"
    subprocess.run(compiler + [str(source), "-o", str(reference)], check=True)
    architecture = ["-arch", "x86_64"] if platform.system() == "Darwin" else []
    subprocess.run(compiler + architecture + [str(source), "-o", str(fixture)], check=True)
    run = output / "ida"
    subprocess.run(
        [
            sys.executable,
            str(root / "tests/run_ida_smoke.py"),
            "--ida",
            str(args.ida),
            "--plugin",
            str(args.plugin),
            "--output-dir",
            str(run),
            str(fixture),
            str(root / "tests/ida_finite_table_arguments_probe.py"),
        ],
        check=True,
        cwd=root,
    )
    recovered = output / "recovered"
    subprocess.run(
        compiler + ["-DRECOVERED", "-I", str(run), str(source), "-o", str(recovered)], check=True
    )
    expected = subprocess.check_output([str(reference)], text=True)
    actual = subprocess.check_output([str(recovered)], text=True)
    assert expected == actual, "Reconstructed call arguments changed native outcomes"
    (output / "outcomes.txt").write_text(actual)
    print("PASS: all 256 inputs agree, including mutable tables and two effectful calls")


if __name__ == "__main__":
    main()
