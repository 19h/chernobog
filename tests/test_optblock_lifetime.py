#!/usr/bin/env python3
"""Regress arm64 select threading and compare recovered C on signed boundary inputs."""

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
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        parser.error("this regression requires an arm64 macOS host")
    root = Path(__file__).resolve().parent.parent
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = root / "tests/optblock_lifetime_fixture.c"
    compiler = ["xcrun", "clang", "-O2", "-g"]
    fixture = output / "fixture"
    subprocess.run(compiler + [str(source), "-o", str(fixture)], check=True)
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
            str(root / "tests/ida_optblock_lifetime_probe.py"),
        ],
        check=True,
        cwd=root,
    )
    recovered = output / "recovered"
    subprocess.run(
        compiler + ["-DRECOVERED", "-I", str(run), str(source), "-o", str(recovered)], check=True
    )
    expected = subprocess.check_output([str(fixture)], text=True)
    actual = subprocess.check_output([str(recovered)], text=True)
    assert len(expected.splitlines()) == 64
    assert expected == actual, "Recovered select threading changed native outcomes"
    (output / "outcomes.txt").write_text(actual)
    print("PASS: repeated decompilation and all 64 signed boundary input pairs agree")


if __name__ == "__main__":
    main()
