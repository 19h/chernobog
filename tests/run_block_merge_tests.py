#!/usr/bin/env python3
"""Compile and verify the production block-merge detector without Hex-Rays.

The unmodified source is copied next to a minimal counted interface shim.
The frozen old algorithm is compiled as an independent differential oracle.
This verifies algorithmic equivalence, not SDK ABI compatibility.
"""

import argparse
import os
from pathlib import Path
import shlex
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path,
                        default=root / "src/deobf/handlers/block_merge.cpp")
    parser.add_argument("--cxx", type=Path)
    parser.add_argument("--cxx-flag", action="append", default=[],
                        help="One compiler argument; repeat as --cxx-flag=<token>")
    parser.add_argument("--sanitize", action="store_true")
    parser.add_argument("--benchmark", action="store_true",
                        help="Emit CSV measurements after equivalence tests pass")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="chernobog-block-merge-tests-") as directory:
        temporary = Path(directory)
        (temporary / "block_merge.cpp").write_bytes(args.source.read_bytes())
        (temporary / "block_merge.h").write_text('#include "block_merge_ida_stub.hpp"\n')
        executable = temporary / "block_merge_tests"
        compiler = ([str(args.cxx)] if args.cxx is not None
                    else shlex.split(os.environ.get("CXX", "c++")))
        command = compiler + [
            "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
        ] + [flag for flag in args.cxx_flag if flag] + [
            "-I", str(root / "tests"),
            str(temporary / "block_merge.cpp"),
            str(root / "tests/block_merge_reference.cpp"),
            str(root / "tests/block_merge_tests.cpp"),
            "-o", str(executable),
        ]
        if args.sanitize:
            command += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        subprocess.run(command, check=True)
        return subprocess.run([str(executable)]
                              + (["--benchmark"] if args.benchmark else [])).returncode


if __name__ == "__main__":
    raise SystemExit(main())
