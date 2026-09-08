#!/usr/bin/env python3
"""Compile the production static adapter against a counted IDA interface shim.

No IDA installation or rax/Z3 linking is needed. The decoder, image byte-view,
and SMIR negotiation policies are the production implementations. This suite
tests traversal behavior, not compatibility of the shim with the IDA ABI.
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
    parser.add_argument("--static-analysis-source", type=Path,
                        default=root / "src/hybrid/static_analysis.cpp",
                        help="Alternate production source for regression falsification")
    parser.add_argument("--sanitize", action="store_true")
    parser.add_argument("--cxx", type=Path,
                        help="Exact compiler executable; otherwise use CXX or c++")
    parser.add_argument("--cxx-flag", action="append", default=[],
                        help="One compiler argument; repeat as --cxx-flag=<token>")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="chernobog-static-tests-") as directory:
        temporary = Path(directory)
        # The adapter includes these SDK headers. The shim owns only this
        # temporary include directory, never the SDK or production include path.
        for name in ("pro.h", "ida.hpp", "idp.hpp", "ua.hpp", "bytes.hpp",
                     "xref.hpp", "segregs.hpp", "kernwin.hpp"):
            (temporary / name).write_text(
                '#include "static_analysis_ida_stub.hpp"\n')
        executable = temporary / "static_analysis_tests"
        compiler = ([str(args.cxx)] if args.cxx is not None
                    else shlex.split(os.environ.get("CXX", "c++")))
        command = compiler + [
            "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
        ] + [flag for flag in args.cxx_flag if flag] + [
            "-I", str(temporary), "-I", str(root / "tests"),
            "-I", str(root / "src"), "-I", str(root / "src/hybrid"),
            "-I", str(root / "vendor/rax/capi/include"),
            str(root / "tests/static_analysis_tests.cpp"),
            str(args.static_analysis_source),
            str(root / "src/hybrid/decoder_core.cpp"),
            str(root / "src/hybrid/program_model_core.cpp"),
            str(root / "src/hybrid/smir_analysis.cpp"),
            "-o", str(executable),
        ]
        if args.sanitize:
            command += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        subprocess.run(command, check=True)
        return subprocess.run([str(executable)]).returncode


if __name__ == "__main__":
    raise SystemExit(main())
