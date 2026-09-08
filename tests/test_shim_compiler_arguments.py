"""Verify CMake/configuration flag transport to both standalone shim runners."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
CMAKE = "cmake"
CTEST = "ctest"


class ShimCompilerArgumentsTests(unittest.TestCase):
    def configure_and_capture(self, generator):
        with tempfile.TemporaryDirectory(prefix="chernobog-shim-flags-") as directory:
            temporary = Path(directory)
            recorder = temporary / "record.py"
            recorder.write_text(
                "import json, pathlib, sys\n"
                "pathlib.Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:]))\n")
            project = temporary / "CMakeLists.txt"
            project.write_text("\n".join([
                "cmake_minimum_required(VERSION 3.27)",
                "project(shim_flag_transport NONE)",
                "enable_testing()",
                "set(CMAKE_BUILD_TYPE Debug)",
                "set(CMAKE_CXX_COMPILER_ID Clang)",
                "set(CMAKE_CXX_COMPILER_ARG1 [=[--driver-mode=g++]=])",
                "set(CMAKE_CXX_FLAGS [=[-DCOMMON=1 -DTEXT=\"space;value>$<0:literal>\" -fsanitize=undefined]=])",
                "set(CMAKE_CXX_FLAGS_DEBUG [=[-Og -DDEBUG_TEXT=\"debug;value>$<0:literal>\"]=])",
                "set(CMAKE_CXX_FLAGS_RELEASE [=[-O3 -DNDEBUG]=])",
                "set(CMAKE_CXX_FLAGS_RELWITHDEBINFO \"\")",
                "set(CMAKE_CXX_COMPILER_TARGET x86_64-apple-darwin)",
                "set(CMAKE_CXX_COMPILER_EXTERNAL_TOOLCHAIN [=[/toolchain with space]=])",
                "set(CMAKE_SYSROOT [=[/generic sysroot]=])",
                "set(APPLE TRUE)",
                "set(CMAKE_SYSTEM_NAME Darwin)",
                "set(CMAKE_OSX_ARCHITECTURES x86_64)",
                "set(CMAKE_OSX_SYSROOT [=[/SDK with space]=])",
                "set(CMAKE_OSX_DEPLOYMENT_TARGET 13.3)",
                "include([=[%s]=])" % (ROOT / "cmake/ShimCompilerArguments.cmake"),
                "chernobog_shim_compiler_arguments(flags)",
                "add_test(NAME capture COMMAND [=[%s]=] [=[%s]=]" % (sys.executable, recorder),
                '  "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>.json" ${flags})',
            ]))
            build = temporary / "build"
            subprocess.run([CMAKE, "-S", str(temporary), "-B", str(build),
                            "-G", generator], check=True, capture_output=True, text=True)
            configurations = ("Debug", "Release") if "Multi-Config" in generator else ("Debug",)
            for configuration in configurations:
                subprocess.run([CTEST, "--test-dir", str(build), "-C", configuration,
                                "--output-on-failure"], check=True, capture_output=True, text=True)
                arguments = json.loads((build / (configuration + ".json")).read_text())
                # An inactive configuration contributes an empty flag value;
                # the runners must discard it, preserving every nonempty token.
                flags = [value.removeprefix("--cxx-flag=") for value in arguments
                         if value != "--cxx-flag="]
                selected = (["-Og", "-DDEBUG_TEXT=debug;value>$<0:literal>"] if configuration == "Debug"
                            else ["-O3", "-DNDEBUG"])
                self.assertEqual(flags, [
                    "--driver-mode=g++", "-DCOMMON=1", "-DTEXT=space;value>$<0:literal>",
                    "-fsanitize=undefined", *selected,
                    "--target=x86_64-apple-darwin", "--gcc-toolchain=/toolchain with space",
                    "--sysroot=/generic sysroot", "-arch", "x86_64",
                    "-isysroot", "/SDK with space", "-mmacosx-version-min=13.3",
                ])

    @unittest.skipUnless(shutil.which("ninja"), "CMake generation probe needs Ninja")
    def test_single_configuration_cmake_transport(self):
        self.configure_and_capture("Ninja")

    @unittest.skipUnless(shutil.which("ninja"), "CMake generation probe needs Ninja")
    def test_multiple_configuration_cmake_transport(self):
        self.configure_and_capture("Ninja Multi-Config")

    def test_runners_forward_each_argument_without_shell_or_retokenization(self):
        with tempfile.TemporaryDirectory(prefix="chernobog-shim-runner-flags-") as directory:
            temporary = Path(directory)
            compiler = temporary / "compiler with space"
            captured = temporary / "arguments.json"
            compiler.write_text(
                "#!%s\n" % sys.executable
                + "import json, os, pathlib, sys\n"
                + "pathlib.Path(os.environ['SHIM_ARGUMENT_REPORT']).write_text(json.dumps(sys.argv[1:]))\n"
                + "output = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])\n"
                + "output.write_text('#!/bin/sh\\nexit 0\\n')\n"
                + "output.chmod(0o755)\n")
            compiler.chmod(0o755)
            environment = dict(os.environ, SHIM_ARGUMENT_REPORT=str(captured))
            flags = ["-arch", "x86_64", "-DVALUE=space;literal$()", "-O3"]
            for runner in ("run_static_analysis_tests.py", "run_block_merge_tests.py"):
                subprocess.run([
                    sys.executable, str(ROOT / "tests" / runner),
                    "--cxx", str(compiler), "--cxx-flag=",
                    *("--cxx-flag=" + value for value in flags),
                ], check=True, env=environment, capture_output=True, text=True)
                arguments = json.loads(captured.read_text())
                self.assertEqual(arguments[5:9], flags)
                self.assertNotIn("", arguments)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--cmake", default=CMAKE)
    parser.add_argument("--ctest", default=CTEST)
    options, remaining = parser.parse_known_args()
    CMAKE, CTEST = options.cmake, options.ctest
    unittest.main(argv=[sys.argv[0], *remaining])
