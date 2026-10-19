"""Compile captured caller pseudocode and compare it with the native fixtures."""

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

UNARY = (
    "mba_context_old_value",
    "mba_context_symbolic_identity",
    "mba_context_symbolic_selector",
    "mba_context_nested_calls",
    "mba_context_symbolic_add",
    "mba_context_symbolic_shift",
    "mba_context_symbolic_signed",
    "mba_context_guard_overflow",
)
BINARY = (
    "mba_context_return_range",
    "mba_context_known_bits",
    "mba_context_empty_branch",
    "mba_context_branch_equal",
    "mba_context_false_edge",
    "mba_context_join_equal",
    "mba_context_join_different",
    "mba_context_overwrite",
    "mba_context_symbolic_xor",
    "mba_context_symbolic_byte_math",
)
POINTER = "mba_context_effectful_argument"
FUNCTIONS = UNARY + BINARY + (POINTER,)

HARNESS = r"""
static unsigned long long comparisons;

#define CHECK_CALL(name, ...)                                                    \
    do                                                                          \
    {                                                                           \
        mba_call_effects = seed;                                                 \
        uint64_t expected = reference_##name(__VA_ARGS__);                       \
        uint32_t expected_effects = mba_call_effects;                             \
        mba_call_effects = seed;                                                 \
        uint64_t actual = name(__VA_ARGS__);                                     \
        if (actual != expected || mba_call_effects != expected_effects)          \
        {                                                                       \
            fprintf(stderr, #name " mismatch at x=%08x y=%08x\n", x, y);         \
            return 1;                                                           \
        }                                                                       \
        ++comparisons;                                                          \
    } while (0)

static int check_values(uint32_t x, uint32_t y)
{
    const uint32_t seed = x ^ y ^ UINT32_C(0xD5134B77);
    @CHECKS@

    uint32_t expected_memory = x;
    uint32_t actual_memory = x;
    mba_call_effects = seed;
    uint64_t expected = reference_mba_context_effectful_argument(&expected_memory);
    uint32_t expected_effects = mba_call_effects;
    mba_call_effects = seed;
    uint64_t actual = mba_context_effectful_argument(&actual_memory);
    if (actual != expected || expected_memory != actual_memory ||
        mba_call_effects != expected_effects)
    {
        fprintf(stderr, "effectful argument mismatch at x=%08x\n", x);
        return 1;
    }
    ++comparisons;
    return 0;
}

int main(void)
{
    for (uint32_t x = 0; x < 256; ++x)
    {
        for (uint32_t y = 0; y < 256; ++y)
        {
            if (check_values(x, y))
                return 1;
        }
    }

    static const uint32_t boundaries[] = {
        0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF
    };
    for (unsigned i = 0; i < sizeof(boundaries) / sizeof(boundaries[0]); ++i)
    {
        for (unsigned j = 0; j < sizeof(boundaries) / sizeof(boundaries[0]); ++j)
        {
            if (check_values(boundaries[i], boundaries[j]))
                return 1;
        }
    }

    uint32_t state = UINT32_C(0xBA513C77);
    for (unsigned i = 0; i < 10000; ++i)
    {
        state = state * UINT32_C(1664525) + UINT32_C(1013904223);
        uint32_t x = state;
        state = state * UINT32_C(1664525) + UINT32_C(1013904223);
        if (check_values(x, state))
            return 1;
    }
    printf("Captured caller comparisons: %llu\n", comparisons);
    return 0;
}
"""


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
    functions = {entry["name"]: entry["captures"] for entry in capture["functions"]}
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
    checks = [f"CHECK_CALL({name}, x);" for name in UNARY]
    checks.extend(f"CHECK_CALL({name}, x, y);" for name in BINARY)
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
    for profile in ("normal", "deep"):
        source = output / f"{profile}.c"
        binary = output / f"{profile}.bin"
        definitions = [functions[name][profile] for name in FUNCTIONS]
        source.write_text(
            "\n".join(prefix + definitions) + HARNESS.replace("@CHECKS@", "\n    ".join(checks)),
            encoding="utf-8",
        )
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
        match = re.search(r"Captured caller comparisons: (\d+)", execution.stdout)
        if not match:
            raise RuntimeError("The compiled capture did not report its comparison count")
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
        "functions": list(FUNCTIONS),
        "results": results,
    }
    (output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
