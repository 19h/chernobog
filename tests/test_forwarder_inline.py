#!/usr/bin/env python3
"""Compare original native adapters with executable reconstructed caller C."""

import argparse
import json
from pathlib import Path
import platform
import re
import subprocess
import sys


def replace_function(source, name, text):
    begin = source.index("NOINLINE uint64_t " + name + "(")
    body = source.index("{", begin)
    depth = 1
    end = body + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[:begin] + text + source[end:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ida", required=True, type=Path)
    parser.add_argument("--plugin", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = root / "tests/forwarder_fixture.c"
    cc = "clang"
    command = [cc, "-O0", "-fwrapv", "-fno-stack-protector"]
    if platform.system() == "Darwin":
        cc = subprocess.check_output(["xcrun", "--find", "clang"], text=True).strip()
        sdk = subprocess.check_output(
            ["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True
        ).strip()
        command = [cc, *command[1:], "-isysroot", sdk]
    target = ["-arch", "x86_64"] if platform.system() == "Darwin" else []
    fixture, reference = output / "fixture", output / "reference"
    subprocess.run([*command, *target, str(source), "-o", str(fixture)], check=True)
    subprocess.run([*command, str(source), "-o", str(reference)], check=True)
    expected = subprocess.check_output([str(reference)], text=True)
    assert subprocess.check_output([str(fixture)], text=True) == expected
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
            "--set",
            "CHERNOBOG_DEBUG=1",
            str(fixture),
            str(root / "tests/ida_forwarder_probe.py"),
        ],
        check=True,
        cwd=root,
    )
    report = json.loads((run / "forwarder.json").read_text())
    recovered_source = source.read_text()
    for name in ("forward_caller", "negative_caller"):
        text = re.sub(r"\b(?:input|a[0-9]+|a|b):\s*", "", report["pseudocode"][name])
        recovered_source = replace_function(recovered_source, name, text)
    recovered_source = (
        "#define __fastcall\n#define __int64 long long\ntypedef unsigned long long _QWORD;\n"
        + recovered_source
    )
    recovered_c, recovered = output / "recovered.c", output / "recovered"
    recovered_c.write_text(recovered_source)
    subprocess.run([*command, str(recovered_c), "-o", str(recovered)], check=True)
    actual = subprocess.check_output([str(recovered)], text=True, timeout=10)
    assert actual == expected, "native adapter and recovered caller outcomes differ"
    report.update(
        native_outcomes_equal=True,
        input_cases=len(actual.splitlines()),
        outcomes=actual.splitlines(),
    )
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        "PASS: original native adapters and reconstructed callers agree on %d cases"
        % len(actual.splitlines())
    )


if __name__ == "__main__":
    main()
