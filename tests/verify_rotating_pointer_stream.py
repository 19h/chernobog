#!/usr/bin/env python3
"""Verify paired IDA evidence for bounded pointer-stream string recovery."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def annotations(record):
    return [line for line in record["display"] if "rot32-xor[" in line]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", default="docs/VMP_ROTATING_POINTER_STREAM_EVIDENCE.json")
    args = parser.parse_args()
    evidence = json.loads(Path(args.evidence).read_text())
    require(evidence["schema_version"] == 1, "evidence schema")
    for name, expected in evidence["sources"].items():
        require(digest(Path(name)) == expected, "source hash: " + name)

    expected_failures = [
        "transform_words proven unit/key/bound/encoding",
        "transform_words exact cipher restoration",
        "transform_words exact native restoration",
    ]
    outputs = {}
    for name, expected in evidence["runs"].items():
        root = Path(expected["directory"])
        run_path = root / "run.json"
        capture_path = root / "string_transforms.json"
        require(digest(run_path) == expected["run_sha256"], name + " run hash")
        require(digest(capture_path) == expected["capture_sha256"], name + " capture hash")
        run = json.loads(run_path.read_text())
        capture = json.loads(capture_path.read_text())
        plugin = root / "idauser/plugins/chernobog.dylib"
        copied_probe = root / "probe/ida_string_transform_probe.py"
        fixture = (
            "vmp-string-transforms-pointer-hardened"
            if name.startswith("x64")
            else "vmp-string-transforms-pointer32-hardened"
        )
        require(digest(root / fixture) == expected["input_sha256"], name + " copied input")
        require(digest(plugin) == expected["plugin_sha256"], name + " plugin copy")
        require(
            digest(copied_probe) == evidence["sources"]["tests/ida_string_transform_probe.py"],
            name + " probe copy",
        )
        require(run["plugin_sha256"] == expected["plugin_sha256"], name + " plugin manifest")
        require(run["input_sha256"] == expected["input_sha256"], name + " input manifest")
        require(
            run["script_sha256"] == evidence["sources"]["tests/ida_string_transform_probe.py"],
            name + " script manifest",
        )
        require(
            run["process_return_code"] == expected["return_code"]
            and run["runner_return_code"] == expected["return_code"],
            name + " exit status",
        )
        require(
            run["artifacts_unchanged"]
            and run["expected_log_found"]
            and not run["internal_error_found"],
            name + " runner integrity",
        )
        require(len(capture["records"]) == 14, name + " function inventory")
        require(len(capture["checks"]) == expected["checks"], name + " check inventory")
        failures = [check["case"] for check in capture["checks"] if not check["passed"]]
        require(failures == capture["errors"], name + " check/error agreement")
        require(
            failures == (expected_failures if name == "x64_prior" else []), name + " exact failures"
        )
        records = {row["name"]: row for row in capture["records"]}
        require(len(records) == 14, name + " unique function names")
        for routine, record in records.items():
            count = len(annotations(record))
            expect = routine in {"transform_bytes", "transform_words", "transform_byte_utf16"}
            if name == "x64_prior" and routine == "transform_words":
                expect = False
            require(count == int(expect), name + " annotation: " + routine)
        word = records["transform_words"]
        mutable = records["transform_mutable_word_pointer"]
        multiple = records["transform_multiple_pointer_reads"]
        if name.startswith("x64"):
            for routine in (word, mutable):
                require(
                    "*result++" in routine["text"]
                    and any(
                        expression["op"] == "cot_postinc" for expression in routine["expressions"]
                    ),
                    name + " observed pointer shape",
                )
            require(
                any(expression["op"] == "cot_ptr" for expression in multiple["expressions"])
                and sum(expression["op"] == "cot_idx" for expression in multiple["expressions"])
                >= 3,
                name + " multiple-source-read shape",
            )
        if name == "x64_current":
            require(
                "16-bit units, key=0xA17E395B, units=5" in annotations(word)[0]
                and 'UTF-16LE candidate "VMPΩ"' in annotations(word)[0],
                "recovered exact word candidate",
            )
        require(not annotations(mutable), name + " writable source abstains")
        require(not annotations(multiple), name + " multiple-read source abstains")
        outputs[name] = capture

    for arch in ("x64", "i386"):
        a = outputs[arch + "_prior"]["records"]
        b = outputs[arch + "_current"]["records"]
        require(
            [(row["name"], row["expressions"]) for row in a]
            == [(row["name"], row["expressions"]) for row in b],
            arch + " identical decompiler expression inventory",
        )
    require(
        evidence["runs"]["x64_prior"]["input_sha256"]
        == evidence["runs"]["x64_current"]["input_sha256"],
        "paired x64 input",
    )
    require(
        evidence["runs"]["i386_prior"]["input_sha256"]
        == evidence["runs"]["i386_current"]["input_sha256"],
        "paired i386 input",
    )
    native = Path("build/vmp-string-transforms-pointer-hardened")
    require(
        digest(native) == evidence["runs"]["x64_current"]["input_sha256"],
        "executed x64 oracle binary",
    )
    require(
        subprocess.run([str(native)], check=False, timeout=10).returncode == 0,
        "native x64 plaintext oracle",
    )
    require(
        digest(Path("build/vmp-string-transforms-pointer32-hardened"))
        == evidence["runs"]["i386_current"]["input_sha256"],
        "i386 binary",
    )
    print("rotating pointer stream paired evidence PASS: x64 recovery, i386 preservation")


if __name__ == "__main__":
    main()
