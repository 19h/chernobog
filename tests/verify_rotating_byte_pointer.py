#!/usr/bin/env python3
"""Verify the exact x64 byte-pointer paired IDA and native-process captures."""

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
    evidence = json.loads(Path("docs/VMP_ROTATING_BYTE_POINTER_EVIDENCE.json").read_text())
    require(evidence["schema_version"] == 1, "evidence schema")
    for name, expected in evidence["sources"].items():
        require(digest(Path(name)) == expected, "source hash: " + name)
    prior_pointer = json.loads(Path("docs/VMP_ROTATING_POINTER_STREAM_EVIDENCE.json").read_text())
    require(
        evidence["runs"]["prior"]["plugin_sha256"]
        == prior_pointer["runs"]["x64_prior"]["plugin_sha256"],
        "shared prior plugin identity",
    )
    require(
        evidence["runs"]["current"]["plugin_sha256"]
        == prior_pointer["runs"]["x64_current"]["plugin_sha256"],
        "shared current plugin identity",
    )
    expected_failures = [
        "byte_pointer_stream exact plaintext candidate",
        "byte_pointer_stream source restoration",
        "byte_pointer_stream permission restoration",
        "byte_pointer_stream code restoration",
    ]
    captures = {}
    for label, expected in evidence["runs"].items():
        root = Path(expected["directory"])
        run_file = root / "run.json"
        capture_file = root / "byte_pointer_stream.json"
        require(digest(run_file) == expected["run_sha256"], label + " run hash")
        require(digest(capture_file) == expected["capture_sha256"], label + " capture hash")
        run = json.loads(run_file.read_text())
        capture = json.loads(capture_file.read_text())
        require(
            digest(root / "vmp-byte-pointer-stream") == evidence["binary_sha256"],
            label + " copied input",
        )
        require(
            digest(root / "idauser/plugins/chernobog.dylib") == expected["plugin_sha256"],
            label + " copied plugin",
        )
        require(
            digest(root / "probe/ida_byte_pointer_stream_probe.py")
            == evidence["sources"]["tests/ida_byte_pointer_stream_probe.py"],
            label + " copied probe",
        )
        require(
            run["input_sha256"] == evidence["binary_sha256"]
            and run["plugin_sha256"] == expected["plugin_sha256"]
            and run["script_sha256"]
            == evidence["sources"]["tests/ida_byte_pointer_stream_probe.py"],
            label + " run identities",
        )
        require(
            run["process_return_code"] == expected["return_code"]
            and run["runner_return_code"] == expected["return_code"]
            and run["artifacts_unchanged"]
            and run["expected_log_found"]
            and not run["internal_error_found"],
            label + " runner result",
        )
        require(len(capture["records"]) == 2, label + " routine count")
        require(len(capture["checks"]) == 18, label + " check count")
        failures = [check["case"] for check in capture["checks"] if not check["passed"]]
        require(failures == capture["errors"], label + " check/error agreement")
        require(
            failures == (expected_failures if label == "prior" else []),
            label + " exact failures",
        )
        records = {record["name"]: record for record in capture["records"]}
        require(
            set(records) == {"byte_pointer_stream", "byte_pointer_loaded_global"},
            label + " routine inventory",
        )
        direct, loaded = records["byte_pointer_stream"], records["byte_pointer_loaded_global"]
        require(
            direct["initializer_itype"] == 92 and loaded["initializer_itype"] == 122,
            label + " LEA/MOV instruction types",
        )
        for record in (direct, loaded):
            require(
                "*result++" in record["text"]
                and sum(item["op"] == "postinc" for item in record["expressions"]) == 1
                and any(item["op"] == "ptr" for item in record["expressions"]),
                label + " byte-pointer expression: " + record["name"],
            )
        require(not annotations(loaded), label + " loaded mutable pointer abstains")
        require(len(annotations(direct)) == int(label == "current"), label + " exact positive")
        if label == "current":
            require(
                "8-bit units, key=0xA17E395B, units=9" in annotations(direct)[0]
                and 'UTF-8 candidate "VMP byte"' in annotations(direct)[0],
                "typed byte-pointer recovery",
            )
        captures[label] = capture
    require(
        [(x["name"], x["text"], x["expressions"]) for x in captures["prior"]["records"]]
        == [(x["name"], x["text"], x["expressions"]) for x in captures["current"]["records"]],
        "paired original ctree shapes",
    )
    binary = Path("build/vmp-byte-pointer-stream")
    require(digest(binary) == evidence["binary_sha256"], "native executable hash")
    require(
        subprocess.run([str(binary)], check=False, timeout=10).returncode == 0,
        "native process plaintext oracle",
    )
    print("rotating byte-pointer paired evidence PASS: x64 recovery and loaded-global abstention")


if __name__ == "__main__":
    main()
