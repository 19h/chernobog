"""Verify two Morok input paths against protected QEMU and IDA observations."""

import argparse
import hashlib
import json
from pathlib import Path

from verify_native_shadow_defined_flags import verify_run


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "pair_report",
        "binary",
        "second_binary",
        "shadow",
        "second_shadow",
        "first_input",
        "second_input",
        "first_ida",
        "second_ida",
        "first_runtime",
        "second_runtime",
        "other_first_ida",
        "other_second_ida",
        "other_first_runtime",
        "other_second_runtime",
        "output",
    ):
        parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    args = parser.parse_args()
    paired = json.loads(args.pair_report.read_text())
    binary_hash = sha(args.binary)
    shadow_hash = sha(args.shadow)
    assert binary_hash == sha(args.second_binary)
    assert shadow_hash == sha(args.second_shadow)
    assert paired["artifact_sha256"]["first"] == binary_hash
    assert paired["artifact_sha256"]["second"] == binary_hash
    input_hashes = [sha(args.first_input), sha(args.second_input)]
    assert input_hashes[0] != input_hashes[1]
    case_names = ("valid_v14_1", "valid_v14_0")
    case_reports = [paired["cases"][name] for name in case_names]
    output_hashes = []
    for index, case in enumerate(case_reports):
        assert case["input_sha256"] == input_hashes[index]
        assert case["input_bytes"] == len((args.first_input, args.second_input)[index].read_bytes())
        assert case["paired_equal"] and case["exit_code"] == 0
        observations = case["observations"]
        assert len(observations) == 6
        assert sorted(row["artifact"] for row in observations) == [
            "first",
            "first",
            "original",
            "original",
            "second",
            "second",
        ]
        assert all(
            row["exit_code"] == 0
            and not row["timed_out"]
            and not row["output_exceeded"]
            and row["stdout_sha256"] == case["stdout_sha256"]
            and row["stderr_sha256"] == case["stderr_sha256"]
            for row in observations
        )
        output_hashes.append(case["stdout_sha256"])
    assert output_hashes[0] != output_hashes[1]

    paths = (
        ((args.first_ida, args.first_runtime), (args.second_ida, args.second_runtime)),
        (
            (args.other_first_ida, args.other_first_runtime),
            (args.other_second_ida, args.other_second_runtime),
        ),
    )
    metrics = []
    runtime = []
    for input_index, pair in enumerate(paths):
        metrics.append([])
        runtime.append([])
        for ida_path, runtime_path in pair:
            metrics[-1].append(
                verify_run(
                    ida_path, runtime_path, binary_hash, input_hashes[input_index], shadow_hash
                )
            )
            runtime[-1].append(json.loads(runtime_path.read_text()))
    reference = runtime[0][0]
    for pair in runtime:
        for observation in pair:
            assert observation["entry_data_hex"] == reference["entry_data_hex"]
            assert observation["boundary_data_hex"] == reference["boundary_data_hex"]
            assert observation["reported_path"] == reference["reported_path"]
            assert observation["entry_packed_65536_sha256"] == shadow_hash
    assert all(
        metric["exact_gprs"] == 4094 * 16
        and metric["exact_defined_flag_bits"] == 18811
        and metric["exact_boundary_registers"] == 18
        and metric["exact_boundary_window_bytes"] == 2848
        for pair in metrics
        for metric in pair
    )
    report = {
        "schema": 1,
        "source_sha256": sha(Path(__file__)),
        "pair_report_sha256": sha(args.pair_report),
        "binary_sha256": binary_hash,
        "shadow_sha256": shadow_hash,
        "input_sha256": dict(zip(case_names, input_hashes)),
        "stdout_sha256": dict(zip(case_names, output_hashes)),
        "same_entry_data": True,
        "same_boundary_data": True,
        "same_reported_path": True,
        "same_unpacked_code": True,
        "checks_per_input": {
            name: dict(zip(("first", "second"), metrics[index]))
            for index, name in enumerate(case_names)
        },
        "total_aligned_entries": 4 * 4094,
        "total_exact_gprs": 4 * 4094 * 16,
        "total_exact_defined_flag_bits": 4 * 18811,
        "total_exact_boundary_window_bytes": 4 * 2848,
        "scope": "two completed process outputs and one bounded 4096-instruction prefix per protected run",
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
