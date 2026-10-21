"""Validate bounded, snapshot-attributed diagnostics in actual D810 captures."""

import argparse
import hashlib
import json
from pathlib import Path
import re

OUTCOMES = {
    "extraction_refused",
    "no_improvement",
    "generated",
    "generation_failed",
    "verified",
    "disproved",
    "unknown",
    "exhausted",
    "emission_rejected",
    "applied",
}
PHASES = {"core", "microcode", "calls", "memory", "control", "catalog"}
STAGES = {
    "extraction",
    "generation",
    "context_proof",
    "candidate_proof",
    "emitted_proof",
    "commit",
    "solver_query",
}


def verify(captures):
    inputs, snapshots, catalog_only, overflow = [], 0, 0, 0
    for path in captures:
        raw = path.read_bytes()
        data = json.loads(raw)
        if data["errors"]:
            raise ValueError("Capture contains decompilation failures")
        inputs.append(dict(name=path.parent.name, sha256=hashlib.sha256(raw).hexdigest()))
        for function in data["functions"]:
            for profile, capture in function["captures"].items():
                if profile == "baseline":
                    continue
                statistics = capture["statistics"]
                regions = statistics["regions"]
                events, counts = regions["events"], regions["counts"]
                if (
                    set(counts) != OUTCOMES
                    or regions["capacity"] != 32
                    or len(events) > 32
                    or any(not isinstance(n, int) or n < 0 for n in counts.values())
                    or regions["unrecorded"] < 0
                    or sum(counts.values()) != len(events) + regions["unrecorded"]
                ):
                    raise ValueError("Invalid bounded diagnostic accounting")
                if counts["applied"] != statistics["catalog_applied"] + statistics["applied"]:
                    raise ValueError("Actual catalog/semantic mutations disagree with event counts")
                for outcome, count in counts.items():
                    if sum(e["outcome"] == outcome for e in events) > count:
                        raise ValueError("Event details exceed exact outcome count")
                for event in events:
                    if (
                        event["phase"] not in PHASES
                        or event["stage"] not in STAGES
                        or event["outcome"] not in OUTCOMES
                        or not re.fullmatch(r"[0-9a-f]{16}", event["region_key"])
                        or event["generation"] < 0
                        or event["mutation_epoch"] < 0
                        or event["block"] < 0
                        or event["statement"] < 0
                        or (
                            event["source_ea"] is not None
                            and not re.fullmatch(r"0x[0-9a-fA-F]+", event["source_ea"])
                        )
                    ):
                        raise ValueError("Invalid region provenance")
                    if event["outcome"] == "applied" and event["stage"] != "commit":
                        raise ValueError("An application was recorded before commit")
                snapshots += 1
                overflow += regions["unrecorded"]
                catalog_only += int(
                    statistics["catalog_applied"] > 0 and statistics["applied"] == 0
                )
    if not snapshots:
        raise ValueError("No explicit deobfuscation snapshots")
    return dict(
        inputs=inputs,
        snapshots=snapshots,
        catalog_only_snapshots=catalog_only,
        unrecorded_events=overflow,
        detail_capacity=32,
        passed=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("captures", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = verify(args.captures)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
