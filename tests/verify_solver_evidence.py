#!/usr/bin/env python3
"""Replay complete recorded formulas and SAT assignments in a standalone Z3."""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path


def solve(solver, formula, bindings=""):
    # The producer is Z3's own SMT-LIB serializer. Only declarations, assertions,
    # metadata and checks belong in this replay format; no external file inputs.
    if re.search(r"\((?:include|set-option|eval|echo|reset|push|pop)\b", formula):
        raise AssertionError("unsupported replay command")
    body = re.sub(r"(?m)^\s*\(check-sat\)\s*$", "", formula)
    result = subprocess.run([solver, "-in", "-smt2", "-T:5"],
                            input=body + "\n" + bindings + "\n(check-sat)\n",
                            text=True, capture_output=True, timeout=10)
    replies = [line.strip() for line in result.stdout.splitlines()
               if line.strip() in ("sat", "unsat", "unknown")]
    if result.returncode or len(replies) != 1 or "(error" in result.stdout:
        raise AssertionError("standalone solver did not return one result")
    return replies[0]


def assignment(row, flip_first=False):
    lines = []
    count = int(row["model_constants"]) - int(row["model_constants_omitted"])
    for index in range(count):
        symbol, value = row[f"model_{index}_symbol"], row[f"model_{index}_value"]
        if not re.fullmatch(r"[A-Za-z0-9_:.!\-]+", symbol):
            raise AssertionError("unsupported model identifier")
        if not re.fullmatch(r"#x[0-9a-fA-F]+|#b[01]+|true|false", value):
            raise AssertionError("unsupported model literal")
        if flip_first and index == 0:
            if value.startswith("#x"):
                value = "#x" + format(int(value[2:], 16) ^ 1, f"0{len(value)-2}x")
            elif value.startswith("#b"):
                value = "#b" + format(int(value[2:], 2) ^ 1, f"0{len(value)-2}b")
            else:
                value = "false" if value == "true" else "true"
        lines.append(f"(assert (= |{symbol}| {value}))")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--solver", default=shutil.which("z3"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.solver:
        parser.error("standalone Z3 is unavailable")
    data = json.loads(args.report.read_text())
    assert not data["errors"] and all(c["passed"] for c in data["checks"])
    rows = [r for capture in data["captures"].values() for r in capture["records"]]
    formula_checks = model_checks = skipped = 0
    counterexamples = []
    corruption_checked = False
    for row in rows:
        if row.get("formula_complete") != "true" or row["result"] == "unknown":
            skipped += 1
            continue
        assert solve(args.solver, row["formula"]) == row["result"], "recorded solver result did not replay"
        formula_checks += 1
        if row["result"] == "sat" and row.get("model_complete") == "true":
            assert solve(args.solver, row["formula"], assignment(row)) == "sat", "recorded model is not satisfying"
            model_checks += 1
            if row["role"] == "bitvector-equivalence mismatch":
                counterexamples.append(row["query_id"])
            if (not corruption_checked and row["role"] == "MBA coefficient sample"
                    and int(row["model_constants"]) > 0):
                assert solve(args.solver, row["formula"], assignment(row, True)) == "unsat", "corrupted model was accepted"
                corruption_checked = True
    assert formula_checks and model_checks and counterexamples and corruption_checked
    result = {
        "report_sha256": hashlib.sha256(args.report.read_bytes()).hexdigest(),
        "solver_sha256": hashlib.sha256(Path(args.solver).read_bytes()).hexdigest(),
        "solver_version": subprocess.run([args.solver, "-version"], capture_output=True, text=True, check=True).stdout.strip(),
        "formula_checks": formula_checks, "model_checks": model_checks,
        "skipped_incomplete_or_unknown": skipped, "counterexample_queries": counterexamples,
        "corrupted_assignment_rejected": corruption_checked,
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
