#!/usr/bin/env python3
"""Run an IDAPython smoke probe in an isolated, reproducible IDA process.

Raw inputs are copied into a disposable directory before IDA starts, and IDAUSR
contains only the requested Chernobog artifact plus the minimum accepted-license
configuration. Database inputs are rejected unless --allow-database is explicit.
RAX execution/materialization is disabled unless --enable-rax is explicit.
Inherited CHERNOBOG_* options are removed; use --set for explicit overrides.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time


DATABASE_SUFFIXES = {
    ".i64",
    ".idb",
    ".id0",
    ".id1",
    ".id2",
    ".nam",
    ".til",
}

DEFAULT_PASS_PATTERN = r"\[chernobog\]\[[^\]\r\n]+\] PASS(?:\s|$)"

CONTROLLED_ENVIRONMENT = {
    "IDAUSR",
    "IDADIR",
    "CHERNOBOG_AUTO",
    "CHERNOBOG_VERBOSE",
    "CHERNOBOG_PLUGIN_PATH",
    "CHERNOBOG_PLUGIN_PRELOADED",
    "CHERNOBOG_RAX_DISABLE",
    "CHERNOBOG_RAX_ENABLED",
    "CHERNOBOG_RAX_APPLY_ANALYSIS",
}

# The copied plugin's identity is reported separately. Its per-run transport
# path must not make otherwise identical configurations compare differently.
ENVIRONMENT_DIGEST_EXCLUSIONS = {"CHERNOBOG_PLUGIN_PATH"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def observed_sha256(path: Path) -> str | None:
    """A missing/unreadable artifact after execution invalidates attribution."""
    try:
        return sha256(path)
    except OSError:
        return None


def chernobog_environment_sha256(environment: dict[str, str]) -> str:
    configuration = {
        key: value for key, value in environment.items()
        if key.startswith("CHERNOBOG_")
        and key not in ENVIRONMENT_DIGEST_EXCLUSIONS
    }
    serialized = json.dumps(
        configuration, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def parse_assignment(raw: str) -> tuple[str, str]:
    key, separator, value = raw.partition("=")
    if not separator or not key or "\x00" in raw:
        raise argparse.ArgumentTypeError("expected KEY=VALUE")
    return key, value


def existing_file(raw: str) -> Path:
    path = Path(raw).expanduser().resolve()
    if not path.is_file():
        raise argparse.ArgumentTypeError("file does not exist: %s" % path)
    return path


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("input", type=existing_file)
    result.add_argument("script", type=existing_file)
    result.add_argument(
        "--ida",
        type=existing_file,
        default=os.environ.get("CHERNOBOG_IDAT"),
        help="IDA text executable (or CHERNOBOG_IDAT)",
    )
    result.add_argument(
        "--plugin",
        type=existing_file,
        default=os.environ.get("CHERNOBOG_PLUGIN"),
        help="exact Chernobog artifact (or CHERNOBOG_PLUGIN)",
    )
    result.add_argument(
        "--license",
        type=existing_file,
        default=os.environ.get("IDA_LICENSE_FILE"),
        help="optional IDA key file (or IDA_LICENSE_FILE)",
    )
    result.add_argument(
        "--ida-user-template",
        type=Path,
        default=Path.home() / ".idapro",
        help="source for ida.reg and ida-config.json only",
    )
    result.add_argument("--allow-database", action="store_true")
    result.add_argument("--enable-rax", action="store_true")
    result.add_argument("--verbose", action="store_true")
    result.add_argument("--set", action="append", type=parse_assignment, default=[])
    result.add_argument(
        "--expect-log",
        default=DEFAULT_PASS_PATTERN,
        help=(
            "regular expression that must occur in ida.log; defaults to a "
            "Chernobog PASS marker because IDA may return zero after qexit(N)"
        ),
    )
    result.add_argument(
        "--output-dir",
        type=Path,
        help="retain all run artifacts in this new/empty directory",
    )
    return result


def require_tool_path(value: Path | str | None, option: str) -> Path:
    if value is None:
        raise SystemExit("%s is required" % option)
    path = Path(value).expanduser().resolve()
    if not path.is_file():
        raise SystemExit("%s is not a file: %s" % (option, path))
    return path


def prepare_run_directory(output_dir: Path | None) -> tuple[Path, bool]:
    if output_dir is None:
        return Path(tempfile.mkdtemp(prefix="chernobog-ida-smoke.")), True
    result = output_dir.expanduser().resolve()
    if result.exists():
        if not result.is_dir() or any(result.iterdir()):
            raise SystemExit("--output-dir must be absent or empty: %s" % result)
    result.mkdir(parents=True, exist_ok=True)
    return result, False


def main() -> int:
    arguments = parser().parse_args()
    controlled_assignments = sorted(
        key for key, _ in arguments.set if key in CONTROLLED_ENVIRONMENT
    )
    if controlled_assignments:
        raise SystemExit(
            "--set cannot override runner-controlled variables: %s"
            % ", ".join(controlled_assignments)
        )
    ida = require_tool_path(arguments.ida, "--ida")
    plugin = require_tool_path(arguments.plugin, "--plugin")
    license_file = (
        require_tool_path(arguments.license, "--license")
        if arguments.license is not None
        else None
    )
    input_path: Path = arguments.input
    if (
        input_path.suffix.lower() in DATABASE_SUFFIXES
        and not arguments.allow_database
    ):
        raise SystemExit(
            "database input refused; use the original binary or pass "
            "--allow-database explicitly: %s" % input_path
        )

    source_hash = sha256(input_path)
    run_dir, disposable = prepare_run_directory(arguments.output_dir)
    ida_user = run_dir / "idauser"
    plugins = ida_user / "plugins"
    plugins.mkdir(parents=True)
    for filename in ("ida.reg", "ida-config.json"):
        source = arguments.ida_user_template.expanduser().resolve() / filename
        if not source.is_file():
            raise SystemExit("missing IDA acceptance configuration: %s" % source)
        shutil.copy2(source, ida_user / filename)
    installed_plugin = plugins / plugin.name
    shutil.copy2(plugin, installed_plugin)
    probe_directory = run_dir / "probe"
    probe_directory.mkdir()
    copied_script = probe_directory / arguments.script.name
    shutil.copy2(arguments.script, copied_script)
    copied_input = run_dir / input_path.name
    shutil.copy2(input_path, copied_input)
    log_path = run_dir / "ida.log"

    environment = {
        key: value for key, value in os.environ.items()
        if not key.startswith("CHERNOBOG_")
    }
    environment.update(
        {
            "IDAUSR": str(ida_user),
            "IDADIR": str(ida.parent),
            "CHERNOBOG_AUTO": "1",
            "CHERNOBOG_VERBOSE": "1" if arguments.verbose else "0",
            "CHERNOBOG_PLUGIN_PATH": str(installed_plugin),
            "CHERNOBOG_PLUGIN_PRELOADED": "1",
        }
    )
    if arguments.enable_rax:
        environment.update(
            {
                "CHERNOBOG_RAX_DISABLE": "0",
                "CHERNOBOG_RAX_ENABLED": "1",
                "CHERNOBOG_RAX_APPLY_ANALYSIS": "1",
            }
        )
    else:
        environment.update(
            {
                "CHERNOBOG_RAX_DISABLE": "1",
                "CHERNOBOG_RAX_ENABLED": "0",
                "CHERNOBOG_RAX_APPLY_ANALYSIS": "0",
            }
        )
    for key, value in arguments.set:
        environment[key] = value

    command = [str(ida), "-A"]
    if license_file is not None:
        command.append("-Olicense:keyfile=%s" % license_file)
    command.extend(
        [
            "-L%s" % log_path,
            "-S%s" % copied_script,
            str(copied_input),
        ]
    )

    print("run_dir=%s" % run_dir, flush=True)
    print("input_sha256=%s" % source_hash, flush=True)
    plugin_hash = sha256(installed_plugin)
    script_hash = sha256(copied_script)
    source_script_hash = sha256(arguments.script)
    copied_input_hash = sha256(copied_input)
    ida_hash = sha256(ida)
    print("plugin_sha256=%s" % plugin_hash, flush=True)
    started = time.perf_counter_ns()
    completed = subprocess.run(command, env=environment, check=False)
    elapsed_ns = time.perf_counter_ns() - started
    unchanged = observed_sha256(input_path) == source_hash
    copied_script_unchanged = observed_sha256(copied_script) == script_hash
    plugin_unchanged = observed_sha256(installed_plugin) == plugin_hash
    ida_hash_after = observed_sha256(ida)
    ida_unchanged = ida_hash_after == ida_hash
    input_copy_matches_source = copied_input_hash == source_hash
    artifacts_unchanged = (
        unchanged and copied_script_unchanged and plugin_unchanged
        and ida_unchanged and input_copy_matches_source
    )
    if not artifacts_unchanged:
        print("run artifact integrity check failed", file=sys.stderr)
        return_code = 125
    else:
        return_code = completed.returncode
    log_text = (
        log_path.read_text(encoding="utf-8", errors="replace")
        if log_path.is_file() else ""
    )
    marker_found = re.search(arguments.expect_log, log_text) is not None
    if return_code == 0 and not marker_found:
        print(
            "required log marker absent: %s" % arguments.expect_log,
            file=sys.stderr,
        )
        return_code = 124

    report = {
        "schema_version": 2,
        "input_sha256": copied_input_hash,
        "source_input_sha256": source_hash,
        "plugin_sha256": plugin_hash,
        "plugin_unchanged": plugin_unchanged,
        "script_sha256": script_hash,
        "script_unchanged": copied_script_unchanged,
        "source_script_sha256": source_script_hash,
        "source_script_unchanged": (
            observed_sha256(arguments.script) == source_script_hash
        ),
        "source_input_unchanged": unchanged,
        "input_copy_matches_source": input_copy_matches_source,
        "ida_path": str(ida),
        "ida_sha256": ida_hash,
        "ida_sha256_after": ida_hash_after,
        "ida_unchanged": ida_unchanged,
        "artifacts_unchanged": artifacts_unchanged,
        "chernobog_environment_sha256": chernobog_environment_sha256(environment),
        "enable_rax": arguments.enable_rax,
        "verbose": arguments.verbose,
        "process_elapsed_ns": elapsed_ns,
        "process_return_code": completed.returncode,
        "expected_log_pattern": arguments.expect_log,
        "expected_log_found": marker_found,
        "runner_return_code": return_code,
    }
    report_path = run_dir / "run.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("process_elapsed_ns=%d" % elapsed_ns, flush=True)

    if return_code != 0 or not disposable:
        print("ida_log=%s" % log_path, flush=True)
        print("run_report=%s" % report_path, flush=True)
    if disposable and return_code == 0:
        shutil.rmtree(run_dir)
    elif disposable:
        print("failed artifacts retained at %s" % run_dir, file=sys.stderr)
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
