"""Provision a fingerprinted native IDA runtime and collect paired acceptance evidence."""

from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
WINDOWS_IDA_REGISTRY = r"Software\Hex-Rays\IDA"


def embedded_revision_matches(embedded, full):
    # CMake's public provenance header embeds git --short=12. The complete
    # source identity remains bound by the trusted bundle and file SHA-256s.
    return (
        isinstance(embedded, str)
        and re.fullmatch(r"[0-9a-f]{12,40}", embedded) is not None
        and re.fullmatch(r"[0-9a-f]{40}", full) is not None
        and full.startswith(embedded)
    )


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            h.update(block)
    return h.hexdigest()


def accepted_ida_configuration(template, system, version):
    if system != "Windows":
        return (template / "ida.reg").is_file()
    # IDA's Windows registry backend is independent of IDAUSR. HCLI writes
    # these versioned values through ida_registry, rather than creating ida.reg.
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            WINDOWS_IDA_REGISTRY,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ) as key:
            value, kind = winreg.QueryValueEx(key, "EULA " + version.replace(".", ""))
            return kind == winreg.REG_DWORD and value == 1
    except OSError:
        return False


def accept_windows_eula(version):
    # HCLI's requested --accept-eula can be skipped when its bundled Python
    # cannot import idalib. Perform that same requested action through the
    # documented native registry backend; license checks remain independent.
    if version != "9.4":
        raise RuntimeError("Native EULA fallback is qualified only for the pinned IDA 9.4 runtime")
    import winreg

    try:
        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            WINDOWS_IDA_REGISTRY,
            0,
            winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY,
        ) as key:
            # Match the pinned HCLI accept_eula() procedure exactly: a current
            # IDA build may retain an earlier 9.x agreement-version key.
            for accepted in ("90", "91", "92", "93", "94"):
                winreg.SetValueEx(key, "EULA " + accepted, 0, winreg.REG_DWORD, 1)
    except OSError:
        raise RuntimeError("Unable to configure requested native Windows EULA acceptance") from None


def execute(command, *, env=None, timeout=1800):
    # HCLI's installation output includes a license identifier. Keep it out of
    # logs and artifacts, including failure paths and subprocess exceptions.
    try:
        result = subprocess.run(
            command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Native runtime command exceeded its time limit") from None
    if result.returncode:
        text = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout.decode("utf-8", errors="replace"))
        details = []
        for line in text.splitlines():
            for marker in (
                "Install failed:",
                "Could not create the Python environment:",
                "Error:",
                "No such option:",
                "Got unexpected extra argument",
                "License provisioning failed:",
                "License diagnostic:",
            ):
                if marker not in line:
                    continue
                detail = line[line.index(marker) :]
                for key in ("IDA_LICENSE_ID", "HCLI_API_KEY"):
                    value = (env or os.environ).get(key)
                    if value:
                        detail = detail.replace(value, "<credential>")
                detail = re.sub(r"https?://\S+", "<url>", detail)
                detail = re.sub(r"\S+\.hexlic", "<license-file>", detail)
                detail = re.sub(r"[\w.+-]+@[\w.-]+", "<email>", detail)
                detail = detail.replace(str(Path.home()), "<home>").replace(str(ROOT), "<repo>")
                details.append(detail[:400])
                break
        if not details:
            for marker, category in (
                ("Select customer:", "interactive_customer_selection"),
                ("Aborted!", "interactive_abort"),
                ("Usage:", "invalid_cli_usage"),
                ("Traceback", "python_exception"),
            ):
                if marker in text:
                    details.append(category)
        raise RuntimeError(
            f"{Path(command[0]).name} failed with status {result.returncode}: "
            + "; ".join(details[-2:])
        )


def provision(args, entry):
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    metadata = json.loads((ROOT / "tests/fixtures/hcli_0.26.3.json").read_text())
    system = {"Darwin": "mac", "Linux": "linux", "Windows": "windows"}[platform.system()]
    arm = platform.machine().lower() in ("arm64", "aarch64")
    observed = {"mac": "macos", "linux": "linux", "windows": "windows"}[system] + (
        "-arm64" if arm else "-x86_64"
    )
    if observed != entry["target"]:
        raise RuntimeError("Runtime target is not native to this runner")
    arch = "arm64" if system == "mac" and arm else "aarch64" if arm else "x86_64"
    name = f"hcli-{system}-{arch}-{metadata['version']}" + (".exe" if system == "windows" else "")
    asset = next(a for a in metadata["assets"] if a["name"] == name)
    hcli = directory / name
    with urllib.request.urlopen(asset["browser_download_url"], timeout=120) as response:
        hcli.write_bytes(response.read())
    if "sha256:" + digest(hcli) != asset["digest"]:
        raise RuntimeError("Pinned HCLI digest mismatch")
    hcli.chmod(hcli.stat().st_mode | stat.S_IXUSR)
    environment = dict(os.environ, IDAUSR=str(directory / "idauser"), NO_COLOR="1", TERM="dumb")
    if not environment.get("HCLI_API_KEY") or not environment.get("IDA_LICENSE_ID"):
        raise RuntimeError("Required runtime credentials unavailable")
    download = directory / "download"
    download.mkdir()
    execute(
        [
            str(hcli),
            "--disable-updates",
            "download",
            entry["installer_key"],
            "--output-dir",
            str(download),
        ],
        env=environment,
    )
    installers = list(download.rglob(Path(entry["installer_key"]).name))
    if len(installers) != 1:
        raise RuntimeError("Exact installer download missing")
    installer = installers[0]
    if (
        installer.stat().st_size != entry["installer_size"]
        or digest(installer) != entry["installer_sha256"]
    ):
        raise RuntimeError("Pinned IDA installer digest mismatch")
    installation = directory / "ida"
    # Select the exact license before the CLI can prompt for a customer.
    execute(
        [
            sys.executable,
            str(ROOT / "tests/cobra_runtime_license.py"),
            "--directory",
            environment["IDAUSR"],
        ],
        env=environment,
    )
    execute(
        [
            str(hcli),
            "--disable-updates",
            "ida",
            "install",
            str(installer),
            "--yes",
            "--accept-eula",
            "--install-dir",
            str(installation),
            "--create-python-environment",
            "--set-default",
        ],
        env=environment,
    )
    idat = [
        p for p in installation.rglob("idat.exe" if system == "windows" else "idat") if p.is_file()
    ]
    licenses = list((directory / "idauser").glob("*.hexlic"))
    if len(idat) != 1 or not licenses:
        raise RuntimeError("Expected one native IDA text executable and its license bundle")
    for license_file in licenses:
        shutil.copy2(license_file, idat[0].parent / license_file.name)
    template = directory / "idauser"
    if system == "windows":
        accept_windows_eula(entry["ida_version"])
    if not accepted_ida_configuration(template, platform.system(), entry["ida_version"]):
        raise RuntimeError("HCLI did not produce accepted IDA configuration")
    if not (template / "ida-config.json").is_file():
        (template / "ida-config.json").write_text("{}\n")
    venv_python = (
        template / "venv" / ("Scripts/python.exe" if system == "windows" else "bin/python")
    )
    if not venv_python.is_file():
        raise RuntimeError("HCLI did not produce a native IDAPython environment")
    config = {
        "python": str(venv_python),
        "ida": str(idat[0]),
        "license_files": len(licenses),
        "template": str(template),
        "hcli_sha256": digest(hcli),
        "installer_sha256": digest(installer),
    }
    (directory / "private-config.json").write_text(json.dumps(config))
    installer.unlink()
    print(f"Provisioned fingerprinted native IDA {entry['ida_version']} for {entry['target']}")


def collect(args, entry):
    directory = args.directory.resolve()
    config = json.loads((directory / "private-config.json").read_text())
    os.environ["IDAPYTHON_VENV_EXECUTABLE"] = config["python"]
    bundle = args.bundle.resolve()
    identity = json.loads((bundle / "identity.json").read_text())
    harness_revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    revision = harness_revision if args.artifact_revision is None else args.artifact_revision
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise RuntimeError("Expected a complete artifact source revision")
    if identity["target"] != entry["target"] or identity["revision"] != revision:
        raise RuntimeError("Acceptance bundle source/target mismatch")
    for name, expected in identity["files"].items():
        if digest(bundle / name) != expected:
            raise RuntimeError("Acceptance bundle artifact digest mismatch")
    bridge = next(bundle.glob("chernobog_mba_cobra_sdk_bridge.*"))
    fixture = next(
        p for p in bundle.glob("chernobog_mba_cobra_runtime_fixture*") if p.suffix != ".pdb"
    )
    plugins = [p for p in args.plugin.rglob("*") if p.suffix in (".dll", ".so", ".dylib")]
    if len(plugins) != 1:
        raise RuntimeError("Expected exactly one release plugin artifact")
    # The plugin loader resolves its initialization name from this basename.
    plugin = directory / ("chernobog" + plugins[0].suffix)
    shutil.copy2(plugins[0], plugin)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    legacy_path = ROOT / "tests/fixtures/mba_cobra_legacy_manifest.json"
    legacy_hash = digest(legacy_path)
    legacy = json.loads(legacy_path.read_text())
    for name, expected in legacy["sources"].items():
        if digest(ROOT / name) != expected:
            raise RuntimeError("Frozen legacy fixture source mismatch")
    fixture.chmod(fixture.stat().st_mode | stat.S_IXUSR)
    native_control = subprocess.run([str(fixture)], capture_output=True, text=True, timeout=120)
    native_control.check_returncode()
    counts = {}
    for group, marker in (
        ("nested", "Nested MBA"),
        ("masks", "Mask update"),
        ("semantic", "MBA SMT native"),
    ):
        match = re.search(marker + r" comparisons: (\d+)", native_control.stdout)
        if not match and args.sdk_only:
            continue
        if not match or int(match[1]) != legacy["oracle_comparisons"][group]:
            raise RuntimeError("Original native fixture oracle failed: " + group)
        counts[group] = int(match[1])
    base = [sys.executable, str(ROOT / "tests/run_ida_smoke.py"), str(fixture)]
    common = [
        "--ida",
        config["ida"],
        "--plugin",
        str(plugin),
        "--ida-user-template",
        config["template"],
    ]
    runs = []
    cases = [
        (
            "sdk-cobra",
            "ida_mba_cobra_sdk_probe.py",
            [
                "CHERNOBOG_COBRA_SDK_BRIDGE=" + str(bridge),
                "CHERNOBOG_COBRA_SDK_MODES=cobra:Normal,cobra:Deep,cobra:Faults",
            ],
        ),
        (
            "sdk-legacy",
            "ida_mba_cobra_sdk_probe.py",
            [
                "CHERNOBOG_COBRA_SDK_BRIDGE=" + str(bridge),
                "CHERNOBOG_COBRA_SDK_MODES=legacy:Normal,legacy:Deep",
            ],
        ),
        ("legacy", "ida_mba_nested_probe.py", ["CHERNOBOG_MBA_BACKEND=legacy"]),
        ("cobra", "ida_mba_nested_probe.py", ["CHERNOBOG_MBA_BACKEND=cobra"]),
    ]
    if args.sdk_only:
        cases = cases[:2]
    for backend in (() if args.sdk_only else ("legacy", "cobra")):
        for group in ("semantic", "calls", "masks"):
            probe = "ida_mba_smt_probe.py" if group == "semantic" else f"ida_mba_{group}_probe.py"
            cases.append(
                (
                    backend + "-" + group,
                    probe,
                    [
                        "CHERNOBOG_MBA_BACKEND=" + backend,
                        "CHERNOBOG_MBA_FIXTURE_TYPES=" + str(legacy_path),
                    ],
                )
            )
    for label, probe, settings in cases:
        run_dir = directory / ("run-" + label)
        command = base + [str(ROOT / "tests" / probe)] + common + ["--output-dir", str(run_dir)]
        for setting in settings:
            command += ["--set", setting]
        try:
            execute(command)
        finally:
            # Preserve only the runner's redacted report and owned test JSON,
            # including when a probe rejects an artifact. Never copy IDAUSR.
            if (run_dir / "run.json").is_file():
                shutil.copy2(run_dir / "run.json", output / (label + "-run.json"))
            capture_names = (
                "mba_cobra_sdk.json",
                "mba_nested.json",
                "mba_smt.json",
                "mba_calls.json",
                "mba_masks.json",
            )
            for name in capture_names:
                if (run_dir / name).is_file():
                    shutil.copy2(run_dir / name, output / (label + ".json"))
        run = json.loads((run_dir / "run.json").read_text())
        if not run["artifacts_unchanged"] or run["runner_return_code"]:
            raise RuntimeError("Installed plugin run failed integrity checks")
        group = label.split("-", 1)[1] if "-" in label else "nested"
        capture = (
            "mba_cobra_sdk.json"
            if label.startswith("sdk-")
            else "mba_smt.json" if group == "semantic" else f"mba_{group}.json"
        )
        shutil.copy2(run_dir / capture, output / (label + ".json"))
        if not label.startswith("sdk-"):
            oracle = directory / ("oracle-" + label)
            try:
                execute(
                    [
                        sys.executable,
                        str(
                            ROOT
                            / "tests"
                            / {
                                "nested": "verify_mba_nested.py",
                                "semantic": "verify_mba_semantic_capture.py",
                                "calls": "verify_mba_context_capture.py",
                                "masks": "verify_mba_masks.py",
                            }[group]
                        ),
                        str(run_dir / capture),
                        "--output-dir",
                        str(oracle),
                    ]
                )
            except RuntimeError:
                for log in oracle.glob("*-build.log"):
                    content = (
                        log.read_text(errors="replace")
                        .replace(str(ROOT), "<repo>")
                        .replace(str(Path.home()), "<home>")
                        .replace(str(directory), "<runtime>")
                    )
                    (output / (label + "-" + log.name)).write_text(content)
                raise
            shutil.copy2(oracle / "verification.json", output / (label + "-oracle.json"))
        runs.append(
            {
                "label": label,
                "plugin_sha256": run["plugin_sha256"],
                "process_elapsed_ns": run["process_elapsed_ns"],
                "artifacts_unchanged": True,
            }
        )
    sdk_cobra = json.loads((output / "sdk-cobra.json").read_text())
    sdk_legacy = json.loads((output / "sdk-legacy.json").read_text())
    for key in (
        "kernel_version",
        "hexrays_version",
        "system",
        "machine",
        "plugin_sha256",
        "bridge_sha256",
    ):
        if sdk_cobra[key] != sdk_legacy[key]:
            raise RuntimeError("Paired SDK artifact/runtime mismatch")
    sdk_cobra["reports"] += sdk_legacy["reports"]
    sdk_cobra["errors"] += sdk_legacy["errors"]
    if any(
        not embedded_revision_matches(report["revision"], revision)
        for report in sdk_cobra["reports"]
    ):
        raise RuntimeError("Loaded SDK code differs from the artifact source revision")
    (output / "sdk.json").write_text(json.dumps(sdk_cobra, indent=2) + "\n")
    report = {
        "schema_version": 1,
        "target": entry["target"],
        "revision": revision,
        "harness_revision": harness_revision,
        "collection_mode": "sdk_only" if args.sdk_only else "full",
        "runtime": entry,
        "hcli_sha256": config["hcli_sha256"],
        "runs": runs,
        "bundle": identity,
        "legacy_manifest_sha256": legacy_hash,
        "fixture_sha256": digest(fixture),
        "native_control": counts,
        "status": "diagnostic" if args.artifact_revision is not None else "passed",
    }
    if digest(legacy_path) != legacy_hash:
        raise RuntimeError("Frozen legacy manifest changed during acceptance")
    (output / "native.json").write_text(json.dumps(report, indent=2) + "\n")
    kind = "Diagnostic" if args.artifact_revision is not None else "Acceptance"
    scope = (
        "SDK execution"
        if args.sdk_only
        else "SDK, installed-plugin corpus, and paired unsigned oracles"
    )
    print(f"{kind} {scope} passed: {entry['target']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("provision", "collect"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--plugin", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--artifact-revision", help="Diagnostic collection only; cannot qualify promotion"
    )
    parser.add_argument(
        "--sdk-only",
        action="store_true",
        help="Diagnostic SDK execution without corpus qualification",
    )
    args = parser.parse_args()
    if args.sdk_only and (args.operation != "collect" or args.artifact_revision is None):
        raise RuntimeError(
            "SDK-only collection requires an explicitly diagnostic artifact revision"
        )
    manifest = json.loads((ROOT / "tests/fixtures/ida_cobra_runtime_manifest.json").read_text())
    if manifest["status"] != "checksums_frozen":
        raise RuntimeError("Runtime checksums are not frozen")
    if (
        digest(ROOT / "tests/fixtures/mba_cobra_legacy_manifest.json")
        != manifest["legacy_manifest_sha256"]
    ):
        raise RuntimeError("Frozen legacy manifest fingerprint mismatch")
    entry = next(row for row in manifest["runtimes"] if row["target"] == args.target)
    if not entry["installer_sha256"] or len(entry["installer_sha256"]) != 64:
        raise RuntimeError("Installer fingerprint unavailable")
    (provision if args.operation == "provision" else collect)(args, entry)


if __name__ == "__main__":
    main()
