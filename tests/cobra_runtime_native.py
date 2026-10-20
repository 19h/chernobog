"""Provision a fingerprinted native IDA runtime and collect paired acceptance evidence."""

from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            h.update(block)
    return h.hexdigest()


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
        raise RuntimeError(f"{Path(command[0]).name} failed with status {result.returncode}")


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
            "--license-id",
            environment["IDA_LICENSE_ID"],
            "--create-python-environment",
            "--no-set-default",
        ],
        env=environment,
    )
    idat = [
        p for p in installation.rglob("idat.exe" if system == "windows" else "idat") if p.is_file()
    ]
    licenses = list(installation.rglob("*.hexlic"))
    if len(idat) != 1 or len(licenses) != 1:
        raise RuntimeError("Expected one native IDA text executable and license")
    template = directory / "idauser"
    if not (template / "ida.reg").is_file():
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
        "license": str(licenses[0]),
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
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
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
    base = [sys.executable, str(ROOT / "tests/run_ida_smoke.py"), str(fixture)]
    common = [
        "--ida",
        config["ida"],
        "--plugin",
        str(plugin),
        "--license",
        config["license"],
        "--ida-user-template",
        config["template"],
    ]
    runs = []
    for label, probe, settings in (
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
    ):
        run_dir = directory / ("run-" + label)
        command = base + [str(ROOT / "tests" / probe)] + common + ["--output-dir", str(run_dir)]
        for setting in settings:
            command += ["--set", setting]
        execute(command)
        run = json.loads((run_dir / "run.json").read_text())
        if not run["artifacts_unchanged"] or run["runner_return_code"]:
            raise RuntimeError("Installed plugin run failed integrity checks")
        capture = "mba_cobra_sdk.json" if label.startswith("sdk-") else "mba_nested.json"
        shutil.copy2(run_dir / capture, output / (label + ".json"))
        if not label.startswith("sdk-"):
            oracle = directory / ("oracle-" + label)
            execute(
                [
                    sys.executable,
                    str(ROOT / "tests/verify_mba_nested.py"),
                    str(run_dir / capture),
                    "--output-dir",
                    str(oracle),
                ]
            )
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
    (output / "sdk.json").write_text(json.dumps(sdk_cobra, indent=2) + "\n")
    report = {
        "schema_version": 1,
        "target": entry["target"],
        "revision": revision,
        "runtime": entry,
        "hcli_sha256": config["hcli_sha256"],
        "runs": runs,
        "bundle": identity,
        "status": "passed",
    }
    (output / "native.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"Native SDK, installed-plugin corpus, and paired unsigned oracles passed: {entry['target']}"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("provision", "collect"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--plugin", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    manifest = json.loads((ROOT / "tests/fixtures/ida_cobra_runtime_manifest.json").read_text())
    if manifest["status"] != "checksums_frozen":
        raise RuntimeError("Runtime checksums are not frozen")
    entry = next(row for row in manifest["runtimes"] if row["target"] == args.target)
    if not entry["installer_sha256"] or len(entry["installer_sha256"]) != 64:
        raise RuntimeError("Installer fingerprint unavailable")
    (provision if args.operation == "provision" else collect)(args, entry)


if __name__ == "__main__":
    main()
