"""Resolve account-visible IDA installer identities with a pinned HCLI binary."""

from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    metadata = json.loads((ROOT / "tests/fixtures/hcli_0.26.3.json").read_text())
    system = {"Darwin": "mac", "Linux": "linux", "Windows": "windows"}[platform.system()]
    arm = platform.machine().lower() in ("arm64", "aarch64")
    arch = "arm64" if system == "mac" and arm else "aarch64" if arm else "x86_64"
    name = f"hcli-{system}-{arch}-{metadata['version']}" + (".exe" if system == "windows" else "")
    asset = next(a for a in metadata["assets"] if a["name"] == name)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    executable = args.output.parent / name
    with urllib.request.urlopen(asset["browser_download_url"], timeout=120) as response:
        data = response.read()
    assert (
        "sha256:" + hashlib.sha256(data).hexdigest() == asset["digest"]
    ), "HCLI binary digest mismatch"
    executable.write_bytes(data)
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    if not os.environ.get("HCLI_API_KEY") or not os.environ.get("IDA_LICENSE_ID"):
        raise RuntimeError("Required repository credentials unavailable")
    environment = dict(os.environ, COLUMNS="500", NO_COLOR="1", TERM="dumb")
    result = subprocess.run(
        [str(executable.resolve()), "--disable-updates", "download", "--list-tags"],
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=180,
    )
    if result.returncode:
        raise RuntimeError("HCLI installer inventory authentication failed")
    rows = []
    for line in re.sub(r"\x1b\[[0-9;]*m", "", result.stdout).splitlines():
        columns = line.split()
        if not columns or not re.fullmatch(r"ida-pro:9\.[45]:[^:]+", columns[0]):
            continue
        key = columns[-1]
        if not key.startswith("release/") or "/" not in key:
            continue
        _, version, target = columns[0].split(":")
        rows.append({"version": version, "hcli_platform": target, "installer_key": key})
    if not rows:
        raise RuntimeError("No exact IDA 9.4/9.5 installer identities were returned")
    report = {
        "schema_version": 1,
        "hcli_version": metadata["version"],
        "hcli_sha256": asset["digest"].split(":", 1)[1],
        "installers": rows,
        "license_entitlements_verified": False,
        "acceptance_ready": False,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Resolved {len(rows)} installer identities; runtime acceptance remains pending")


if __name__ == "__main__":
    main()
