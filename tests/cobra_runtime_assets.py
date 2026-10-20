"""Freeze installer fingerprints from exact keys using the official HCLI API."""

from __future__ import annotations
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import urllib.request

from hcli.lib.api.asset import asset


async def resolve(manifest, directory):
    directory.mkdir(parents=True, exist_ok=True)
    for entry in manifest["runtimes"]:
        record = await asset.get_file("installers", entry["installer_key"])
        if not record or not record.url or not record.url.startswith("https://"):
            raise RuntimeError("Exact installer key is unavailable")
        path = directory / Path(record.filename).name
        digest = hashlib.sha256()
        size = 0
        with urllib.request.urlopen(record.url, timeout=180) as response, path.open("wb") as stream:
            for block in iter(lambda: response.read(1048576), b""):
                digest.update(block)
                stream.write(block)
                size += len(block)
        if size != entry["installer_size"] or size != record.size:
            raise RuntimeError("Installer size changed during fingerprint resolution")
        observed = digest.hexdigest()
        if entry.get("installer_sha256") and entry["installer_sha256"] != observed:
            raise RuntimeError("Pinned installer digest changed")
        entry["installer_sha256"] = observed
        print(f"Resolved {entry['target']}: {size} B; SHA-256 {observed}", flush=True)
        path.unlink()
    manifest["status"] = "checksums_frozen"
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    result = asyncio.run(resolve(manifest, args.directory))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
