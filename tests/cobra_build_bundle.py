"""Package SDK-only acceptance artifacts separately from release plugins."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    files = {}
    for stem in (
        "chernobog_mba_cobra_sdk_bridge",
        "chernobog_mba_cobra_runtime_fixture",
        "chernobog_mba_d810_sdk_bridge",
        "chernobog_mba_d810_runtime_fixture",
    ):
        candidates = [
            p
            for p in Path("build").rglob(stem + "*")
            if p.is_file()
            and p.suffix in (".so", ".dll", ".exe", "")
            and "CMakeFiles" not in p.parts
        ]
        if len(candidates) != 1:
            raise RuntimeError(f"Expected one built {stem}; found {len(candidates)}")
        source = candidates[0]
        shutil.copy2(source, args.output / source.name)
        files[source.name] = hashlib.sha256(source.read_bytes()).hexdigest()
    report = {
        "schema_version": 1,
        "target": args.target,
        "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "files": files,
    }
    (args.output / "identity.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
