"""Read the complete installer catalog through the pinned official HCLI API client."""

from __future__ import annotations
import argparse
import asyncio
import json
from pathlib import Path
import re

from hcli.lib.api.asset import PagingFilter, asset


async def collect():
    result = []
    offset = 0
    while True:
        page = await asset.get_files("installers", PagingFilter(limit=1000, offset=offset))
        for item in page.items:
            if re.search(r"(?:release|eap)/ida-pro/9\.[45]/", item.key):
                # Never serialize signed download URLs, customer names, or credentials.
                result.append(
                    {
                        "installer_key": item.key,
                        "filename": item.filename,
                        "size": item.size,
                        "metadata_sha256": (item.metadata or {}).get("sha256"),
                    }
                )
        offset += len(page.items)
        if offset >= page.total or not page.items:
            break
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = asyncio.run(collect())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps({"schema_version": 1, "hcli_version": "0.26.3", "installers": rows}, indent=2)
        + "\n"
    )
    print(f"Resolved {len(rows)} complete-catalog installer identities")


if __name__ == "__main__":
    main()
