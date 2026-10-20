"""Resolve the exact active license through the pinned official HCLI client."""

import argparse
import asyncio
import os
from pathlib import Path

from hcli.lib.api.customer import customer
from hcli.lib.api.license import license


async def download(directory):
    identifier = os.environ["IDA_LICENSE_ID"]
    matches = []
    for account in await customer.get_customers():
        for record in await license.get_licenses(str(account.id)):
            if record.pubhash == identifier and record.status == "active":
                matches.append((str(account.id), record))
    if not matches:
        raise LookupError("Exact active license was not found")
    if len(matches) != 1:
        raise RuntimeError("Exact active license selection was not unique")
    account, record = matches[0]
    if not record.license_key or not record.asset_types:
        raise RuntimeError("Selected license has no downloadable assets")
    directory.mkdir(parents=True, exist_ok=True)
    for kind in record.asset_types:
        await license.download_license(account, record.license_key, kind, str(directory))
    if len(list(directory.glob("*.hexlic"))) != 1:
        raise RuntimeError("Expected one downloaded native license")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(download(args.directory))
    print("Exact active runtime license resolved")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # API exception bodies can contain account metadata or signed URLs.
        raise SystemExit("License provisioning failed: " + type(error).__name__) from None
