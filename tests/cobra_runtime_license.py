"""Resolve the exact active license through the pinned official HCLI client."""

import argparse
import asyncio
import os
from pathlib import Path

from hcli.lib.api.customer import customer
from hcli.lib.api.license import license

license_stage = "initial"


class AmbiguousLicenseIdentity(RuntimeError):
    pass


class LicenseAssetsUnavailable(RuntimeError):
    pass


class NativeLicenseNotDownloaded(RuntimeError):
    pass


async def license_records(account):
    # The pinned get_licenses() convenience method reads only page one.
    from hcli.lib.api.common import get_api_client
    from hcli.lib.api.license import PagedResponse

    client = await get_api_client()
    records = []
    page = 1
    while True:
        response = PagedResponse(
            **await client.get_json(f"/api/licenses/{account}?page={page}&limit=100")
        )
        records.extend(response.items)
        if len(records) >= response.total:
            return records
        if not response.items:
            raise RuntimeError("Incomplete license catalog")
        page += 1


async def download(directory):
    global license_stage
    identifier = os.environ["IDA_LICENSE_ID"]
    matches = []
    license_stage = "customers"
    for account in await customer.get_customers():
        license_stage = "license_catalog"
        for record in await license_records(str(account.id)):
            if record.pubhash == identifier and record.status == "active":
                matches.append((str(account.id), record))
    license_stage = "selection"
    print(f"License diagnostic: matches={len(matches)}", flush=True)
    if not matches:
        raise LookupError("Exact active license was not found")
    identities = {record.license_key for _, record in matches}
    if len(identities) != 1:
        raise AmbiguousLicenseIdentity("Exact active license identity was not unique")
    account, record = matches[0]
    license_stage = "assets"
    print(
        f"License diagnostic: key_available={bool(record.license_key)} assets={len(record.asset_types or [])}",
        flush=True,
    )
    if not record.license_key or not record.asset_types:
        raise LicenseAssetsUnavailable("Selected license has no downloadable assets")
    directory.mkdir(parents=True, exist_ok=True)
    license_stage = "download"
    for kind in record.asset_types:
        await license.download_license(account, record.license_key, kind, str(directory))
    count = len(list(directory.glob("*.hexlic")))
    print(f"License diagnostic: native_files={count}", flush=True)
    if not count:
        raise NativeLicenseNotDownloaded("No native license was downloaded")


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
        raise SystemExit(
            "License provisioning failed: " + type(error).__name__ + " stage=" + license_stage
        ) from None
