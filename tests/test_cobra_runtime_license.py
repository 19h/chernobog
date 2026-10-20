"""Exact license selection without account prompts or customer-data output."""

import asyncio
import importlib.util
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import AsyncMock, patch


class LicenseSelectionTests(unittest.TestCase):
    def setUp(self):
        self.customer = types.SimpleNamespace(
            get_customers=AsyncMock(return_value=[types.SimpleNamespace(id="account")])
        )
        self.api = types.SimpleNamespace(get_licenses=AsyncMock(), download_license=AsyncMock())
        spec = importlib.util.spec_from_file_location(
            "runtime_license_under_test", Path(__file__).with_name("cobra_runtime_license.py")
        )
        self.module = importlib.util.module_from_spec(spec)
        with patch.dict(
            "sys.modules",
            {
                "hcli.lib.api.customer": types.SimpleNamespace(customer=self.customer),
                "hcli.lib.api.license": types.SimpleNamespace(license=self.api),
            },
        ):
            spec.loader.exec_module(self.module)
        self.module.license_records = self.api.get_licenses
        self.env = patch.dict(os.environ, {"IDA_LICENSE_ID": "fixture-id"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def record(self, identifier="fixture-id", status="active"):
        return types.SimpleNamespace(
            pubhash=identifier, status=status, license_key="fixture-key", asset_types=["v9"]
        )

    def test_unique_active_id_across_accounts(self):
        self.customer.get_customers.return_value = [
            types.SimpleNamespace(id="first"),
            types.SimpleNamespace(id="second"),
        ]
        self.api.get_licenses.side_effect = [[self.record("other")], [self.record()]]

        async def download(account, key, kind, directory):
            self.assertEqual((account, key, kind), ("second", "fixture-key", "v9"))
            Path(directory, "fixture.hexlic").write_text("synthetic license fixture")

        self.api.download_license.side_effect = download
        with tempfile.TemporaryDirectory() as directory:
            asyncio.run(self.module.download(Path(directory)))
        self.api.download_license.assert_awaited_once()

    def test_absent_or_inactive_id_never_downloads(self):
        for records in ([self.record("other")], [self.record(status="inactive")], []):
            self.api.get_licenses.return_value = records
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(LookupError):
                    asyncio.run(self.module.download(Path(directory)))
        self.api.download_license.assert_not_awaited()

    def test_duplicate_selection_never_downloads(self):
        second = self.record()
        second.license_key = "different-fixture-key"
        self.api.get_licenses.return_value = [self.record(), second]
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RuntimeError):
                asyncio.run(self.module.download(Path(directory)))
        self.api.download_license.assert_not_awaited()

    def test_missing_downloaded_asset_rejects(self):
        self.api.get_licenses.return_value = [self.record()]
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RuntimeError):
                asyncio.run(self.module.download(Path(directory)))

    def test_bundle_and_repeated_account_aliases(self):
        self.api.get_licenses.return_value = [self.record(), self.record()]

        async def download(account, key, kind, directory):
            for name in ("ida.hexlic", "decompiler.hexlic"):
                Path(directory, name).write_text("synthetic license fixture")

        self.api.download_license.side_effect = download
        with tempfile.TemporaryDirectory() as directory:
            asyncio.run(self.module.download(Path(directory)))
            self.assertEqual(len(list(Path(directory).glob("*.hexlic"))), 2)
        self.api.download_license.assert_awaited_once()

    def test_catalog_reads_beyond_first_page(self):
        records = AsyncMock(
            side_effect=[
                {"items": [self.record("other")], "total": 2},
                {"items": [self.record()], "total": 2},
            ]
        )
        client = types.SimpleNamespace(get_json=records)
        # Load the real paginator separately from the selection API test stub.
        spec = importlib.util.spec_from_file_location(
            "runtime_license_pagination", Path(__file__).with_name("cobra_runtime_license.py")
        )
        module = importlib.util.module_from_spec(spec)
        with patch.dict(
            "sys.modules",
            {
                "hcli.lib.api.customer": types.SimpleNamespace(customer=self.customer),
                "hcli.lib.api.license": types.SimpleNamespace(
                    license=self.api, PagedResponse=lambda **fields: types.SimpleNamespace(**fields)
                ),
                "hcli.lib.api.common": types.SimpleNamespace(
                    get_api_client=AsyncMock(return_value=client)
                ),
            },
        ):
            spec.loader.exec_module(module)
            result = asyncio.run(module.license_records("account"))
        self.assertEqual([r.pubhash for r in result], ["other", "fixture-id"])
        self.assertIn("page=2", records.await_args_list[-1].args[0])


if __name__ == "__main__":
    unittest.main()
