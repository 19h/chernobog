"""Verify platform-specific configuration without reading credentials or real registry keys."""

import contextlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, call, patch


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


RUNTIME = module("cobra_runtime_native")
RUNNER = module("run_ida_smoke")


class RegistryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.destination = self.root / "destination"
        self.source.mkdir()
        self.destination.mkdir()
        (self.source / "ida-config.json").write_text("{}\n")

    def registry(self, value=1, kind=4):
        return types.SimpleNamespace(
            HKEY_CURRENT_USER=1,
            KEY_READ=0x20019,
            KEY_WOW64_64KEY=0x100,
            REG_DWORD=4,
            OpenKey=Mock(return_value=contextlib.nullcontext("handle")),
            QueryValueEx=Mock(return_value=(value, kind)),
            KEY_SET_VALUE=2,
            CreateKeyEx=Mock(return_value=contextlib.nullcontext("handle")),
            SetValueEx=Mock(),
        )

    def test_windows_uses_native_versioned_registry_value(self):
        registry = self.registry()
        with patch.dict(sys.modules, {"winreg": registry}):
            self.assertTrue(RUNTIME.accepted_ida_configuration(self.source, "Windows", "9.4"))
        registry.OpenKey.assert_called_once_with(1, r"Software\Hex-Rays\IDA", 0, 0x20119)
        registry.QueryValueEx.assert_called_once_with("handle", "EULA 94")
        self.assertFalse((self.source / "ida.reg").exists())

    def test_windows_rejects_unaccepted_or_wrongly_typed_value(self):
        for value, kind in ((0, 4), ("1", 1), (1, 1)):
            with patch.dict(sys.modules, {"winreg": self.registry(value, kind)}):
                self.assertFalse(RUNTIME.accepted_ida_configuration(self.source, "Windows", "9.4"))

    def test_windows_missing_registry_value_rejects(self):
        registry = self.registry()
        registry.QueryValueEx.side_effect = OSError("missing")
        with patch.dict(sys.modules, {"winreg": registry}):
            self.assertFalse(RUNTIME.accepted_ida_configuration(self.source, "Windows", "9.4"))

    def test_requested_windows_acceptance_matches_pinned_hcli(self):
        registry = self.registry()
        with patch.dict(sys.modules, {"winreg": registry}):
            RUNTIME.accept_windows_eula("9.4")
        registry.CreateKeyEx.assert_called_once_with(1, r"Software\Hex-Rays\IDA", 0, 0x102)
        self.assertEqual(
            registry.SetValueEx.call_args_list,
            [
                call("handle", "EULA " + version, 0, 4, 1)
                for version in ("90", "91", "92", "93", "94")
            ],
        )

    def test_unqualified_windows_agreement_version_rejects(self):
        with self.assertRaises(RuntimeError):
            RUNTIME.accept_windows_eula("9.5")

    def test_startup_diagnostics_do_not_publish_license_text(self):
        text = "License agreement: Jane Example example@example.test secret-key; IDAPython DLL failed: WinError 193"
        diagnostic = RUNNER.startup_diagnostics(text)
        self.assertEqual(diagnostic["categories"], ["eula", "license", "loader", "python"])
        self.assertEqual(diagnostic["windows_error_codes"], ["193"])
        self.assertNotIn("Example", str(diagnostic))
        self.assertNotIn("secret-key", str(diagnostic))

    def test_failed_windows_acceptance_rejects(self):
        registry = self.registry()
        registry.SetValueEx.side_effect = OSError("denied")
        with patch.dict(sys.modules, {"winreg": registry}), self.assertRaises(RuntimeError):
            RUNTIME.accept_windows_eula("9.4")

    def test_unix_requires_registry_file(self):
        for system in ("Darwin", "Linux"):
            self.assertFalse(RUNTIME.accepted_ida_configuration(self.source, system, "9.4"))
        (self.source / "ida.reg").write_text("accepted fixture")
        for system in ("Darwin", "Linux"):
            self.assertTrue(RUNTIME.accepted_ida_configuration(self.source, system, "9.4"))

    def test_windows_template_does_not_require_unix_file(self):
        RUNNER.copy_ida_configuration(self.source, self.destination, windows=True)
        self.assertEqual(
            (self.destination / "ida-config.json").read_bytes(),
            (self.source / "ida-config.json").read_bytes(),
        )
        self.assertFalse((self.destination / "ida.reg").exists())

    def test_unix_template_still_requires_registry_file(self):
        with self.assertRaises(SystemExit):
            RUNNER.copy_ida_configuration(self.source, self.destination, windows=False)


if __name__ == "__main__":
    unittest.main()
