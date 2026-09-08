"""Runner isolation, artifact attribution, and classification without IDA."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class RunReportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.template = self.root / "template"
        self.template.mkdir()
        for name in ("ida.reg", "ida-config.json"):
            (self.template / name).write_text("{}")
        self.binary = self.root / "fixture.bin"
        self.binary.write_bytes(b"fixture input")
        self.plugin = self.root / "plugin.bin"
        self.plugin.write_bytes(b"fixture plugin")
        self.probe = self.root / "probe.py"
        self.probe.write_text("# fixture probe\n")
        self.executable = self.root / "fake-ida"
        self.run_number = 0

    def run_fixture(
        self, *, write_log=True, exit_code=0, before_probe="", after_probe="",
        inherited=None, assignments=(),
    ):
        self.executable.write_text(
            "#!%s\n" % sys.executable
            + "import json, os, pathlib, runpy, sys\n"
            + "probe = pathlib.Path(next(x[2:] for x in sys.argv if x.startswith('-S')))\n"
            + "log = pathlib.Path(next(x[2:] for x in sys.argv if x.startswith('-L')))\n"
            + before_probe
            + "\nrunpy.run_path(str(probe), run_name='__main__')\n"
            + after_probe
            + "\n"
            + ("log.write_text('[chernobog][fixture] PASS\\n')\n"
               if write_log else "")
            + "sys.exit(%d)\n" % exit_code
        )
        self.executable.chmod(0o755)
        initial_hashes = {
            key: hashlib.sha256(path.read_bytes()).hexdigest()
            for key, path in (
                ("input_sha256", self.binary),
                ("plugin_sha256", self.plugin),
                ("script_sha256", self.probe),
                ("ida_sha256", self.executable),
            )
        }
        self.run_number += 1
        self.output = self.root / ("run%d" % self.run_number)
        environment = os.environ.copy()
        environment.update(inherited or {})
        command = [
            sys.executable, str(Path(__file__).with_name("run_ida_smoke.py")),
            "--ida", str(self.executable), "--plugin", str(self.plugin),
            "--ida-user-template", str(self.template),
            "--output-dir", str(self.output),
        ]
        for assignment in assignments:
            command.extend(["--set", assignment])
        command.extend([str(self.binary), str(self.probe)])
        result = subprocess.run(command, env=environment, capture_output=True, text=True)
        report_path = self.output / "run.json"
        self.assertTrue(report_path.is_file(), result.stderr)
        report = json.loads(report_path.read_text())
        for key, digest in initial_hashes.items():
            self.assertEqual(report[key], digest, key)
        self.assertEqual(report["schema_version"], 2)
        self.assertIsInstance(report["process_elapsed_ns"], int)
        self.assertGreater(report["process_elapsed_ns"], 0)
        self.assertEqual(report["process_return_code"], exit_code)
        self.assertEqual(report["runner_return_code"], result.returncode)
        self.assertEqual(report["expected_log_found"], write_log)
        return result, report

    def test_success(self):
        result, report = self.run_fixture()
        self.assertEqual(result.returncode, 0)
        for key in (
            "source_input_unchanged", "script_unchanged", "source_script_unchanged",
            "plugin_unchanged", "ida_unchanged", "input_copy_matches_source",
            "artifacts_unchanged",
        ):
            self.assertTrue(report[key], key)
        self.assertEqual(report["ida_sha256"], report["ida_sha256_after"])
        self.assertEqual((self.output / "probe" / self.probe.name).read_bytes(),
                         self.probe.read_bytes())

    def test_missing_log_is_a_failed_assertion(self):
        result, _ = self.run_fixture(write_log=False)
        self.assertEqual(result.returncode, 124)

    def test_process_failure_precedes_pass_marker(self):
        result, _ = self.run_fixture(exit_code=7)
        self.assertEqual(result.returncode, 7)

    def test_inherited_options_are_removed_and_explicit_values_survive(self):
        self.probe.write_text(
            "import os\n"
            "assert 'CHERNOBOG_DISABLE' not in os.environ\n"
            "assert os.environ['CHERNOBOG_RAX_MAX_INSNS'] == '123'\n"
            "assert os.environ['CHERNOBOG_AUTO'] == '1'\n"
            "assert os.environ['CHERNOBOG_RAX_DISABLE'] == '1'\n"
            "assert os.environ['FIXTURE_SECRET'] == 'private-fixture-value'\n"
        )
        result, report = self.run_fixture(
            inherited={"CHERNOBOG_DISABLE": "1", "CHERNOBOG_RAX_MAX_INSNS": "9"},
            assignments=("CHERNOBOG_RAX_MAX_INSNS=123", "FIXTURE_SECRET=private-fixture-value"),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        serialized = json.dumps(report)
        self.assertNotIn("private-fixture-value", serialized + result.stdout + result.stderr)
        self.assertNotIn("FIXTURE_SECRET", serialized)

    def test_environment_digest_is_canonical_and_sensitive_to_effective_options(self):
        _, first = self.run_fixture(
            assignments=("CHERNOBOG_TEST_A=1", "CHERNOBOG_TEST_B=2"))
        _, reordered = self.run_fixture(
            inherited={"CHERNOBOG_DISABLE": "1"},
            assignments=("CHERNOBOG_TEST_B=2", "CHERNOBOG_TEST_A=0", "CHERNOBOG_TEST_A=1"))
        _, different = self.run_fixture(
            assignments=("CHERNOBOG_TEST_A=2", "CHERNOBOG_TEST_B=2"))
        self.assertEqual(first["chernobog_environment_sha256"],
                         reordered["chernobog_environment_sha256"])
        self.assertNotEqual(first["chernobog_environment_sha256"],
                            different["chernobog_environment_sha256"])
        configuration = {
            "CHERNOBOG_AUTO": "1", "CHERNOBOG_VERBOSE": "0",
            "CHERNOBOG_PLUGIN_PRELOADED": "1", "CHERNOBOG_RAX_DISABLE": "1",
            "CHERNOBOG_RAX_ENABLED": "0", "CHERNOBOG_RAX_APPLY_ANALYSIS": "0",
            "CHERNOBOG_TEST_A": "1", "CHERNOBOG_TEST_B": "2",
        }
        canonical = json.dumps(configuration, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True).encode("utf-8")
        self.assertEqual(first["chernobog_environment_sha256"],
                         hashlib.sha256(canonical).hexdigest())

    def test_source_probe_mutation_does_not_change_executed_copy(self):
        result, report = self.run_fixture(
            before_probe="pathlib.Path(%r).write_text('raise RuntimeError(\"changed\")\\n')\n"
            % str(self.probe))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(report["source_script_unchanged"])
        self.assertTrue(report["script_unchanged"])
        self.assertTrue(report["artifacts_unchanged"])

    def test_copied_probe_mutation_fails_attribution(self):
        result, report = self.run_fixture(after_probe="probe.write_text('# changed\\n')")
        self.assertEqual(result.returncode, 125)
        self.assertFalse(report["script_unchanged"])
        self.assertFalse(report["artifacts_unchanged"])

    def test_installed_plugin_deletion_fails_attribution(self):
        result, report = self.run_fixture(
            after_probe="pathlib.Path(os.environ['CHERNOBOG_PLUGIN_PATH']).unlink()")
        self.assertEqual(result.returncode, 125)
        self.assertFalse(report["plugin_unchanged"])
        self.assertFalse(report["artifacts_unchanged"])

    def test_executable_mutation_fails_attribution(self):
        result, report = self.run_fixture(
            after_probe="pathlib.Path(sys.argv[0]).write_text('# changed\\n')")
        self.assertEqual(result.returncode, 125)
        self.assertFalse(report["ida_unchanged"])
        self.assertNotEqual(report["ida_sha256"], report["ida_sha256_after"])

    def test_source_input_deletion_precedes_process_and_log_failure(self):
        result, report = self.run_fixture(
            write_log=False, exit_code=7,
            after_probe="pathlib.Path(%r).unlink()" % str(self.binary))
        self.assertEqual(result.returncode, 125)
        self.assertFalse(report["source_input_unchanged"])


if __name__ == "__main__":
    unittest.main()
