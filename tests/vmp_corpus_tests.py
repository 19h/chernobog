"""Corpus admission controls; native/protected ISA checks live in the real corpus."""
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
from vmp_corpus.linux32 import Linux32
import run_vmp_conditions as conditions

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("vmp_corpus", Path(__file__).with_name("run_vmp_corpus.py"))
corpus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corpus)


def valid_rows(seed):
    rows = []
    for index, (x, y, memory) in enumerate(corpus.inputs(seed)):
        for function in (0, 1):
            result, flags, delta, before, changed, after = corpus.expected(function, x, y, memory)
            rows.append(f"{index} {function} {x:08x} {y:08x} {memory:08x} {result:016x} {flags:04x} {delta} {before:08x} {changed:08x} {after:08x}")
    return rows


class CorpusTests(unittest.TestCase):
    def test_linux32_container_cleanup_and_pinned_image(self):
        runtime = Linux32.__new__(Linux32)
        runtime.docker = ["docker", "--context", "test"]
        runtime.image = "sha256:" + "a" * 64
        runtime.mounts = []
        failure = {"exit_code": -9, "timed_out": True, "output_exceeded": False}
        with patch("vmp_corpus.linux32.execute", side_effect=[(failure, b"", b""), ({"exit_code": 0}, b"", b"")]) as run:
            self.assertEqual(runtime.execute(["guest-command"])[0], failure)
            start = run.call_args_list[0].args[0]
            name = start[start.index("--name") + 1]
            self.assertTrue(name.startswith("chernobog-vmp32-"))
            self.assertEqual(start[-2:], [runtime.image, "guest-command"])
            self.assertEqual(run.call_args_list[1].args[0], runtime.docker + ["rm", "-f", name])
            self.assertIn("--read-only", start)
            self.assertEqual(start[start.index("--network") + 1], "none")

    def test_linux32_guest_identity_is_complete(self):
        with tempfile.TemporaryDirectory() as temp:
            runtime = Linux32.__new__(Linux32)
            runtime.output = Path(temp)
            (runtime.output / "guest-runs").mkdir()
            binary = runtime.output / "original"
            binary.write_bytes(b"fixture")
            stdout = runtime.output / "guest-runs/original-1.txt"
            stdout.write_bytes(b"observation")
            report = runtime.output / "guest-runs/original-1.json"
            hashes = {name: "a" * 64 for name in ("qemu-i386", "ld-linux.so.2", "libc.so.6")}
            runtime.metadata = {"sha256": hashes}
            good = {"binary_unchanged": True, "binary_sha256": corpus.digest(binary),
                    "stdout_sha256": corpus.digest(stdout), "runtime_sha256": hashes}
            launcher = {"exit_code": 0, "timed_out": False, "output_exceeded": False}
            with patch.object(runtime, "execute", return_value=(launcher, b"", b"")):
                report.write_text(json.dumps(good))
                self.assertEqual(runtime.run(binary, 1)[1], b"observation")
                for replacement in ({"binary_unchanged": False}, {"binary_sha256": "0" * 64},
                                    {"stdout_sha256": "0" * 64}, {"runtime_sha256": {}},
                                    {"runtime_sha256": dict(hashes, **{"qemu-i386": "0" * 64})}):
                    report.write_text(json.dumps(dict(good, **replacement)))
                    with self.assertRaises(RuntimeError):
                        runtime.run(binary, 1)

    def test_elf32_bounds_architecture_and_load_mapping(self):
        data = bytearray(512)
        struct.pack_into("<16sHHIIIIIHHHHHH", data, 0, b"\x7fELF\x01\x01\x01", 2, 3, 1,
                         0x8048080, 52, 256, 0, 52, 32, 1, 40, 3, 2)
        struct.pack_into("<8I", data, 52, 1, 0, 0x8048000, 0x8048000, 512, 512, 5, 4096)
        data[84:101] = b"\0.text\0.shstrtab\0"
        data[128] = 0xC3
        struct.pack_into("<10I", data, 296, 1, 1, 6, 0x8048080, 128, 1, 0, 0, 1, 0)
        struct.pack_into("<10I", data, 336, 7, 3, 0, 0, 84, 17, 0, 0, 1, 0)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "elf32"
            path.write_bytes(data)
            section = corpus.text_section(path)
            self.assertTrue(section["file_backed"])
            self.assertEqual(corpus.function_bytes(path, section, 0x8048080, 1), b"\xc3")
            for offset, width, value in ((4, "B", 2), (5, "B", 2), (18, "H", 62), (28, "I", 500),
                                          (32, "I", 500), (42, "H", 31), (44, "H", 0), (46, "H", 39),
                                          (48, "H", 4097), (50, "H", 3), (296, "I", 99), (72, "I", 1)):
                with self.subTest(offset=offset):
                    changed = bytearray(data)
                    struct.pack_into("<" + width, changed, offset, value)
                    path.write_bytes(changed)
                    with self.assertRaises(ValueError):
                        corpus.text_section(path)
            for offset, value in ((300, 8), (304, 0), (312, 129), (76, 4)):
                changed = bytearray(data)
                struct.pack_into("<I", changed, offset, value)
                path.write_bytes(changed)
                section = corpus.text_section(path)
                self.assertFalse(section["file_backed"])
                with self.assertRaises(ValueError):
                    corpus.function_bytes(path, section, 0x8048080, 1)
            changed = bytearray(data)
            struct.pack_into("<H", changed, 48, 4)
            changed[376:416] = changed[296:336]
            path.write_bytes(changed)
            with self.assertRaises(ValueError):
                corpus.text_section(path)

    def test_independent_corner_values(self):
        self.assertEqual(corpus.expected(0, 0, 1, 0)[:2], (1, 0))
        self.assertEqual(corpus.expected(0, 0, 1, 0xFFFFFFFF)[:2], (0, 0x55))
        self.assertEqual(corpus.expected(0, 0, 1, 0xFBFFFFFF)[:2], (0x80000000, 0x894))
        self.assertEqual(corpus.expected(1, 0, 1, 0)[:2], (33, 4))

    def test_parser_accepts_complete_records(self):
        for seed in corpus.INPUT_SEEDS:
            result = corpus.verify(("\n".join(valid_rows(seed)) + "\n").encode(), seed)
            self.assertTrue(result["passed"])
            self.assertEqual(result["rows"], 560)

    def test_every_observable_and_identity_rejected_when_changed(self):
        rows = valid_rows(corpus.INPUT_SEEDS[0])
        for field in range(11):
            with self.subTest(field=field):
                damaged = rows.copy()
                values = damaged[0].split()
                values[field] = "9"
                damaged[0] = " ".join(values)
                self.assertFalse(corpus.verify("\n".join(damaged).encode(), corpus.INPUT_SEEDS[0])["passed"])

    def test_record_cardinality_and_format(self):
        rows = valid_rows(corpus.INPUT_SEEDS[0])
        for damaged in (rows[:-1], rows + rows[:1], ["bad record"] + rows[1:]):
            self.assertFalse(corpus.verify("\n".join(damaged).encode(), corpus.INPUT_SEEDS[0])["passed"])
        for field in range(11):
            damaged = rows.copy()
            values = damaged[0].split()
            values[field] = "invalid"
            damaged[0] = " ".join(values)
            self.assertFalse(corpus.verify("\n".join(damaged).encode(), corpus.INPUT_SEEDS[0])["passed"])
        self.assertFalse(corpus.verify(b"\xff", corpus.INPUT_SEEDS[0])["passed"])

    def test_execution_environment_excludes_inherited_injection(self):
        with patch.dict(corpus.os.environ, {"DYLD_INSERT_LIBRARIES": "inherited", "DYLD_LIBRARY_PATH": "inherited",
                                           "LD_PRELOAD": "inherited", "LD_LIBRARY_PATH": "inherited",
                                           "CHERNOBOG_CORPUS_TEST": "retained"}, clear=True):
            self.assertEqual(corpus.base_environment(), {"CHERNOBOG_CORPUS_TEST": "retained"})

    def test_process_limits_and_accounting(self):
        measurement, out, _ = corpus.execute([sys.executable, "-c", "print('ok')"])
        self.assertEqual(measurement["exit_code"], 0)
        self.assertEqual(out, b"ok\n")
        self.assertGreater(measurement["elapsed_ns"], 0)
        self.assertGreater(measurement["peak_resident_bytes"], 0)
        measurement, _, _ = corpus.execute([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.05)
        self.assertTrue(measurement["timed_out"])
        self.assertLess(measurement["exit_code"], 0)
        measurement, out, _ = corpus.execute([sys.executable, "-c", "import sys; sys.stdout.write('x' * (2*1024*1024+1))"])
        self.assertTrue(measurement["output_exceeded"])
        self.assertLessEqual(len(out), 2*1024*1024)

    def test_macho_bounds_and_initialized_text(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "image"
            for invalid in (b"", b"\x00"*32, struct.pack("<8I", 0xFEEDFACF, 0, 0, 0, 1, 999, 0, 0)):
                path.write_bytes(invalid)
                with self.assertRaises(ValueError):
                    corpus.text_section(path)
            header = struct.pack("<8I", 0xFEEDFACF, 0, 0, 0, 1, 152, 0, 0)
            segment = struct.pack("<II16sQQQQIIII", 0x19, 152, b"__TEXT", 0x1000, 4096, 0, 185, 7, 5, 1, 0)
            section = struct.pack("<16s16sQQ8I", b"__text", b"__TEXT", 0x1100, 1, 184, 0, 0, 0, 0, 0, 0, 0)
            path.write_bytes(header+segment+section+b"\xc3")
            text = corpus.text_section(path)
            self.assertTrue(text["file_backed"])
            self.assertEqual(corpus.function_bytes(path, text, 0x1100, 1), b"\xc3")
            with self.assertRaises(ValueError):
                corpus.function_bytes(path, text, 0x1101, 1)
            data = bytearray(path.read_bytes())
            struct.pack_into("<I", data, 32+72+64, 1)
            path.write_bytes(data)
            self.assertFalse(corpus.text_section(path)["file_backed"])
            with self.assertRaises(ValueError):
                corpus.function_bytes(path, corpus.text_section(path), 0x1100, 1)


class ConditionMeasurementTests(unittest.TestCase):
    @staticmethod
    def fixture():
        return {"entries": {"entry": {"instructions": [{"ea": 100, "kind": "setcc", "owner": None}],
                                       "truncated": False}},
                "owners_omitted": 0, "reachability_preserved": True,
                "owners": [{"entry": 10, "status": "inspected", "native_head_count": 2,
                            "native_truncated": False, "native_sha256": "same native input", "flags_before": 0,
                            "conditions": [{"ea": 11, "kind": "cmov"}], "native_preserved": True,
                            "generated": {"status": "captured", "capture_truncated": False,
                                          "microcode_sha256": "same IR", "conditions": {"11": ["native condition"]},
                                          "codegen_delta": {"codegen_setcc": 0, "codegen_cmov": 0, "codegen_cmov_memory": 0}},
                            "decompiled": {"status": "success", "sha256": "same pseudocode"}}]}

    def test_ownerless_sites_are_not_counted_as_emissions(self):
        report = self.fixture()
        summary = conditions.summarize(report)
        self.assertEqual(summary["reachable_condition_sites"], 1)
        self.assertEqual(summary["ownerless_condition_sites"], 1)
        self.assertEqual(summary["owned_function_condition_sites"], 1)
        self.assertEqual(summary["codegen_events"], {"codegen_setcc": 0, "codegen_cmov": 0, "codegen_cmov_memory": 0})
        self.assertEqual(summary["decompiled_successes"], 1)

    def test_failed_generation_is_not_successful_recovery(self):
        report = self.fixture()
        report["owners"][0]["generated"] = {"status": "failed", "failure_code": -1,
                                            "codegen_delta": {"codegen_cmov": 1}}
        report["owners"][0]["decompiled"] = {"status": "failed", "failure_code": -2}
        report["owners"].append({"entry": 200, "status": "native_budget", "conditions": []})
        summary = conditions.summarize(report)
        self.assertEqual(summary["generated_successes"], 0)
        self.assertEqual(summary["decompiled_successes"], 0)
        self.assertEqual(summary["native_budget_skips"], 1)
        self.assertEqual(summary["generated_failures"][0]["failure_code"], -1)
        # This counter is an emission event, explicitly not a recovered function.
        self.assertEqual(summary["codegen_events"]["codegen_cmov"], 1)

    def test_changed_native_input_or_active_baseline_rejects_comparison(self):
        import copy
        for mutation in ("native", "scope", "baseline"):
            off, on = self.fixture(), self.fixture()
            if mutation == "native":
                on["owners"][0]["native_sha256"] = "different input"
            elif mutation == "scope":
                on["entries"] = copy.deepcopy(on["entries"])
                on["entries"]["entry"]["instructions"][0]["owner"] = 10
            else:
                off["owners"][0]["generated"]["codegen_delta"]["codegen_setcc"] = 1
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                conditions.compare(off, on)

    def test_truncated_capture_is_not_an_unchanged_result(self):
        off, on = self.fixture(), self.fixture()
        on["owners"][0]["generated"]["capture_truncated"] = True
        comparison = conditions.compare(off, on)["owners"][0]
        self.assertFalse(comparison["generated_comparable"])
        self.assertIsNone(comparison["generated_changed"])

    def test_changed_condition_capture_is_located(self):
        off, on = self.fixture(), self.fixture()
        on["owners"][0]["generated"]["microcode_sha256"] = "changed IR"
        on["owners"][0]["generated"]["conditions"]["11"] = ["lowered condition"]
        on["owners"][0]["generated"]["codegen_delta"]["codegen_cmov"] = 1
        comparison = conditions.compare(off, on)["owners"][0]
        self.assertTrue(comparison["generated_changed"])
        self.assertEqual(comparison["changed_condition_sites"], [11])
        self.assertFalse(comparison["decompiled_text_changed"])


if __name__ == "__main__":
    unittest.main()
