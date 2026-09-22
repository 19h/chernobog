"""Measure the QEMU process inside the isolated Linux guest, not Docker's CLI."""
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from run_vmp_corpus import digest, execute


def main():
    binary, seed, report, observations = sys.argv[1:]
    before = digest(binary)
    result, out, _ = execute(["/usr/bin/qemu-i386", "-L", "/usr/i686-linux-gnu", binary, seed], timeout=10)
    result["binary_sha256"] = before
    result["binary_unchanged"] = digest(binary) == before
    result["accounting_scope"] = "Linux wait4 of qemu-i386 process, including translated guest execution"
    result["runtime_sha256"] = {name: digest(path) for name, path in (
        ("qemu-i386", "/usr/bin/qemu-i386"),
        ("ld-linux.so.2", "/usr/i686-linux-gnu/lib/ld-linux.so.2"),
        ("libc.so.6", "/usr/i686-linux-gnu/lib/libc.so.6"))}
    Path(observations).write_bytes(out)
    Path(report).write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
