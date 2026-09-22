#!/usr/bin/env python3

import argparse
import glob
import os
import stat
import sys


def pick(*patterns: str) -> str | None:
    matches = []
    for pattern in patterns:
        matches.extend(glob.glob(pattern))
    matches = sorted(
        {match for match in matches if os.path.isfile(match) and os.access(match, os.X_OK)}
    )
    return matches[-1] if matches else None


def write_wrapper(path: str, command: str) -> None:
    with open(path, "w", encoding="ascii") as handle:
        handle.write("#!/usr/bin/env bash\n")
        handle.write("set -euo pipefail\n")
        handle.write(f'exec {command} "$@"\n')
    os.chmod(
        path,
        stat.S_IRUSR
        | stat.S_IWUSR
        | stat.S_IXUSR
        | stat.S_IRGRP
        | stat.S_IXGRP
        | stat.S_IROTH
        | stat.S_IXOTH,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Create unversioned LLVM shim binaries")
    parser.add_argument("output_dir", help="Directory where wrapper binaries should be written")
    args = parser.parse_args()

    out_dir = os.path.abspath(args.output_dir)
    os.makedirs(out_dir, exist_ok=True)

    clang = pick("/usr/bin/clang", "/usr/bin/clang-*", "/usr/lib/llvm-*/bin/clang")
    lld_link = pick("/usr/bin/lld-link", "/usr/bin/lld-link-*", "/usr/lib/llvm-*/bin/lld-link")
    ld_lld = pick("/usr/bin/ld.lld", "/usr/bin/ld.lld-*", "/usr/lib/llvm-*/bin/ld.lld")
    llvm_lib = pick("/usr/bin/llvm-lib", "/usr/bin/llvm-lib-*", "/usr/lib/llvm-*/bin/llvm-lib")
    llvm_rc = pick("/usr/bin/llvm-rc", "/usr/bin/llvm-rc-*", "/usr/lib/llvm-*/bin/llvm-rc")

    missing = []
    if not clang:
        missing.append("clang")
    if not lld_link and not ld_lld:
        missing.append("lld-link or ld.lld")
    if not llvm_lib:
        missing.append("llvm-lib")
    if not llvm_rc:
        missing.append("llvm-rc")

    if missing:
        print(f"Missing LLVM tools: {', '.join(missing)}", file=sys.stderr)
        return 1

    write_wrapper(os.path.join(out_dir, "clang-cl"), f'"{clang}" --driver-mode=cl')
    write_wrapper(os.path.join(out_dir, "llvm-lib"), f'"{llvm_lib}"')
    write_wrapper(os.path.join(out_dir, "llvm-rc"), f'"{llvm_rc}"')
    if lld_link:
        write_wrapper(os.path.join(out_dir, "lld-link"), f'"{lld_link}"')
        lld_description = lld_link
    else:
        write_wrapper(os.path.join(out_dir, "lld-link"), f'"{ld_lld}" -flavor link')
        lld_description = f"{ld_lld} -flavor link"

    print(f"Prepared LLVM shims in {out_dir}")
    print(f"  clang-cl -> {clang} --driver-mode=cl")
    print(f"  llvm-lib -> {llvm_lib}")
    print(f"  llvm-rc  -> {llvm_rc}")
    print(f"  lld-link -> {lld_description}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
