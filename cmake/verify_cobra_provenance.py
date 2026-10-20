"""Verify an ordered CoBRA patch series without changing its checkout or index."""

from __future__ import annotations
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile


def git(root, *arguments, environment=None):
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        env=dict(os.environ if environment is None else environment, GIT_OPTIONAL_LOCKS="0"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        raise RuntimeError("Git provenance operation failed: " + arguments[0])
    return result.stdout


def verify(root, storage, base, expected, patches):
    vendor = root / "vendor/cobra"
    git(vendor, "merge-base", "--is-ancestor", base, "HEAD")
    if git(vendor, "status", "--porcelain", "--untracked-files=all").strip():
        raise RuntimeError("CoBRA worktree is dirty")
    actual = git(vendor, "rev-parse", "HEAD^{tree}").decode().strip()
    if actual != expected:
        raise RuntimeError("CoBRA HEAD tree does not match the recorded tree")
    objects = Path(
        git(vendor, "rev-parse", "--path-format=absolute", "--git-path", "objects").decode().strip()
    )
    storage.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cobra-replay-", dir=storage) as directory:
        temporary = Path(directory)
        object_store = temporary / "objects"
        object_store.mkdir()
        environment = os.environ.copy()
        environment.update(
            GIT_INDEX_FILE=str(temporary / "index"),
            GIT_OBJECT_DIRECTORY=str(object_store),
            GIT_ALTERNATE_OBJECT_DIRECTORIES=str(objects),
        )
        git(vendor, "read-tree", base, environment=environment)
        previous = git(vendor, "rev-parse", base + "^{tree}").decode().strip()
        touched = set()
        seen = set()
        for name, digest in patches:
            path = (root / name).resolve()
            if (
                path.parent != (root / "patches/cobra").resolve()
                or path.suffix != ".patch"
                or name in seen
            ):
                raise RuntimeError("Invalid or duplicate CoBRA patch path")
            seen.add(name)
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise RuntimeError("CoBRA patch SHA-256 mismatch: " + name)
            git(
                vendor,
                "apply",
                "--cached",
                "--binary",
                "--whitespace=error",
                str(path),
                environment=environment,
            )
            current = git(vendor, "write-tree", environment=environment).decode().strip()
            touched.update(
                git(
                    vendor,
                    "diff",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--name-only",
                    "--no-renames",
                    "-z",
                    previous,
                    current,
                    environment=environment,
                ).split(b"\0")
            )
            previous = current
        if not seen or previous != expected:
            raise RuntimeError("CoBRA patch replay does not produce the recorded tree")
        changed = set(
            git(
                vendor,
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--name-only",
                "--no-renames",
                "-z",
                base,
                "HEAD",
            ).split(b"\0")
        )
        if not changed <= touched:
            raise RuntimeError("CoBRA HEAD changes an unrecorded path")
    return actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--storage", type=Path, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--patch", nargs=2, action="append", default=[])
    args = parser.parse_args()
    try:
        tree = verify(
            args.root.resolve(), args.storage.resolve(), args.base, args.expected, args.patch
        )
    except OSError:
        parser.exit(1, "CoBRA provenance rejected: missing or unreadable input\n")
    except RuntimeError as error:
        parser.exit(1, "CoBRA provenance rejected: " + str(error) + "\n")
    print("CoBRA provenance verified: " + tree)


if __name__ == "__main__":
    main()
