"""Discard restored project compilation state while retaining dependency builds."""

import argparse
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]


def refresh(directory):
    directory = directory.resolve()
    if directory == ROOT or not directory.is_relative_to(ROOT):
        raise ValueError("Build directory must be inside the checkout")
    if not directory.exists():
        return
    # Checkout timestamps may precede cached objects from a concurrent run.
    # Regenerating top-level CMake state also discards mixed class layouts.
    generated = [directory / "CMakeFiles", directory / "CMakeCache.txt", *directory.glob("*.dir")]
    for path in generated:
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    args = parser.parse_args()
    refresh(args.build_dir)
    print("Refreshed project compilation state; dependency builds retained")


if __name__ == "__main__":
    main()
