"""Prevent restored object timestamps from authenticating changed project headers."""

from pathlib import Path
import tempfile
import unittest

from tools.ci_refresh_build_tree import ROOT, refresh


class RefreshBuildTreeTests(unittest.TestCase):
    def test_project_objects_removed_dependencies_retained(self):
        (ROOT / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "build") as temporary:
            build = Path(temporary)
            project = [
                "CMakeFiles/unit.dir/source.cpp.o",
                "unit.dir/Release/source.obj",
                "CMakeCache.txt",
            ]
            dependencies = [
                "_deps/z3-build/CMakeFiles/z3.dir/solver.cpp.o",
                "cobra/core/CMakeFiles/cobra-core.dir/Expr.cpp.o",
                "rax-target/release/librax.a",
            ]
            for name in project + dependencies:
                path = build / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"retained fixture")
            refresh(build)
            self.assertTrue(all(not (build / name).exists() for name in project))
            self.assertTrue(
                all((build / name).read_bytes() == b"retained fixture" for name in dependencies)
            )

    def test_checkout_root_rejected(self):
        with self.assertRaises(ValueError):
            refresh(ROOT)


if __name__ == "__main__":
    unittest.main()
