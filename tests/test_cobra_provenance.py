"""Fault-inject the independent vendor patch replay contract."""

from __future__ import annotations
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "cobra_provenance", Path(__file__).resolve().parents[1] / "cmake/verify_cobra_provenance.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.vendor = self.root / "vendor/cobra"
        self.vendor.mkdir(parents=True)
        self.environment = dict(
            os.environ,
            GIT_AUTHOR_NAME="Fixture",
            GIT_AUTHOR_EMAIL="fixture@example.invalid",
            GIT_COMMITTER_NAME="Fixture",
            GIT_COMMITTER_EMAIL="fixture@example.invalid",
        )
        self.git("init", "-q")
        (self.vendor / "input.txt").write_text("base\n")
        self.git("add", "input.txt")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD").strip()
        (self.vendor / "input.txt").write_text("patched\n")
        (self.vendor / "added.txt").write_text("addition\n")
        self.git("add", "input.txt", "added.txt")
        self.patch = self.root / "patches/cobra/0001.patch"
        self.patch.parent.mkdir(parents=True)
        self.patch.write_bytes(
            self.git("diff", "--no-ext-diff", "--no-textconv", "--cached", "--binary").encode(
                "utf-8"
            )
        )
        self.git("commit", "-qm", "patch")
        self.tree = self.git("rev-parse", "HEAD^{tree}").strip()
        self.digest = hashlib.sha256(self.patch.read_bytes()).hexdigest()

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-C", str(self.vendor), *args], env=self.environment, text=True
        )

    def verify(self, digest=None, tree=None):
        return MODULE.verify(
            self.root,
            self.root / "build",
            self.base,
            tree or self.tree,
            [("patches/cobra/0001.patch", digest or self.digest)],
        )

    def test_exact_replay_preserves_source_index_and_worktree(self):
        index = self.vendor / ".git/index"
        before = index.read_bytes()
        self.assertEqual(self.verify(), self.tree)
        self.assertEqual(index.read_bytes(), before)
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=all"), "")

    def test_alternate_commit_metadata_is_allowed(self):
        self.git("commit", "--allow-empty", "-qm", "metadata-only descendant")
        self.assertEqual(self.verify(), self.tree)

    def test_patch_digest_tampering_rejected(self):
        with self.assertRaises(RuntimeError):
            self.verify(digest="0" * 64)

    def test_tracked_and_untracked_dirt_rejected(self):
        for name in ("input.txt", "untracked.txt"):
            path = self.vendor / name
            old = path.read_bytes() if path.exists() else None
            path.write_text("dirty\n")
            with self.assertRaises(RuntimeError):
                self.verify()
            if old is None:
                path.unlink()
            else:
                path.write_bytes(old)

    def test_manifest_tree_tampering_rejected(self):
        with self.assertRaises(RuntimeError):
            self.verify(tree="0" * 40)

    def test_different_replayed_contents_rejected_even_with_matching_digest(self):
        raw = self.patch.read_text().replace("+patched", "+forged")
        self.patch.write_bytes(raw.encode("utf-8"))
        with self.assertRaises(RuntimeError):
            self.verify(digest=hashlib.sha256(self.patch.read_bytes()).hexdigest())

    def test_unrecorded_committed_change_rejected(self):
        (self.vendor / "extra.txt").write_text("extra\n")
        self.git("add", "extra.txt")
        self.git("commit", "-qm", "extra")
        with self.assertRaises(RuntimeError):
            self.verify(tree=self.git("rev-parse", "HEAD^{tree}").strip())

    def test_empty_and_duplicate_series_rejected(self):
        for patches in ([], [("patches/cobra/0001.patch", self.digest)] * 2):
            with self.assertRaises(RuntimeError):
                MODULE.verify(self.root, self.root / "build", self.base, self.tree, patches)


if __name__ == "__main__":
    unittest.main()
