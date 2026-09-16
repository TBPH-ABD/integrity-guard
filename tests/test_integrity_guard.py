"""Tests for integrity-guard baselining and change detection."""
from __future__ import annotations

import json
import os
import tempfile
import unittest

import integrity_guard
from integrity_guard import (DEFAULT_EXCLUDES, compare, file_digest,
                             is_excluded, snapshot)
from tests.support.fakes import capture_cli


class TreeTestCase(unittest.TestCase):
    """Builds a real directory tree in a temp dir. Nothing is mocked."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.write("index.html", "home")
        self.write("config.php", "secrets")
        self.write("assets/app.js", "console.log(1)")

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, relative: str, content: str) -> str:
        path = os.path.join(self.root, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path

    def snap(self, excludes=None):
        return snapshot(self.root, excludes if excludes is not None else [])

    def changes(self, before, excludes=None):
        return compare(before, self.snap(excludes))

    @staticmethod
    def by_kind(changes):
        return {c.kind: c for c in changes}


class TestDigest(unittest.TestCase):
    def test_same_content_same_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = os.path.join(tmp, "a"), os.path.join(tmp, "b")
            for path in (a, b):
                with open(path, "w") as fh:
                    fh.write("identical")
            self.assertEqual(file_digest(a), file_digest(b))

    def test_different_content_different_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = os.path.join(tmp, "a"), os.path.join(tmp, "b")
            with open(a, "w") as fh:
                fh.write("one")
            with open(b, "w") as fh:
                fh.write("two")
            self.assertNotEqual(file_digest(a), file_digest(b))

    def test_large_file_is_streamed(self):
        # Exceeds the 1 MiB chunk size, exercising the streaming loop.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "big")
            with open(path, "wb") as fh:
                fh.write(b"x" * (1024 * 1024 * 2 + 17))
            self.assertEqual(len(file_digest(path)), 64)


class TestExclusion(unittest.TestCase):
    def test_matching_glob_is_excluded(self):
        self.assertTrue(is_excluded("app.log", ["*.log"]))

    def test_non_matching_glob_is_kept(self):
        self.assertFalse(is_excluded("app.py", ["*.log"]))

    def test_default_excludes_cover_common_noise(self):
        self.assertTrue(is_excluded("debug.log", DEFAULT_EXCLUDES))
        self.assertTrue(is_excluded(".git/config", DEFAULT_EXCLUDES))
        self.assertTrue(is_excluded("node_modules/x/index.js", DEFAULT_EXCLUDES))


class TestSnapshot(TreeTestCase):
    def test_records_every_file(self):
        data = self.snap()
        self.assertEqual(data["file_count"], 3)
        self.assertIn("index.html", data["files"])
        self.assertIn(os.path.join("assets", "app.js"), data["files"])

    def test_records_metadata_not_just_content(self):
        entry = self.snap()["files"]["index.html"]
        for field in ("sha256", "size", "mode", "uid", "gid"):
            self.assertIn(field, entry)

    def test_excluded_files_are_absent(self):
        self.write("debug.log", "noise")
        self.assertNotIn("debug.log", self.snap(["*.log"])["files"])

    def test_excluded_directories_are_pruned(self):
        self.write("node_modules/pkg/index.js", "x")
        files = self.snap(["node_modules/*"])["files"]
        self.assertFalse(any("node_modules" in f for f in files))

    def test_symlink_is_recorded_by_target_not_followed(self):
        os.symlink(os.path.join(self.root, "index.html"),
                   os.path.join(self.root, "link.html"))
        entry = self.snap()["files"]["link.html"]
        self.assertTrue(entry["sha256"].startswith("symlink:"))


class TestCompare(TreeTestCase):
    def test_no_changes_when_tree_is_untouched(self):
        self.assertEqual(self.changes(self.snap()), [])

    def test_added_file_is_detected(self):
        before = self.snap()
        self.write("evil.php", "<?php system($_GET['c']); ?>")
        found = self.by_kind(self.changes(before))
        self.assertIn("added", found)
        self.assertEqual(found["added"].path, "evil.php")

    def test_deleted_file_is_detected(self):
        before = self.snap()
        os.remove(os.path.join(self.root, "config.php"))
        self.assertIn("deleted", self.by_kind(self.changes(before)))

    def test_modified_content_is_detected(self):
        before = self.snap()
        self.write("index.html", "home TAMPERED")
        found = self.by_kind(self.changes(before))
        self.assertIn("modified", found)
        self.assertIn("bytes", found["modified"].detail)

    def test_permission_change_is_detected_without_content_change(self):
        before = self.snap()
        os.chmod(os.path.join(self.root, "index.html"), 0o777)
        found = self.by_kind(self.changes(before))
        self.assertIn("permissions", found)
        self.assertNotIn("modified", found)

    def test_symlink_retarget_is_detected(self):
        link = os.path.join(self.root, "link.html")
        os.symlink(os.path.join(self.root, "index.html"), link)
        before = self.snap()
        os.remove(link)
        os.symlink(os.path.join(self.root, "config.php"), link)
        self.assertIn("modified", self.by_kind(self.changes(before)))

    def test_several_changes_are_all_reported(self):
        before = self.snap()
        self.write("evil.php", "shell")
        self.write("index.html", "changed")
        os.remove(os.path.join(self.root, "config.php"))
        kinds = {c.kind for c in self.changes(before)}
        self.assertEqual(kinds, {"added", "modified", "deleted"})

    def test_added_and_modified_are_high_severity(self):
        self.assertEqual(integrity_guard.SEVERITY["added"], "high")
        self.assertEqual(integrity_guard.SEVERITY["modified"], "high")


class TestCli(TreeTestCase):
    def baseline_path(self) -> str:
        return os.path.join(self.root, "..", "baseline.json")

    def test_init_then_check_is_clean(self):
        with tempfile.TemporaryDirectory() as out:
            baseline = os.path.join(out, "b.json")
            code, _ = capture_cli(integrity_guard.main,
                                  ["init", self.root, "-b", baseline])
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(baseline))
            code, _ = capture_cli(integrity_guard.main,
                                  ["check", self.root, "-b", baseline])
            self.assertEqual(code, 0)

    def test_check_exits_nonzero_after_tampering(self):
        with tempfile.TemporaryDirectory() as out:
            baseline = os.path.join(out, "b.json")
            capture_cli(integrity_guard.main, ["init", self.root, "-b", baseline])
            self.write("evil.php", "shell")
            code, text = capture_cli(integrity_guard.main,
                                     ["check", self.root, "-b", baseline])
            self.assertEqual(code, 1)
            self.assertIn("evil.php", text)

    def test_update_accepts_the_new_state(self):
        with tempfile.TemporaryDirectory() as out:
            baseline = os.path.join(out, "b.json")
            capture_cli(integrity_guard.main, ["init", self.root, "-b", baseline])
            self.write("new.txt", "ok")
            capture_cli(integrity_guard.main, ["update", self.root, "-b", baseline])
            code, _ = capture_cli(integrity_guard.main,
                                  ["check", self.root, "-b", baseline])
            self.assertEqual(code, 0)

    def test_check_without_baseline_reports_error(self):
        code, text = capture_cli(
            integrity_guard.main, ["check", self.root, "-b", "/nope/none.json"])
        self.assertEqual(code, 2)
        self.assertIn("No baseline", text)

    def test_missing_directory_is_rejected(self):
        code, text = capture_cli(integrity_guard.main,
                                 ["init", "/definitely/not/here"])
        self.assertEqual(code, 2)
        self.assertIn("Not a directory", text)

    def test_json_report_is_written(self):
        with tempfile.TemporaryDirectory() as out:
            baseline = os.path.join(out, "b.json")
            report = os.path.join(out, "r.json")
            capture_cli(integrity_guard.main, ["init", self.root, "-b", baseline])
            self.write("evil.php", "shell")
            capture_cli(integrity_guard.main,
                        ["check", self.root, "-b", baseline, "-o", report])
            with open(report, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual(data["change_count"], 1)
            self.assertEqual(data["changes"][0]["kind"], "added")


if __name__ == "__main__":
    unittest.main()
