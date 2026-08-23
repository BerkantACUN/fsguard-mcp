"""Tests for the filesystem tool functions — every one of these must go
through ConfinedRoot before touching disk, with no per-tool path check
a future tool could forget to include."""

import os

import pytest

from fsguard_mcp.confined_path import ConfinedRoot, PathEscapeError
from fsguard_mcp.fs import (
    fs_list_directory,
    fs_move_file,
    fs_read_file,
    fs_search_files,
    fs_write_file,
)


def _can_make_symlinks(tmp_path) -> bool:
    target = tmp_path / "_probe_target"
    target.mkdir()
    link = tmp_path / "_probe_link"
    try:
        os.symlink(target, link, target_is_directory=True)
        return True
    except OSError:
        return False
    finally:
        if link.exists() or link.is_symlink():
            link.unlink()
        target.rmdir()


class TestReadFile:
    def test_reads_a_file_in_root(self, tmp_path):
        (tmp_path / "a.txt").write_text("hello world")
        root = ConfinedRoot(tmp_path)
        assert fs_read_file(root, "a.txt") == "hello world"

    def test_rejects_a_read_outside_root(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        (tmp_path / "outside.txt").write_text("secret")
        root = ConfinedRoot(allowed)
        with pytest.raises(PathEscapeError):
            fs_read_file(root, "../outside.txt")

    def test_reading_a_missing_file_is_a_clear_error_not_a_crash(self, tmp_path):
        root = ConfinedRoot(tmp_path)
        with pytest.raises(FileNotFoundError):
            fs_read_file(root, "nope.txt")


class TestWriteFile:
    def test_writes_a_new_file_in_root(self, tmp_path):
        root = ConfinedRoot(tmp_path)
        fs_write_file(root, "new.txt", "content")
        assert (tmp_path / "new.txt").read_text() == "content"

    def test_overwrites_an_existing_file_in_root(self, tmp_path):
        (tmp_path / "existing.txt").write_text("old")
        root = ConfinedRoot(tmp_path)
        fs_write_file(root, "existing.txt", "new")
        assert (tmp_path / "existing.txt").read_text() == "new"

    def test_creates_parent_directories_within_root(self, tmp_path):
        root = ConfinedRoot(tmp_path)
        fs_write_file(root, "a/b/c.txt", "deep")
        assert (tmp_path / "a" / "b" / "c.txt").read_text() == "deep"

    def test_rejects_a_write_outside_root(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        root = ConfinedRoot(allowed)
        with pytest.raises(PathEscapeError):
            fs_write_file(root, "../escape.txt", "pwned")
        assert not (tmp_path / "escape.txt").exists()

    def test_rejects_a_write_via_traversal_through_a_nonexistent_directory(self, tmp_path):
        # The reported escape, exercised through the actual tool
        # function rather than the core primitive directly.
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        root = ConfinedRoot(allowed)
        with pytest.raises(PathEscapeError):
            fs_write_file(root, "a/../../evil.txt", "PWNED")
        assert not (tmp_path / "evil.txt").exists()

    def test_rejects_a_write_through_a_symlinked_parent_pointing_outside(self, tmp_path):
        if not _can_make_symlinks(tmp_path):
            pytest.skip("symlink creation not permitted in this environment")
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        os.symlink(outside, allowed / "escape", target_is_directory=True)

        root = ConfinedRoot(allowed)
        with pytest.raises(PathEscapeError):
            fs_write_file(root, "escape/pwned.txt", "pwned")
        assert not (outside / "pwned.txt").exists()


class TestListDirectory:
    def test_lists_entries_with_type(self, tmp_path):
        (tmp_path / "f.txt").write_text("hi")
        (tmp_path / "d").mkdir()
        root = ConfinedRoot(tmp_path)
        entries = fs_list_directory(root, ".")
        names = {e["name"]: e["type"] for e in entries}
        assert names == {"f.txt": "file", "d": "directory"}

    def test_rejects_listing_outside_root(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        root = ConfinedRoot(allowed)
        with pytest.raises(PathEscapeError):
            fs_list_directory(root, "..")


class TestSearchFiles:
    def test_finds_matching_files_recursively(self, tmp_path):
        (tmp_path / "a.py").write_text("x")
        nested = tmp_path / "sub"
        nested.mkdir()
        (nested / "b.py").write_text("x")
        (nested / "c.txt").write_text("x")
        root = ConfinedRoot(tmp_path)

        matches = fs_search_files(root, "*.py")
        assert set(matches) == {"a.py", os.path.join("sub", "b.py")}

    def test_search_root_outside_confinement_is_rejected(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        root = ConfinedRoot(allowed)
        with pytest.raises(PathEscapeError):
            fs_search_files(root, "*.py", path="..")

    def test_symlinked_subdirectory_pointing_outside_is_excluded_from_results(self, tmp_path):
        if not _can_make_symlinks(tmp_path):
            pytest.skip("symlink creation not permitted in this environment")
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.py").write_text("x")
        os.symlink(outside, allowed / "escape", target_is_directory=True)

        root = ConfinedRoot(allowed)
        matches = fs_search_files(root, "*.py")
        assert matches == []


class TestMoveFile:
    def test_moves_within_root(self, tmp_path):
        (tmp_path / "src.txt").write_text("hi")
        root = ConfinedRoot(tmp_path)
        fs_move_file(root, "src.txt", "dst.txt")
        assert not (tmp_path / "src.txt").exists()
        assert (tmp_path / "dst.txt").read_text() == "hi"

    def test_rejects_moving_the_source_from_outside_root(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        (tmp_path / "outside.txt").write_text("secret")
        root = ConfinedRoot(allowed)
        with pytest.raises(PathEscapeError):
            fs_move_file(root, "../outside.txt", "stolen.txt")

    def test_rejects_moving_the_destination_outside_root(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        (allowed / "src.txt").write_text("hi")
        root = ConfinedRoot(allowed)
        with pytest.raises(PathEscapeError):
            fs_move_file(root, "src.txt", "../exfiltrated.txt")
        assert not (tmp_path / "exfiltrated.txt").exists()
        assert (allowed / "src.txt").exists()

    def test_rejects_moving_the_destination_via_traversal_through_a_nonexistent_directory(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        (allowed / "src.txt").write_text("secret-data")
        root = ConfinedRoot(allowed)
        with pytest.raises(PathEscapeError):
            fs_move_file(root, "src.txt", "newdir/../../escaped.txt")
        assert not (tmp_path / "escaped.txt").exists()
        assert (allowed / "src.txt").read_text() == "secret-data"
