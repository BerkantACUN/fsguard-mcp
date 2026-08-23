"""
Adversarial tests for the core path-confinement primitive, written
directly against the failure modes of the CVEs this project exists to
fix. These create real directories and real symlinks on disk and prove
containment holds against the actual filesystem — not just against
string logic.
"""

import os
from pathlib import Path

import pytest

from fsguard_mcp.confined_path import ConfinedRoot, PathEscapeError


def _can_make_symlinks(tmp_path) -> bool:
    target = tmp_path / "_symlink_probe_target"
    target.mkdir()
    link = tmp_path / "_symlink_probe_link"
    try:
        os.symlink(target, link, target_is_directory=True)
        return True
    except OSError:
        return False
    finally:
        if link.exists() or link.is_symlink():
            link.unlink()
        target.rmdir()


class TestOrdinaryAccessWorks:
    def test_root_itself_is_allowed(self, tmp_path):
        root = ConfinedRoot(tmp_path)
        assert root.resolve(tmp_path) == tmp_path.resolve()

    def test_a_file_directly_in_root_is_allowed(self, tmp_path):
        (tmp_path / "a.txt").write_text("hi")
        root = ConfinedRoot(tmp_path)
        resolved = root.resolve(tmp_path / "a.txt")
        assert resolved == (tmp_path / "a.txt").resolve()

    def test_a_nested_subdirectory_file_is_allowed(self, tmp_path):
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)
        (nested / "f.txt").write_text("hi")
        root = ConfinedRoot(tmp_path)
        root.resolve(nested / "f.txt")  # must not raise

    def test_relative_path_is_resolved_against_the_root(self, tmp_path):
        (tmp_path / "rel.txt").write_text("hi")
        root = ConfinedRoot(tmp_path)
        resolved = root.resolve("rel.txt")
        assert resolved == (tmp_path / "rel.txt").resolve()


class TestTheCVE_2025_53109_ExactFailureMode:
    """CVE-2025-53109/53110: naive startsWith() prefix matching was
    defeated by a symlink inside the allowed root pointing outside it."""

    def test_symlink_inside_root_pointing_outside_is_rejected(self, tmp_path):
        if not _can_make_symlinks(tmp_path):
            pytest.skip("symlink creation not permitted in this environment")

        allowed = tmp_path / "allowed"
        allowed.mkdir()
        secret_dir = tmp_path / "secret"
        secret_dir.mkdir()
        (secret_dir / "passwords.txt").write_text("hunter2")

        escape_link = allowed / "escape"
        os.symlink(secret_dir, escape_link, target_is_directory=True)

        root = ConfinedRoot(allowed)
        with pytest.raises(PathEscapeError):
            root.resolve(escape_link / "passwords.txt")

    def test_symlinked_file_inside_root_pointing_outside_is_rejected(self, tmp_path):
        if not _can_make_symlinks(tmp_path):
            pytest.skip("symlink creation not permitted in this environment")

        allowed = tmp_path / "allowed"
        allowed.mkdir()
        secret = tmp_path / "secret.txt"
        secret.write_text("hunter2")

        link = allowed / "innocent-looking.txt"
        os.symlink(secret, link)

        root = ConfinedRoot(allowed)
        with pytest.raises(PathEscapeError):
            root.resolve(link)

    def test_symlink_inside_root_pointing_elsewhere_inside_root_is_still_allowed(self, tmp_path):
        # A symlink is not inherently dangerous — only one that escapes
        # the root. This must not become an over-broad "no symlinks ever"
        # rule.
        if not _can_make_symlinks(tmp_path):
            pytest.skip("symlink creation not permitted in this environment")

        allowed = tmp_path / "allowed"
        allowed.mkdir()
        real_dir = allowed / "real"
        real_dir.mkdir()
        (real_dir / "f.txt").write_text("hi")

        link = allowed / "alias"
        os.symlink(real_dir, link, target_is_directory=True)

        root = ConfinedRoot(allowed)
        root.resolve(link / "f.txt")  # must not raise


class TestSharedPrefixSiblingIsNotContainment:
    """The exact bug class in a string-prefix ("startsWith") check: a
    sibling directory that merely *shares characters* with the allowed
    root's path is not the same as being inside it."""

    def test_sibling_directory_with_shared_string_prefix_is_rejected(self, tmp_path):
        allowed = tmp_path / "safe"
        allowed.mkdir()
        sibling = tmp_path / "safe-evil"
        sibling.mkdir()
        (sibling / "secret.txt").write_text("hunter2")

        root = ConfinedRoot(allowed)
        with pytest.raises(PathEscapeError):
            root.resolve(sibling / "secret.txt")


class TestTraversalAndAbsoluteOverride:
    def test_dot_dot_traversal_out_of_root_is_rejected(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside.txt"
        outside.write_text("secret")

        root = ConfinedRoot(allowed)
        with pytest.raises(PathEscapeError):
            root.resolve(allowed / ".." / "outside.txt")

    def test_absolute_path_pointing_outside_root_is_rejected(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside.txt"
        outside.write_text("secret")

        root = ConfinedRoot(allowed)
        with pytest.raises(PathEscapeError):
            root.resolve(outside)


class TestWriteTargetsThatDoNotExistYet:
    """CVE-2026-27735-adjacent case: the naive fix of 'resolve() and
    check containment' silently does nothing useful for a path that
    doesn't exist yet, because resolve(strict=True) just fails or
    resolve(strict=False) doesn't follow symlinks for missing
    components consistently across platforms. must_exist=False must
    still resolve the *existing* parent through any symlinks."""

    def test_new_file_directly_in_root_is_allowed(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        root = ConfinedRoot(allowed)
        resolved = root.resolve(allowed / "new-file.txt", must_exist=False)
        assert resolved.parent == allowed.resolve()

    def test_new_file_in_a_symlinked_parent_pointing_outside_is_rejected(self, tmp_path):
        if not _can_make_symlinks(tmp_path):
            pytest.skip("symlink creation not permitted in this environment")

        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()

        escape_link = allowed / "escape"
        os.symlink(outside_dir, escape_link, target_is_directory=True)

        root = ConfinedRoot(allowed)
        with pytest.raises(PathEscapeError):
            root.resolve(escape_link / "new-file.txt", must_exist=False)

    def test_new_file_several_levels_of_nonexistent_dirs_deep_still_checked(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        root = ConfinedRoot(allowed)
        # a/b/c don't exist yet — must still resolve against the real
        # existing ancestor (allowed) and stay contained.
        resolved = root.resolve(allowed / "a" / "b" / "c.txt", must_exist=False)
        assert str(resolved).startswith(str(allowed.resolve()))

    def test_new_file_via_traversal_from_a_nonexistent_dir_is_rejected(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside.txt"

        root = ConfinedRoot(allowed)
        with pytest.raises(PathEscapeError):
            root.resolve(allowed / "does" / "not" / "exist" / ".." / ".." / ".." / ".." / "outside.txt", must_exist=False)

    def test_the_exact_reported_escape_a_slash_dotdot_dotdot_evil(self, tmp_path):
        # The precise reproduction that slipped past the earlier version
        # of this check: on a platform where the walk-up-by-.parent
        # logic doesn't collapse ".." semantically, this returned a
        # "contained" verdict for a path that a real mkdir(parents=True)
        # or shutil.move would actually place *outside* the root.
        allowed = tmp_path / "safe"
        allowed.mkdir()
        root = ConfinedRoot(allowed)
        with pytest.raises(PathEscapeError):
            root.resolve("a/../../evil.txt", must_exist=False)

    def test_traversal_through_a_missing_dir_that_stops_exactly_at_the_root_is_still_rejected_if_it_goes_further(self, tmp_path):
        allowed = tmp_path / "safe"
        allowed.mkdir()
        root = ConfinedRoot(allowed)
        # "a" doesn't exist; ".." from it lands back at "safe" (fine),
        # but the second ".." climbs one level above the root — must
        # still be rejected even though the first ".." alone wouldn't
        # have escaped.
        with pytest.raises(PathEscapeError):
            root.resolve("a/../../outside.txt", must_exist=False)

    def test_traversal_through_a_missing_dir_that_stays_inside_is_allowed(self, tmp_path):
        allowed = tmp_path / "safe"
        allowed.mkdir()
        root = ConfinedRoot(allowed)
        # "a" doesn't exist, but "a/../b.txt" normalizes to "b.txt",
        # which is legitimately inside the root — this must not become
        # an over-broad "any .. in a missing path is rejected" rule.
        resolved = root.resolve("a/../b.txt", must_exist=False)
        assert resolved == allowed.resolve() / "b.txt"


class TestConstructionValidation:
    def test_root_must_exist(self, tmp_path):
        with pytest.raises(OSError):
            ConfinedRoot(tmp_path / "does-not-exist")

    def test_root_must_be_a_directory(self, tmp_path):
        f = tmp_path / "a-file.txt"
        f.write_text("hi")
        with pytest.raises(NotADirectoryError):
            ConfinedRoot(f)

    def test_a_filesystem_root_is_refused_as_the_confined_root(self, tmp_path):
        drive_root = Path(tmp_path.anchor)  # e.g. "C:\\" or "/"
        with pytest.raises(ValueError):
            ConfinedRoot(drive_root)


class TestUNCAndCrossDriveRejection:
    """A security-review finding: without a cheap pre-check, resolving a
    \\\\host\\share path makes the OS actually attempt an SMB connection
    (and Windows will try to authenticate that connection as the server
    process — the "forced NTLM auth via UNC path" credential-theft
    technique) *before* containment is ever checked. A candidate on a
    different drive/host than the root must be rejected by string
    comparison alone, with no filesystem or network access at all."""

    def test_unc_path_is_rejected_without_touching_the_network(self, tmp_path):
        root = ConfinedRoot(tmp_path)
        # A non-routable, TEST-NET-1 address (RFC 5737) — if this were
        # ever actually dialed, the test would hang for a long timeout
        # instead of failing fast. It must never get that far.
        with pytest.raises(PathEscapeError):
            root.resolve(r"\\192.0.2.123\share\x", must_exist=False)

    def test_different_drive_letter_is_rejected(self, tmp_path):
        root = ConfinedRoot(tmp_path)
        other_drive = "Z:" if tmp_path.drive.upper() != "Z:" else "Y:"
        with pytest.raises(PathEscapeError):
            root.resolve(f"{other_drive}\\evil.txt", must_exist=False)


class TestAlternateDataStreamRejection:
    """A security-review finding: NTFS Alternate Data Streams
    ("name:stream") are invisible to iterdir()/rglob() but fully
    readable and writable through the same path string — enough to
    hide content from a directory listing, or to forge the absence of
    Windows' "Mark of the Web" via a ":Zone.Identifier" stream."""

    def test_a_stream_suffix_is_rejected(self, tmp_path):
        (tmp_path / "base.txt").write_text("hi")
        root = ConfinedRoot(tmp_path)
        with pytest.raises(PathEscapeError):
            root.resolve("base.txt:hidden", must_exist=False)

    def test_the_zone_identifier_stream_specifically_is_rejected(self, tmp_path):
        (tmp_path / "base.txt").write_text("hi")
        root = ConfinedRoot(tmp_path)
        with pytest.raises(PathEscapeError):
            root.resolve("base.txt:Zone.Identifier", must_exist=False)

    def test_an_ordinary_windows_drive_letter_is_not_mistaken_for_a_stream(self, tmp_path):
        # The ':' in "C:\\" itself must not trip this check.
        root = ConfinedRoot(tmp_path)
        (tmp_path / "ok.txt").write_text("hi")
        root.resolve(str(tmp_path / "ok.txt"))  # must not raise


class TestNonDirectoryAncestor:
    def test_treating_a_file_as_if_it_had_children_is_a_clear_error(self, tmp_path):
        (tmp_path / "existing-file.txt").write_text("hi")
        root = ConfinedRoot(tmp_path)
        with pytest.raises(NotADirectoryError):
            root.resolve("existing-file.txt/nonsense/more.txt", must_exist=False)
