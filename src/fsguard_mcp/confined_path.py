"""
The core safety primitive: symlink-resolved, component-based path
containment. Every filesystem and git tool goes through this before
touching disk — see README.md for why.

The failure mode this fixes: CVE-2025-53109/53110 used `startsWith()`
string-prefix matching on a path to decide if it was "inside" the
allowed directory. That's defeated two ways: (1) a symlink inside the
allowed root whose target is outside it — the string check never
resolves the symlink, so it never sees the real destination; (2) a
sibling directory that merely shares a string prefix with the allowed
root (an allowed `/safe` also string-matches `/safe-evil`), which has
nothing to do with actual containment.

The fix here is to always resolve the candidate path through the real
filesystem (following every symlink) and then compare using path
*component* containment (`Path.is_relative_to()`), never string
comparison. Two paths that share characters but differ in even one
path component are never "contained" by this check, symlink or not.
"""

from __future__ import annotations

import os
from pathlib import Path


class PathEscapeError(ValueError):
    """Raised when a path would resolve outside the confined root."""


class ConfinedRoot:
    """Confines all path resolution to a single directory tree."""

    def __init__(self, root: str | Path) -> None:
        resolved = Path(root).resolve(strict=True)
        if not resolved.is_dir():
            raise NotADirectoryError(f"Confined root is not a directory: {resolved}")
        if resolved.parent == resolved:
            # A drive root (C:\) or the POSIX root (/) itself — "confined"
            # to one of these is not confinement at all. Almost always a
            # misconfigured or forgotten FSGUARD_ROOT, not an intentional
            # choice, and worth failing loudly rather than silently
            # granting effectively unrestricted access.
            raise ValueError(
                f"Refusing to use a filesystem root as the confined root: {resolved}"
            )
        self.root = resolved

    def resolve(self, candidate: str | Path, *, must_exist: bool = True) -> Path:
        """Resolve `candidate` (relative to the root, or absolute) and
        verify it's contained in the root after following every symlink.

        must_exist=True (the default, for reads and anything that must
        already exist) requires the full path to exist and resolves it
        directly.

        must_exist=False (for write targets that may not exist yet)
        walks up to the nearest existing ancestor, resolves *that*
        through any symlinks, and reattaches the non-existent tail —
        so a symlinked parent directory pointing outside the root is
        still caught, even though the final target itself is new.

        Raises PathEscapeError if the resolved path is not the root
        itself or a real descendant of it.
        """
        candidate_path = Path(candidate)
        self._reject_alternate_data_streams(candidate_path)

        combined = candidate_path if candidate_path.is_absolute() else (self.root / candidate_path)

        # Cheap, filesystem-free rejection of anything anchored on a
        # different drive or UNC host than the confined root — checked
        # *before* anything below ever calls .exists()/.resolve(), which
        # would otherwise make the OS actually attempt an SMB connection
        # to an attacker-supplied \\host\share path. That's not just an
        # escape risk: Windows will try to authenticate that connection
        # as the server process, which is the textbook "forced NTLM auth
        # via UNC path" credential-theft technique — and even a merely
        # unreachable host blocks this synchronous server for the length
        # of a full SMB connection timeout. A relative candidate always
        # inherits the root's own drive here, so this never affects
        # ordinary use.
        if combined.drive.lower() != self.root.drive.lower():
            raise PathEscapeError(
                f"Path is anchored on a different drive or host than the confined root: {candidate!r}"
            )

        # The containment check always uses the missing-leaf-safe walk,
        # whether or not the caller requires the path to exist — this is
        # deliberate: it means "is this path allowed" and "does this
        # path exist" are two separate questions, checked in that order,
        # so a plain missing file surfaces as FileNotFoundError instead
        # of being misreported as a security violation.
        resolved = self._resolve_allowing_missing_leaf(combined)

        if not self._is_contained(resolved):
            raise PathEscapeError(
                f"Path resolves outside the confined root {self.root}: {candidate!r} -> {resolved}"
            )

        if must_exist and not resolved.exists():
            raise FileNotFoundError(f"Path does not exist: {candidate}")

        return resolved

    def _reject_alternate_data_streams(self, candidate_path: Path) -> None:
        # NTFS Alternate Data Streams use "name:stream" syntax. A stream
        # is invisible to iterdir()/rglob() (so fs_list/fs_search would
        # never show it) but fully readable and writable through the
        # same path string — enough to hide content from directory
        # listings, or to write a ":Zone.Identifier" stream that forges
        # the absence of Windows' "Mark of the Web" on a file. Reject any
        # ':' outside the drive-letter position in any path component.
        for i, part in enumerate(candidate_path.parts):
            if i == 0 and candidate_path.drive:
                continue  # e.g. "C:\\" itself, not a stream
            if ":" in part:
                raise PathEscapeError(
                    f"Path component contains ':' (possible alternate data stream): {part!r}"
                )

    def _resolve_allowing_missing_leaf(self, combined: Path) -> Path:
        # Step 1 — lexical normalization, BEFORE touching the
        # filesystem at all. This is not optional: walking up to the
        # nearest *existing* ancestor by repeatedly taking .parent
        # treats a literal ".." component as just another path segment
        # to pop, not as "go up a level" — so a not-yet-existing tail
        # like "does/not/exist/../../../../outside.txt" would keep its
        # ".." tokens completely uninterpreted, and the later
        # containment check (a lexical comparison of path components)
        # would see them as harmless extra segments still "under" the
        # root, even though the real filesystem — once mkdir/move
        # actually creates each missing ancestor — resolves them right
        # out of the confined root. os.path.normpath() collapses "."
        # and ".." purely as path algebra, with no filesystem access,
        # so this can never depend on what happens to exist on disk.
        normalized = Path(os.path.normpath(str(combined)))

        # Step 2 — walk up the now ".."-free path to the nearest
        # existing ancestor, resolve *that* through any symlinks, and
        # reattach the (already-normalized, so safe to rejoin literally)
        # missing tail. This is what catches a symlinked parent
        # directory pointing outside the root even for a brand new file.
        existing = normalized
        missing_tail: list[str] = []
        while not existing.exists():
            if existing.parent == existing:
                raise PathEscapeError(f"No existing ancestor found for: {combined}")
            missing_tail.insert(0, existing.name)
            existing = existing.parent

        if missing_tail and not existing.is_dir():
            # The nearest existing ancestor is a file, not a directory —
            # e.g. candidate was "some-file.txt/nonsense/more.txt". Not a
            # containment issue, but a file can't have children, so this
            # is never a valid path; raise a clear error here rather than
            # returning a nonsensical resolved path and letting a later
            # OS-level call fail with a confusing error instead.
            raise NotADirectoryError(f"Not a directory: {existing}")

        resolved = existing.resolve(strict=True)
        for part in missing_tail:
            resolved = resolved / part
        return resolved

    def _is_contained(self, resolved: Path) -> bool:
        # is_relative_to() already returns True when resolved == self.root.
        return resolved.is_relative_to(self.root)
