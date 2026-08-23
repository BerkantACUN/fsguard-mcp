"""
Filesystem tool functions. Every one resolves its path(s) through the
passed-in ConfinedRoot before touching disk — there is deliberately no
way to call these with a raw, unvalidated path, so a future function
added here can't forget the check the way CVE-2026-27735 did for git.
"""

from __future__ import annotations

import fnmatch
import os
import shutil

from .confined_path import ConfinedRoot, PathEscapeError


def fs_read_file(root: ConfinedRoot, path: str) -> str:
    resolved = root.resolve(path, must_exist=True)
    if resolved.is_dir():
        raise IsADirectoryError(f"Not a file: {path}")
    return resolved.read_text(encoding="utf-8")


def fs_write_file(root: ConfinedRoot, path: str, content: str) -> None:
    resolved = root.resolve(path, must_exist=False)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(content, encoding="utf-8")


def fs_list_directory(root: ConfinedRoot, path: str = ".") -> list[dict]:
    resolved = root.resolve(path, must_exist=True)
    if not resolved.is_dir():
        raise NotADirectoryError(f"Not a directory: {path}")
    return [
        {"name": entry.name, "type": "directory" if entry.is_dir() else "file"}
        for entry in sorted(resolved.iterdir(), key=lambda e: e.name)
    ]


def fs_move_file(root: ConfinedRoot, source: str, destination: str) -> None:
    resolved_source = root.resolve(source, must_exist=True)
    resolved_destination = root.resolve(destination, must_exist=False)
    if resolved_destination.is_dir():
        # shutil.move's "move *into* an existing directory" behavior
        # would silently relocate the file to destination/<basename>
        # instead of the literal destination path the caller asked
        # for — reject instead of surprising the caller about where
        # the file actually landed.
        raise IsADirectoryError(
            f"Destination already exists as a directory: {destination}"
        )
    resolved_destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(resolved_source), str(resolved_destination))


def fs_search_files(root: ConfinedRoot, pattern: str, path: str = ".") -> list[str]:
    resolved = root.resolve(path, must_exist=True)
    if not resolved.is_dir():
        raise NotADirectoryError(f"Not a directory: {path}")

    # Deliberately os.walk(followlinks=False) rather than Path.rglob():
    # not descending into symlinked subdirectories is a guarantee this
    # project needs to hold, not an incidental default — rglob's
    # symlink behavior has differed across Python versions, and this
    # project supports 3.10+, so relying on "whichever pathlib happens
    # to be installed does the safe thing" isn't good enough here.
    matches = []
    for dirpath, dirnames, filenames in os.walk(str(resolved), followlinks=False):
        for name in filenames:
            if fnmatch.fnmatch(name, pattern):
                candidate = os.path.join(dirpath, name)
                try:
                    # Re-validate every match through the root anyway —
                    # keeps the same "everything goes through
                    # ConfinedRoot" invariant as every other tool. Only
                    # a path-escape or an OS-level access problem should
                    # exclude a match — anything else is a real bug and
                    # should surface, not vanish into a silently shorter
                    # result list.
                    resolved_candidate = root.resolve(candidate, must_exist=True)
                except (PathEscapeError, OSError):
                    continue
                matches.append(str(resolved_candidate.relative_to(root.root)))
    return sorted(matches)
