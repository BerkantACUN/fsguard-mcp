"""
MCP tool surface for fsguard-mcp.

Every tool goes through the single ConfinedRoot instance created here
from FSGUARD_ROOT — there is no tool that takes a raw path and skips
containment checking, by construction: fs.py and git_ops.py's functions
all require a ConfinedRoot argument, so there's no code path that could
forget the check the way a new tool in the official servers repeatedly
did across five CVEs.
"""

from __future__ import annotations

import os
import sys

try:
    from mcp.server import MCPServer as _MCPServerImpl
except ImportError:  # SDK < 2.0
    from mcp.server.fastmcp import FastMCP as _MCPServerImpl  # type: ignore[no-redef]

from .confined_path import ConfinedRoot, PathEscapeError
from .fs import fs_list_directory, fs_move_file, fs_read_file, fs_search_files, fs_write_file
from .git_ops import (
    NotAGitRepositoryError,
    git_add,
    git_commit,
    git_diff,
    git_init,
    git_log,
    git_status,
)

mcp = _MCPServerImpl("fsguard-mcp")

_root: ConfinedRoot | None = None


def _get_root() -> ConfinedRoot:
    global _root
    if _root is None:
        root_path = os.environ.get("FSGUARD_ROOT")
        if not root_path:
            raise RuntimeError(
                "FSGUARD_ROOT is not set — fsguard-mcp refuses to guess a root directory. "
                "Set it to the one directory tree this server may touch."
            )
        _root = ConfinedRoot(root_path)
    return _root


def _safe(fn, *args, **kwargs) -> dict:
    try:
        result = fn(*args, **kwargs)
        return result if isinstance(result, dict) else {"result": result}
    except PathEscapeError as e:
        return {"error": "PathEscape", "message": str(e)}
    except Exception as e:
        # str(e) can include local filesystem paths and other internal
        # detail. That's accepted here (it makes tool errors legible to
        # both the calling model and a human debugging a session) but
        # is a real tradeoff for a project whose whole point is not
        # over-trusting what a tool reports — a future version might
        # log the full exception server-side and return a generic
        # message instead. There is currently no logging at all in
        # this codebase, so a caught-and-boxed exception is presently
        # the *only* record of it.
        return {"error": type(e).__name__, "message": str(e)}


@mcp.tool()
def fs_read(path: str) -> dict:
    """Read a text file's contents. path is relative to FSGUARD_ROOT."""
    return _safe(lambda: {"content": fs_read_file(_get_root(), path)})


@mcp.tool()
def fs_write(path: str, content: str) -> dict:
    """Write (creating or overwriting) a text file. Parent directories
    are created as needed, but only within FSGUARD_ROOT."""
    return _safe(lambda: fs_write_file(_get_root(), path, content) or {"written": path})


@mcp.tool()
def fs_list(path: str = ".") -> dict:
    """List the entries of a directory, each tagged file or directory."""
    return _safe(lambda: {"entries": fs_list_directory(_get_root(), path)})


@mcp.tool()
def fs_search(pattern: str, path: str = ".") -> dict:
    """Find files matching a glob pattern (e.g. '*.py') under path,
    recursively. Any match that resolves outside FSGUARD_ROOT — e.g. via
    a symlink — is silently excluded rather than reported."""
    return _safe(lambda: {"matches": fs_search_files(_get_root(), pattern, path)})


@mcp.tool()
def fs_move(source: str, destination: str) -> dict:
    """Move or rename a file/directory. Both source and destination
    must resolve within FSGUARD_ROOT. If destination already exists as
    a file, it is overwritten. If destination already exists as a
    directory, the call fails instead of moving source inside it."""
    return _safe(lambda: fs_move_file(_get_root(), source, destination) or {"moved_to": destination})


@mcp.tool()
def git_init_repo(repo_path: str) -> dict:
    """Initialize a new git repository at repo_path (relative to
    FSGUARD_ROOT)."""
    return _safe(git_init, _get_root(), repo_path)


@mcp.tool()
def git_repo_status(repo_path: str = ".") -> dict:
    """Show staged, unstaged, and untracked files for a repo."""
    return _safe(git_status, _get_root(), repo_path)


@mcp.tool()
def git_stage(repo_path: str, paths: list[str]) -> dict:
    """Stage files for commit. Every path is validated against
    FSGUARD_ROOT before being staged — a path that would escape the
    root fails the whole call, staging nothing."""
    return _safe(git_add, _get_root(), repo_path, paths)


@mcp.tool()
def git_commit_repo(repo_path: str, message: str, author: str) -> dict:
    """Commit staged changes. author must be 'Name <email>'."""
    return _safe(git_commit, _get_root(), repo_path, message, author)


@mcp.tool()
def git_diff_repo(repo_path: str = ".", staged: bool = False) -> dict:
    """Show the diff for a repo's working tree (or staged changes)."""
    return _safe(lambda: {"diff": git_diff(_get_root(), repo_path, staged)})


@mcp.tool()
def git_log_repo(repo_path: str = ".", max_entries: int = 10) -> dict:
    """Show recent commit history."""
    return _safe(lambda: {"log": git_log(_get_root(), repo_path, max_entries)})


def main() -> None:
    if not os.environ.get("FSGUARD_ROOT"):
        print(
            "fsguard-mcp: FSGUARD_ROOT is not set — every tool call will fail until it is. "
            "See README.md.",
            file=sys.stderr,
        )
    mcp.run()


if __name__ == "__main__":
    main()
