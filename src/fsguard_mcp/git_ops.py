"""
Git tool functions, built on dulwich — a pure-Python git implementation
with no subprocess-based content filtering and no argv built from user
input, instead of shelling out to the `git` binary the way the official
git MCP server does.

Why that matters here specifically: CVE-2025-68144 was argument
injection because user-controlled values were passed straight into a
`git` CLI invocation, and the documented RCE chain (`git_init` in a
writable dir -> a malicious `.git/config` clean filter -> `.gitattributes`
applies it -> `git_add` triggers the filter -> arbitrary shell command)
depends entirely on an external `git` process being invoked to run that
filter. dulwich's blob-normalizer path used by add/checkin doesn't shell
out, so that specific chain is closed. Two things dulwich *does* still do
that this module explicitly guards against:

1. **`core.worktree` redirection.** `.git/config` can contain a
   `core.worktree` entry that dulwich honors on `Repo.open()`, and every
   `porcelain.*` call re-opens a `Repo` from whatever path string it's
   given — internally, not something a caller can intercept. Since
   `.git/config` is just a text file inside the confined root,
   `fs_write` (which has no special handling for `.git/*`) lets a caller
   write one, and *every git tool in this module* would then silently
   operate against an arbitrary directory outside the confined root
   without the containment check ever seeing it — a full read/write
   escape using nothing but this server's own exposed tools. `_open_repo`
   below refuses any `.git/config` containing `core.worktree`, and
   independently double-checks that the `Repo` it actually opened
   reports its working path as the exact directory that was validated.
2. **Hooks.** `porcelain.commit()` runs `pre-commit`/`commit-msg`/
   `post-commit` hooks via `subprocess.call()` if they exist and are
   executable at `.git/hooks/*` — real process execution, unrelated to
   content filtering. `git_commit` below always passes `no_verify=True`
   to skip them categorically, rather than relying on them happening to
   not be runnable.

Every path this module touches — the repo itself, and every path handed
to git_add — is also validated through the same ConfinedRoot used by
fs.py. This is the direct fix for CVE-2026-27735, where GitPython's
`repo.index.add()` didn't enforce working-tree boundaries for `../`
paths: here, each path is resolved and checked against the confined
root *before* it's handed to dulwich at all.
"""

from __future__ import annotations

import io
from pathlib import Path

from dulwich import porcelain
from dulwich.repo import Repo

from .confined_path import ConfinedRoot


class NotAGitRepositoryError(ValueError):
    pass


class UnsafeRepositoryError(ValueError):
    """Raised when a repo's own .git/config tries to redirect operations
    outside the confined root — see module docstring, point 1."""


def git_init(root: ConfinedRoot, repo_path: str) -> dict:
    resolved = root.resolve(repo_path, must_exist=False)
    resolved.mkdir(parents=True, exist_ok=True)
    porcelain.init(str(resolved))
    return {"initialized": str(resolved.relative_to(root.root)) or "."}


def _open_repo(root: ConfinedRoot, repo_path: str) -> Repo:
    resolved = root.resolve(repo_path, must_exist=True)
    if not (resolved / ".git").exists():
        raise NotAGitRepositoryError(f"Not a git repository: {repo_path}")

    config_path = resolved / ".git" / "config"
    if config_path.is_file():
        config_text = config_path.read_text(encoding="utf-8", errors="replace")
        if "worktree" in config_text.lower():
            raise UnsafeRepositoryError(
                f"Refusing to operate on {repo_path}: its .git/config sets "
                "core.worktree, which can redirect git operations outside "
                "the confined root."
            )

    repo = Repo(str(resolved))
    # Defense in depth beyond the text check above: confirm dulwich's own
    # notion of the working path, after fully opening and parsing the
    # config, is still exactly the directory we validated — not
    # wherever some other config mechanism might have pointed it.
    actual_path = Path(repo.path).resolve()
    if actual_path != resolved:
        repo.close()
        raise UnsafeRepositoryError(
            f"Refusing to operate on {repo_path}: dulwich resolved its "
            f"working path to {actual_path}, not the confined {resolved}."
        )
    return repo


def git_status(root: ConfinedRoot, repo_path: str = ".") -> dict:
    repo = _open_repo(root, repo_path)
    status = porcelain.status(repo)
    staged = {
        kind: [p.decode() if isinstance(p, bytes) else p for p in paths]
        for kind, paths in status.staged.items()
        if paths
    }
    return {
        "staged": staged,
        "unstaged": [p.decode() if isinstance(p, bytes) else p for p in status.unstaged],
        "untracked": [p.decode() if isinstance(p, bytes) else p for p in status.untracked],
    }


def git_add(root: ConfinedRoot, repo_path: str, paths: list[str]) -> dict:
    """Stage files. Every path is resolved and validated against the
    confined root — not just against the repo directory — before being
    handed to dulwich. See module docstring for the CVE this fixes."""
    repo = _open_repo(root, repo_path)
    repo_dir = Path(repo.path)
    validated: list[str] = []
    for p in paths:
        candidate = repo_dir / p
        root.resolve(candidate, must_exist=True)  # raises PathEscapeError if it escapes
        validated.append(p)
    porcelain.add(repo, paths=validated)
    return {"added": validated}


def git_commit(root: ConfinedRoot, repo_path: str, message: str, author: str) -> dict:
    repo = _open_repo(root, repo_path)
    author_bytes = author.encode("utf-8")
    sha = porcelain.commit(
        repo,
        message=message,
        author=author_bytes,
        committer=author_bytes,
        no_verify=True,  # never run pre-commit/commit-msg/post-commit hooks
    )
    return {"commit": sha.decode("ascii")}


def git_diff(root: ConfinedRoot, repo_path: str = ".", staged: bool = False) -> str:
    repo = _open_repo(root, repo_path)
    buf = io.BytesIO()
    porcelain.diff(repo, staged=staged, outstream=buf)
    return buf.getvalue().decode("utf-8", errors="replace")


def git_log(root: ConfinedRoot, repo_path: str = ".", max_entries: int = 10) -> str:
    repo = _open_repo(root, repo_path)
    buf = io.StringIO()
    porcelain.log(repo, max_entries=max_entries, outstream=buf)
    return buf.getvalue()
