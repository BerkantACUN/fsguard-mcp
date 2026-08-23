# fsguard-mcp

A filesystem + git MCP server that confines every operation to an allowed
directory tree using **symlink-resolved path containment**, not string
prefix matching.

## Why this exists

Anthropic's own official filesystem and git MCP servers (`@modelcontextprotocol/server-filesystem`, part of `modelcontextprotocol/servers`, 89.7k★) have carried **five separate path-confinement CVEs across two servers in ten months**, and the pattern is still active:

- **CVE-2025-53109 / CVE-2025-53110** (filesystem, CVSS 8.4/7.3) — the "allowed directory" check used naive `startsWith()` prefix matching, defeated by symlinks and by sibling directories that merely *share a string prefix* (e.g. an allowed `/home/user-safe` also matches `/home/user-safe-evil`), giving filesystem-wide read/write and a documented RCE path.
- **CVE-2025-68143 / CVE-2025-68144 / CVE-2025-68145** (git) — `git_init` accepted arbitrary unvalidated paths, `git_diff`/`git_checkout` passed user-controlled arguments straight to the `git` CLI (argument injection), and `--repository`-confined mode didn't actually verify `repo_path` stayed inside the confined directory.
- **CVE-2026-27735** (git, disclosed ~2 months before this project started) — `git_add`, implemented via GitPython's `repo.index.add()`, doesn't enforce working-tree boundaries for `../`-style paths, allowing staging and exfiltrating files outside the repo.
- A documented RCE chain: `git_init` in a writable directory → a malicious `.git/config` with a "clean" filter → a `.gitattributes` that applies it → `git_add` triggers the filter → arbitrary shell command runs.

Every one of these was patched with *another string/prefix check bolted onto that one function*. Nobody moved the boundary enforcement to a place a new tool can't simply forget to include — which is exactly how the fourth CVE landed four months after the first three were "fixed."

## How fsguard-mcp is different

1. **One safety primitive, used everywhere.** Every tool — filesystem or git — resolves its target path through the same `ConfinedRoot` (see `confined_path.py`) before doing anything else. There's no per-tool path check to forget.
2. **Symlink-resolved, component-based containment — not string matching.** A path is only inside the root if its *fully resolved* real path (every symlink followed) is a real ancestor-relative subpath of the root's *own* resolved real path, checked with `Path.is_relative_to()` on resolved paths — never `startswith()` on a string. This alone closes CVE-2025-53109/53110's exact failure mode: `/allowed-evil` cannot pass a containment check against a resolved root of `/allowed`, because path-component comparison isn't string-prefix comparison.
3. **No shelling out to `git` for content, ever.** Git operations run through `dulwich` — a pure-Python git implementation with no subprocess and no argv built from user input for anything content-related, and (critically) **no clean/smudge filter execution**, which is what the documented RCE chain depends on. There is no argument-injection surface here because there's no argument list being handed to an external process for reading/writing file content. (dulwich *does* still run `pre-commit`/`commit-msg`/`post-commit` hooks via `subprocess.call()` if they exist — real process execution, unrelated to content filtering. `git_commit` always passes `no_verify=True` to skip them categorically, rather than relying on them happening not to be runnable.)
4. **Write operations validate the parent directory too**, not just an existing target — closing the class of bug where a target doesn't exist yet (so "does this path resolve inside the root" was checked against a path that doesn't exist, and therefore couldn't be symlink-resolved) but its parent directory is itself a symlink pointing outside. Non-existent path segments are lexically normalized (`.`/`..` collapsed as pure path algebra) *before* any of this, independent of what happens to exist on disk — an earlier version of this project checked containment before normalizing, which happened to pass all its tests on Windows (whose path APIs normalize `..` for you) while being bypassable on Linux/macOS. It's fixed now, and there are tests for the exact case, but it's the reason this project treats "the test suite is green on my machine" with real suspicion.
5. **`.git/config` can't redirect operations outside the root.** dulwich honors a repo's own `core.worktree` config entry, and every git operation re-opens a `Repo` from a path string internally — so a caller could write a `.git/config` with `core.worktree` pointing anywhere, and every subsequent git tool would silently operate outside the confined root, invisible to the per-path check (which only ever sees the confined repo directory, never wherever dulwich actually redirected itself to). This was found in this project's own second-round security review — a real read/exfiltration primitive using nothing but this server's own exposed tools, more severe than any CVE it was built to fix. Every git tool now refuses to open a repo whose config sets `core.worktree` at all, and independently re-verifies that the `Repo` object it actually opened reports its working path as the exact directory that was validated.
6. **UNC paths and cross-drive paths are rejected before touching the network or disk at all.** Resolving a `\\host\share\...` path makes Windows actually attempt an SMB connection — and Windows will try to authenticate that connection as the server process, which is the "forced NTLM auth via UNC path" credential-theft technique, on top of blocking the server for a full connection timeout against an unreachable host. A candidate anchored on a different drive or host than the confined root is now rejected by a cheap string comparison, before any filesystem or network call. NTFS Alternate Data Streams (`file.txt:hidden`) are also rejected outright — they're invisible to directory listings but fully readable/writable through the same path string, and can forge the absence of Windows' download-warning "Mark of the Web."

## Tools

| Tool | Does |
|---|---|
| `fs_read(path)` | Read a text file |
| `fs_write(path, content)` | Create or overwrite a text file |
| `fs_list(path=".")` | List a directory's entries |
| `fs_search(pattern, path=".")` | Find files matching a glob pattern, recursively |
| `fs_move(source, destination)` | Move/rename a file |
| `git_init_repo(repo_path)` | Initialize a git repository |
| `git_repo_status(repo_path=".")` | Staged/unstaged/untracked files |
| `git_stage(repo_path, paths)` | Stage files |
| `git_commit_repo(repo_path, message, author)` | Commit staged changes |
| `git_diff_repo(repo_path=".", staged=False)` | Show a diff |
| `git_log_repo(repo_path=".", max_entries=10)` | Show commit history |

## Setup

```bash
pip install fsguard-mcp
export FSGUARD_ROOT="/path/to/the/one/directory/tree/this/server/may/touch"
fsguard-mcp
```

`FSGUARD_ROOT` is required — there is no default, and the server refuses to guess one. Point your MCP client at the `fsguard-mcp` command with `FSGUARD_ROOT` set in its env config.

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

All 68 tests are self-contained (real temp directories, real symlinks, real git repos) — no external services needed.

## Known limitation

Containment is checked, then a filesystem operation runs — there is an inherent TOCTOU (time-of-check-to-time-of-use) gap between the two. A concurrent process with write access to the confined root's own tree could in principle swap a symlink in that window (verified with a working proof-of-concept during review). Closing this fully needs an OS-level primitive (e.g. Linux `openat2(RESOLVE_BENEATH)`, a real mount namespace) rather than anything achievable in portable Python; this project's guarantee is "correct containment logic, checked immediately before use," not "immune to a concurrent attacker who can already write inside the root."

## Status

68 passing tests (unit-level, with real symlinks and real git repos created on disk — not just string-logic assertions). Went through two rounds of adversarial security review before its first commit; both found real, working bypasses (a `..`-traversal escape through not-yet-existing paths on POSIX, and the `core.worktree` redirection above, among smaller findings) that are now fixed and covered by tests written directly against the reported exploit. Not yet published to PyPI.

## License

MIT
