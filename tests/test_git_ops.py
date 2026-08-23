"""
Tests for the git tool functions — several written directly against the
CVEs this module exists to fix.
"""

import pytest

from fsguard_mcp.confined_path import ConfinedRoot, PathEscapeError
from fsguard_mcp.fs import fs_write_file
from fsguard_mcp.git_ops import (
    NotAGitRepositoryError,
    UnsafeRepositoryError,
    git_add,
    git_commit,
    git_diff,
    git_init,
    git_log,
    git_status,
)

AUTHOR = "Test Author <test@example.com>"


class TestGitInit:
    def test_creates_a_real_repo_inside_root(self, tmp_path):
        root = ConfinedRoot(tmp_path)
        git_init(root, "myrepo")
        assert (tmp_path / "myrepo" / ".git").is_dir()

    def test_can_init_the_root_itself(self, tmp_path):
        root = ConfinedRoot(tmp_path)
        git_init(root, ".")
        assert (tmp_path / ".git").is_dir()


class TestGitInit_CVE_2025_68143:
    """CVE-2025-68143: git_init accepted arbitrary unvalidated paths."""

    def test_init_outside_root_is_rejected(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        root = ConfinedRoot(allowed)
        with pytest.raises(PathEscapeError):
            git_init(root, "../outside-repo")
        assert not (tmp_path / "outside-repo" / ".git").exists()

    def test_init_via_absolute_path_outside_root_is_rejected(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside-repo"
        root = ConfinedRoot(allowed)
        with pytest.raises(PathEscapeError):
            git_init(root, str(outside))
        assert not (outside / ".git").exists()

    def test_init_via_traversal_through_a_nonexistent_directory_is_rejected(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        root = ConfinedRoot(allowed)
        with pytest.raises(PathEscapeError):
            git_init(root, "sub/../../evilrepo")
        assert not (tmp_path / "evilrepo" / ".git").exists()


class TestNotARepo:
    def test_status_on_a_non_repo_directory_is_a_clear_error(self, tmp_path):
        root = ConfinedRoot(tmp_path)
        with pytest.raises(NotAGitRepositoryError):
            git_status(root, ".")


class TestGitStatusAndAdd:
    def _init_repo_with_file(self, tmp_path):
        root = ConfinedRoot(tmp_path)
        git_init(root, "repo")
        (tmp_path / "repo" / "a.txt").write_text("hello")
        return root

    def test_status_reports_untracked_file(self, tmp_path):
        root = self._init_repo_with_file(tmp_path)
        status = git_status(root, "repo")
        assert "a.txt" in status["untracked"]

    def test_add_stages_the_file(self, tmp_path):
        root = self._init_repo_with_file(tmp_path)
        git_add(root, "repo", ["a.txt"])
        status = git_status(root, "repo")
        assert "a.txt" not in status["untracked"]
        staged_files = [f for files in status["staged"].values() for f in files]
        assert "a.txt" in staged_files


class TestGitAdd_CVE_2026_27735:
    """CVE-2026-27735: GitPython's repo.index.add() didn't enforce
    working-tree boundaries for ../-style paths, letting a caller stage
    (and thus read/exfiltrate via diff/commit) a file outside the repo
    entirely. Every path handed to git_add here must be validated
    against the confined root before dulwich ever sees it."""

    def test_add_with_traversal_outside_the_confined_root_is_rejected(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        root = ConfinedRoot(allowed)
        git_init(root, "repo")

        secret = tmp_path / "secret.txt"
        secret.write_text("hunter2")

        with pytest.raises(PathEscapeError):
            git_add(root, "repo", ["../../secret.txt"])

    def test_rejected_add_does_not_partially_stage_other_valid_paths(self, tmp_path):
        # A single escaping path in the list must not let any of the
        # paths get added — fail closed, not "best effort."
        root = ConfinedRoot(tmp_path)
        git_init(root, "repo")
        (tmp_path / "repo" / "good.txt").write_text("fine")

        with pytest.raises(PathEscapeError):
            git_add(root, "repo", ["good.txt", "../../../outside.txt"])

        status = git_status(root, "repo")
        staged_files = [f for files in status["staged"].values() for f in files]
        assert "good.txt" not in staged_files


class TestCoreWorktreeRedirectionIsRefused:
    """A security-review finding, more severe than any of the CVEs this
    project set out to fix: dulwich honors `core.worktree` in
    .git/config, and re-opens a Repo internally on every porcelain
    call — so a caller could fs_write a .git/config with
    `core.worktree = <somewhere outside the confined root>` and every
    subsequent git tool would silently operate outside the root
    entirely, invisible to the per-path containment check (which only
    ever sees the *confined* repo directory, never wherever dulwich
    actually redirected itself to). This is a full read/exfiltration
    primitive using only this server's own exposed tools — no symlinks,
    no OS privileges required."""

    def test_a_repo_config_with_core_worktree_is_refused_outright(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        root = ConfinedRoot(allowed)
        git_init(root, "repo")

        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("TOP SECRET")

        fs_write_file(
            root,
            "repo/.git/config",
            f"[core]\n\tworktree = {outside}\n",
        )

        with pytest.raises(UnsafeRepositoryError):
            git_status(root, "repo")

        with pytest.raises(UnsafeRepositoryError):
            git_add(root, "repo", ["secret.txt"])

    def test_the_exact_reported_exfiltration_chain_is_blocked_end_to_end(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        root = ConfinedRoot(allowed)
        git_init(root, "repo")

        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "shared_name.txt").write_text("TOP-SECRET-CONTENT-FROM-OUTSIDE")

        fs_write_file(root, "repo/.git/config", f"[core]\n\tworktree = {outside}\n")
        fs_write_file(root, "repo/shared_name.txt", "harmless decoy")

        with pytest.raises(UnsafeRepositoryError):
            git_add(root, "repo", ["shared_name.txt"])
        with pytest.raises(UnsafeRepositoryError):
            git_diff(root, "repo", staged=True)
        with pytest.raises(UnsafeRepositoryError):
            git_commit(root, "repo", "exfil", "Attacker <a@example.com>")


class TestHooksAreNeverRun:
    """dulwich runs pre-commit/commit-msg/post-commit hooks via
    subprocess.call() if they exist and are executable — real process
    execution, unrelated to (and not covered by) the "no clean/smudge
    filter execution" property. git_commit must always skip them."""

    def test_commit_always_passes_no_verify(self, tmp_path, monkeypatch):
        import dulwich.porcelain as porcelain_module

        root = ConfinedRoot(tmp_path)
        git_init(root, "repo")
        (tmp_path / "repo" / "a.txt").write_text("v1")
        git_add(root, "repo", ["a.txt"])

        captured = {}
        real_commit = porcelain_module.commit

        def spy_commit(*args, **kwargs):
            captured.update(kwargs)
            return real_commit(*args, **kwargs)

        monkeypatch.setattr(porcelain_module, "commit", spy_commit)
        git_commit(root, "repo", "msg", AUTHOR)

        assert captured.get("no_verify") is True


class TestGitCommitAndLogAndDiff:
    def test_full_cycle_init_add_commit_log_diff(self, tmp_path):
        root = ConfinedRoot(tmp_path)
        git_init(root, "repo")
        (tmp_path / "repo" / "a.txt").write_text("v1")
        git_add(root, "repo", ["a.txt"])
        result = git_commit(root, "repo", "initial commit", AUTHOR)
        assert len(result["commit"]) == 40  # a real sha1 hex digest

        log_output = git_log(root, "repo")
        assert "initial commit" in log_output

        (tmp_path / "repo" / "a.txt").write_text("v2")
        diff_output = git_diff(root, "repo")
        assert "a.txt" in diff_output


class TestRepoPathItselfMustStayConfined:
    def test_status_on_a_repo_outside_root_is_rejected(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        ConfinedRoot(outside)  # a real repo location, just not our root
        allowed = tmp_path / "allowed"
        allowed.mkdir()

        root = ConfinedRoot(allowed)
        with pytest.raises(PathEscapeError):
            git_status(root, "../outside")
