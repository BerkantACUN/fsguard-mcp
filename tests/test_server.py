"""Integration tests for the MCP tool layer."""

import pytest

import fsguard_mcp.server as server_module


@pytest.fixture(autouse=True)
def _fresh_root(tmp_path, monkeypatch):
    monkeypatch.setenv("FSGUARD_ROOT", str(tmp_path))
    server_module._root = None
    yield tmp_path
    server_module._root = None


class TestFsTools:
    def test_write_then_read_round_trips(self, _fresh_root):
        server_module.fs_write("a.txt", "hello")
        result = server_module.fs_read("a.txt")
        assert result["content"] == "hello"

    def test_read_outside_root_is_a_typed_error_not_a_crash(self, _fresh_root):
        result = server_module.fs_read("../../../etc/passwd")
        assert result["error"] == "PathEscape"

    def test_list_reports_written_file(self, _fresh_root):
        server_module.fs_write("a.txt", "hi")
        result = server_module.fs_list(".")
        names = [e["name"] for e in result["entries"]]
        assert "a.txt" in names

    def test_search_finds_matching_files(self, _fresh_root):
        server_module.fs_write("a.py", "x")
        server_module.fs_write("b.txt", "x")
        result = server_module.fs_search("*.py")
        assert result["matches"] == ["a.py"]

    def test_move_relocates_the_file(self, _fresh_root):
        server_module.fs_write("src.txt", "hi")
        server_module.fs_move("src.txt", "dst.txt")
        assert server_module.fs_read("dst.txt")["content"] == "hi"


class TestGitTools:
    def test_init_status_add_commit_cycle(self, _fresh_root):
        init_result = server_module.git_init_repo("repo")
        assert "error" not in init_result

        server_module.fs_write("repo/a.txt", "v1")
        status = server_module.git_repo_status("repo")
        assert "a.txt" in status["untracked"]

        add_result = server_module.git_stage("repo", ["a.txt"])
        assert "error" not in add_result

        commit_result = server_module.git_commit_repo("repo", "first", "Test <t@example.com>")
        assert "error" not in commit_result
        assert len(commit_result["commit"]) == 40

        log_result = server_module.git_log_repo("repo")
        assert "first" in log_result["log"]

    def test_add_with_traversal_is_a_typed_error_and_stages_nothing(self, _fresh_root):
        server_module.git_init_repo("repo")
        server_module.fs_write("repo/good.txt", "hi")

        result = server_module.git_stage("repo", ["good.txt", "../../outside.txt"])
        assert result["error"] == "PathEscape"

        status = server_module.git_repo_status("repo")
        staged_files = [f for files in status["staged"].values() for f in files]
        assert "good.txt" not in staged_files

    def test_status_on_a_non_repo_is_a_typed_error(self, _fresh_root):
        result = server_module.git_repo_status(".")
        assert result["error"] == "NotAGitRepositoryError"


class TestMissingRoot:
    def test_missing_fsguard_root_is_a_clear_error(self, monkeypatch):
        monkeypatch.delenv("FSGUARD_ROOT", raising=False)
        server_module._root = None
        result = server_module.fs_list(".")
        assert result["error"] == "RuntimeError"
        assert "FSGUARD_ROOT" in result["message"]
