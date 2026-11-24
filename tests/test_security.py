import sys

import pytest

from guardian.files import read_json
from guardian.ingestion import validate_repository_url
from guardian.process import ToolError, run_tool


@pytest.mark.parametrize("url", ["http://github.com/a/b", "https://github.com.evil.org/a/b",
    "https://user:pass@github.com/a/b", "file:///tmp/repo", "git@github.com:a/b", "https://github.com/a/b?x=y",
    "https://github.com/a/b#main", "https://github.com/a/b;id", "https://github.com/a/../b",
    "https://github.com:443/a/b", "https://github.com/a/b\n", "https://github.com/a/%2e%2e"])
def test_unsafe_urls_are_rejected(url):
    with pytest.raises(ValueError):
        validate_repository_url(url)


def test_valid_url_is_canonical():
    assert validate_repository_url("https://github.com/npm/cli/") == "https://github.com/npm/cli.git"


def test_symlink_source_is_not_read(tmp_path):
    (tmp_path / "package-lock.json").symlink_to("/etc/passwd")
    with pytest.raises(ValueError, match="Symlink"):
        read_json(tmp_path, "package-lock.json")


def test_subprocess_has_timeout_and_does_not_receive_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_SECRET_TEST", "should-not-pass")
    result = run_tool([sys.executable, "-c", "import os; print(os.getenv('GUARDIAN_SECRET_TEST'))"], tmp_path)
    assert result.stdout.strip() == "None"
    with pytest.raises(ToolError, match="timed out"):
        run_tool([sys.executable, "-c", "import time; time.sleep(10)"], tmp_path, timeout=0.1)
