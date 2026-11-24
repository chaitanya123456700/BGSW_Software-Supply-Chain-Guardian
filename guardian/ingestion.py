import re
import shutil
import tempfile
from pathlib import Path

from .files import walk_files
from .models import Repository
from .process import run_tool

GITHUB_URL = re.compile(r"https://github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9_][A-Za-z0-9_.-]{0,99})/?\Z")


def validate_repository_url(repo_url: str) -> str:
    match = GITHUB_URL.fullmatch(repo_url)
    if not match:
        raise ValueError("Use a public https://github.com/owner/repository URL without credentials, query, or fragment")
    owner, name = match.groups()
    if name.endswith(".git"):
        name = name[:-4]
    if not name or name in {".", ".."} or name.endswith("."):
        raise ValueError("Invalid GitHub repository name")
    return f"https://github.com/{owner}/{name}.git"


def ingest_repository(repo_url: str, workspace: Path) -> Repository:
    url = validate_repository_url(repo_url)
    workspace.mkdir(parents=True, exist_ok=True)
    isolated = Path(tempfile.mkdtemp(prefix="repo-", dir=workspace))
    repo = isolated / "source"
    try:
        run_tool(["git", "-c", "http.followRedirects=false", "-c", "credential.helper=",
                  "-c", "core.hooksPath=/dev/null", "clone", "--depth=1", "--single-branch",
                  "--no-tags", "--no-recurse-submodules", "--no-checkout", "--template=", "--", url, str(repo)],
                 isolated, timeout=90, monitor=isolated)
        commit = run_tool(["git", "rev-parse", "HEAD"], repo, timeout=10).stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
            raise ValueError("Git returned an invalid commit SHA")
        run_tool(["git", "-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=true",
                  "checkout", "--detach", commit], repo, timeout=45, monitor=isolated)
        list(walk_files(repo))
        return Repository(url=url, commit=commit, path=str(repo))
    except BaseException:
        shutil.rmtree(isolated, ignore_errors=True)
        raise
