import json
import tempfile
from pathlib import Path

from .files import safe_file
from .models import Inventory
from .process import run_tool


def cross_check_npm(repo: Path, lockfile: str, inventory: Inventory, artifacts: Path, index: int) -> dict:
    """Read npm's lockfile view in a clean directory, without repo configuration."""
    result = {"status": "failed", "tool": "npm ls", "artifact": f"npm-check-{index}.json"}
    try:
        with tempfile.TemporaryDirectory(prefix="npm-check-", dir=artifacts) as temporary:
            directory = Path(temporary)
            (directory / "empty-user.npmrc").write_text("")
            (directory / "empty-global.npmrc").write_text("")
            # npm needs only data files, never repository scripts or .npmrc.
            (directory / "package-lock.json").write_bytes(safe_file(repo, lockfile).read_bytes())
            project = Path(lockfile).parent
            manifest = project / "package.json"
            if (repo / manifest).exists():
                (directory / "package.json").write_bytes(safe_file(repo, manifest.as_posix()).read_bytes())
            workspaces = [item for item in inventory.projects if item.workspace_id and item.manifest_path]
            for workspace in workspaces:
                relative = Path(workspace.manifest_path).relative_to(project)
                destination = directory / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(safe_file(repo, workspace.manifest_path).read_bytes())
            completed = run_tool(["npm", "ls", "--all", "--long", "--json", "--package-lock-only",
                                  "--ignore-scripts", "--offline", "--no-audit", "--no-fund",
                                  *([] if workspaces else ["--workspaces=false"])],
                                 directory, timeout=30, check=False,
                                 extra_env={"NPM_CONFIG_USERCONFIG": str(directory / "empty-user.npmrc"),
                                            "NPM_CONFIG_GLOBALCONFIG": str(directory / "empty-global.npmrc")})
            (artifacts / result["artifact"]).write_text(completed.stdout)
            (artifacts / f"npm-check-{index}.stderr.log").write_text(completed.stderr)
            native = json.loads(completed.stdout)
            observed = set()
            stack = [native]
            while stack:
                parent = stack.pop()
                for name, child in parent.get("dependencies", {}).items():
                    if isinstance(child, dict):
                        if isinstance(child.get("version"), str):
                            observed.add((child.get("name", name), child["version"]))
                        stack.append(child)
            expected = {(c.name, c.version) for c in inventory.components if c.version and
                        c.kind != "repository" and (c.kind != "application" or (workspaces and c.path != project.as_posix()))}
            result.update(status="completed" if completed.returncode == 0 else "incomplete",
                          exit_code=completed.returncode, problems=native.get("problems", []),
                          native_package_versions=len(observed),
                          adapter_only=[list(pair) for pair in sorted(expected - observed)],
                          native_only=[list(pair) for pair in sorted(observed - expected)],
                          policy="Independent logical identity comparison, not proof of every edge; aliases and workspaces can differ.")
    except Exception as exc:
        result["error"] = str(exc)[:2000]
    return result
