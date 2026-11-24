from pathlib import Path

from .files import matches_workspace, read_json, walk_files
from .models import Ecosystem

MARKERS = {
    "requirements.txt": ("python", "pip", True),
    "pyproject.toml": ("python", "unknown", True),
    "poetry.lock": ("python", "poetry", False),
    "uv.lock": ("python", "uv", False),
    "pom.xml": ("maven", "maven", True),
    "go.mod": ("go", "go", True),
    "Cargo.lock": ("cargo", "cargo", False),
    "Cargo.toml": ("cargo", "cargo", True),
    "packages.lock.json": ("nuget", "nuget", False),
}


def detect_ecosystems(repo_path: Path) -> list[Ecosystem]:
    directories = {}
    for path in walk_files(repo_path):
        if path.name in {*MARKERS, "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}:
            directories.setdefault(path.parent, set()).add(path.name)
    result = []
    for directory, names in sorted(directories.items()):
        project = directory.relative_to(repo_path).as_posix()
        metadata_errors = []

        def metadata(path):
            try:
                return read_json(repo_path, path)[0]
            except ValueError as exc:
                metadata_errors.append(str(exc))
                return {}

        def relative(name):
            return (directory / name).relative_to(repo_path).as_posix()

        if names & {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}:
            declared = None
            if "package.json" in names:
                manifest = metadata(relative("package.json"))
                manager = manifest.get("packageManager", "")
                if not isinstance(manager, str):
                    metadata_errors.append("Invalid packageManager declaration")
                    manager = ""
                declared = manager.split("@", 1)[0] or None
            non_npm = names & {"pnpm-lock.yaml", "yarn.lock"}
            inherited = None
            covered_by = None
            if declared in {None, "npm"} and not names & {"pnpm-lock.yaml", "yarn.lock", "package-lock.json"}:
                for ancestor in directory.parents:
                    if not ancestor.is_relative_to(repo_path):
                        break
                    ancestor_names = directories.get(ancestor, set())
                    if "pnpm-lock.yaml" in ancestor_names:
                        inherited = "pnpm"
                        break
                    if "yarn.lock" in ancestor_names:
                        inherited = "yarn"
                        break
                    if "package-lock.json" in ancestor_names:
                        parent_lock = (ancestor / "package-lock.json").relative_to(repo_path).as_posix()
                        parent = metadata(parent_lock)
                        packages = parent.get("packages", {})
                        root_record = packages.get("", {}) if isinstance(packages, dict) else {}
                        workspaces = root_record.get("workspaces", []) if isinstance(root_record, dict) else []
                        if "package.json" in ancestor_names:
                            parent_manifest = metadata((ancestor / "package.json").relative_to(repo_path).as_posix())
                            workspaces = parent_manifest.get("workspaces", workspaces)
                        if isinstance(workspaces, dict):
                            workspaces = workspaces.get("packages", [])
                        local = directory.relative_to(ancestor).as_posix()
                        if (parent.get("lockfileVersion") in {2, 3} and isinstance(workspaces, list)
                                and all(isinstance(pattern, str) for pattern in workspaces)
                                and any(matches_workspace(local, pattern) for pattern in workspaces)):
                            covered_by = parent_lock
                        break
            managers = set()
            if "pnpm-lock.yaml" in names:
                managers.add(("pnpm", "pnpm-lock.yaml"))
            if "yarn.lock" in names:
                managers.add(("yarn", "yarn.lock"))
            if "package-lock.json" in names:
                managers.add(("npm", "package-lock.json"))
            if not managers:
                managers.add((declared or inherited or "npm", None))
            for manager, filename in sorted(managers, key=lambda x: x[0]):
                supported = False
                reason = "No dependency adapter for this package manager"
                if manager == "npm":
                    reason = "npm requires a package-lock v2/v3 file"
                    if filename:
                        lock = metadata(relative(filename))
                        supported = type(lock.get("lockfileVersion")) is int and lock["lockfileVersion"] in {2, 3}
                    if non_npm or declared not in {None, "npm"}:
                        supported = False
                        reason = "Conflicting package manager evidence; npm analysis skipped"
                    elif supported:
                        reason = None
                    if covered_by:
                        supported = True
                        reason = "Workspace inventory is covered by ancestor lockfile"
                    if not filename and not covered_by and "package.json" in names and not metadata_errors:
                        supported = True
                        reason = "Manifest-only npm declarations; exact resolved versions are unknown"
                result.append(Ecosystem(ecosystem="npm", package_manager=manager,
                    project_root=project, manifest_path=relative("package.json") if "package.json" in names else None,
                    lockfile_path=relative(filename) if filename else covered_by, supported=supported,
                    reason=reason, covered_by=covered_by, metadata_errors=metadata_errors.copy()))
        python_files = names & {"requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock"}
        if python_files:
            manifests = [relative(name) for name in ("pyproject.toml", "requirements.txt") if name in names]
            locks = sorted(python_files & {"poetry.lock", "uv.lock"})
            manager = "poetry" if "poetry.lock" in locks else "uv" if locks else "pip"
            result.append(Ecosystem(ecosystem="python", package_manager=manager, project_root=project,
                manifest_path=manifests[0] if manifests else None, manifest_paths=manifests,
                lockfile_path=relative(locks[0]) if locks else None, supported=bool(manifests) and not locks,
                reason="Unsupported Python lockfile; detect-only" if locks else "Python manifest declarations; installed versions and topology are unknown"))
        for filename in sorted((names & MARKERS.keys()) - python_files):
            ecosystem, manager, is_manifest = MARKERS[filename]
            result.append(Ecosystem(ecosystem=ecosystem, package_manager=manager, project_root=project,
                manifest_path=relative(filename) if is_manifest else None,
                lockfile_path=relative(filename) if not is_manifest else None,
                reason="Detected; native dependency adapter not implemented in Phase 1"))
    return result
