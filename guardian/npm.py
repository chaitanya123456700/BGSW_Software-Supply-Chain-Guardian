import hashlib
import re
from pathlib import Path, PurePosixPath
from urllib.parse import quote

from semantic_version import Version

from .files import matches_workspace, read_json
from .models import Component, Edge, Evidence, Inventory, Project, stable_id

NAME = re.compile(r"^(?:@[^/@\s\\]+/)?[^/@\s\\]+$")
MAX_COMPONENTS = 20000
MAX_EDGES = 100000


def pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def resolve_location(records: dict, parent_path: str, name: str, peer=False) -> str | None:
    current = PurePosixPath(parent_path)
    if peer and "node_modules/" in str(current):
        current = PurePosixPath(str(current).rsplit("node_modules/", 1)[0].rstrip("/"))
    for directory in [current, *current.parents]:
        if directory.name != "node_modules":
            candidate = str(directory / "node_modules" / name)
            if candidate in records:
                return candidate
    return None


def declarations(document: dict):
    groups = [("dependencies", "production"), ("devDependencies", "development"),
              ("optionalDependencies", "optional"), ("peerDependencies", "peer")]
    for field, _ in groups:
        value = document.get(field, {})
        if not isinstance(value, dict) or any(not NAME.fullmatch(name) or name in {".", ".."}
                or not isinstance(constraint, str) for name, constraint in value.items()):
            raise ValueError(f"Invalid manifest {field}")
    metadata = document.get("peerDependenciesMeta", {})
    if not isinstance(metadata, dict) or any(not isinstance(value, dict) for value in metadata.values()):
        raise ValueError("Invalid peerDependenciesMeta")
    for field, kind in groups:
        for name, constraint in document.get(field, {}).items():
            if field == "dependencies" and name in document.get("optionalDependencies", {}):
                continue
            if field == "devDependencies" and (name in document.get("dependencies", {}) or name in document.get("optionalDependencies", {})):
                continue
            yield field, kind, name, constraint, kind == "optional" or (kind == "peer" and metadata.get(name, {}).get("optional") is True)


def add_declared_dependency(inventory: Inventory, root: Component, field: str, kind: str,
                            name: str, constraint: str, optional: bool, evidence: Evidence):
    exact = None
    if re.fullmatch(r"[=v]?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", constraint.strip()):
        try:
            exact = str(Version(constraint.strip().lstrip("=v")))
        except ValueError:
            pass
    component = Component(id=stable_id("declared", root.id, field, name), name=name,
        identity=f"pkg:npm/{quote(name, safe='/')}", path=root.path, project=root.project,
        requested_constraint=constraint, resolution_status="declared_only", version_source="manifest_constraint",
        declared_version=exact,
        dev=kind == "development", optional=optional, evidence=[evidence])
    inventory.components.append(component)
    inventory.edges.append(Edge(parent=root.id, child=component.id, dependency=name,
        dependency_type=kind, constraint=constraint, optional=optional, status="declared_only",
        reason="Exact resolved version is unknown", evidence=evidence))


def extract_manifest(repo_path: Path, manifest_path: str, repository_id: str) -> Inventory:
    manifest, digest = read_json(repo_path, manifest_path)
    declared = list(declarations(manifest))
    path = PurePosixPath(manifest_path).parent.as_posix()
    name = manifest.get("name") or "(unnamed application)"
    if not isinstance(name, str):
        raise ValueError("Invalid manifest name")
    evidence = Evidence(file=manifest_path, pointer="", sha256=digest)
    root = Component(id=stable_id("application", repository_id, manifest_path), name=name,
        path=path, project=path, kind="application", evidence=[evidence],
        resolution_status="unknown", version_source="manifest")
    warning = "No lockfile found. Displaying declared dependency constraints; exact resolved versions are unknown."
    project = Project(id=stable_id("project", repository_id, path, "npm"), repository_id=repository_id,
        name=name, path=path, ecosystem="npm", root_id=root.id, manifest_path=manifest_path,
        completeness_status="partial" if declared else "declared_empty",
        dependency_status="declared_only" if declared else "declared_empty", coverage_status="partial",
        warnings=[warning])
    inventory = Inventory(components=[root], roots=[root.id], projects=[project], warnings=[warning], repository_id=repository_id)
    for field, kind, name, constraint, optional in declared:
        add_declared_dependency(inventory, root, field, kind, name, constraint, optional,
            Evidence(file=manifest_path, pointer=f"/{field}/{pointer(name)}", sha256=digest))
    if len(inventory.components) > MAX_COMPONENTS or len(inventory.edges) > MAX_EDGES:
        raise ValueError("Manifest dependency limit exceeded")
    return inventory


def reconcile_npm_projects(repo_path: Path, lockfile: str, manifests: list[str], repository_id: str) -> Inventory:
    """Reuse lockfile extraction, then reconcile authoritative project declarations."""
    inventory = extract_npm(repo_path, lockfile)
    inventory.repository_id = repository_id
    identifiers = {component.id: stable_id("instance", repository_id, component.id) for component in inventory.components}
    for component in inventory.components:
        component.id = identifiers[component.id]
    for edge in inventory.edges:
        edge.parent = identifiers[edge.parent]
        edge.child = identifiers.get(edge.child)
    lock, digest = read_json(repo_path, lockfile)
    records = lock["packages"]
    context = PurePosixPath(lockfile).parent
    by_location = {str(PurePosixPath(component.path).relative_to(context)): component for component in inventory.components}
    by_location[""] = by_location.pop(".")
    aliases = {}
    for path, record in records.items():
        target = record.get("resolved")
        if record.get("link") and isinstance(target, str) and target in records and not records[target].get("link"):
            alias, canonical = by_location[path], by_location[target]
            aliases[alias.id] = canonical.id
            canonical.installation_paths.append(alias.path)
            canonical.evidence.extend(alias.evidence[:1])
    inventory.components = [component for component in inventory.components if component.id not in aliases]
    components_by_id = {component.id: component for component in inventory.components}
    # Workspace membership is containment, not an application dependency.
    inventory.edges = [edge for edge in inventory.edges if edge.parent not in aliases
                       and not (edge.dependency_type == "workspace" and edge.evidence.pointer.endswith("/workspaces"))]
    for edge in inventory.edges:
        edge.child = aliases.get(edge.child, edge.child)
    inventory.roots = []
    root_manifest = (context / "package.json").as_posix()
    sources = list(dict.fromkeys([root_manifest, *manifests]))
    workspace_id = stable_id("project", repository_id, context.as_posix(), "npm")
    for manifest_path in sources:
        exists = (repo_path / manifest_path).exists()
        if not exists and manifest_path != root_manifest:
            continue
        path = PurePosixPath(manifest_path).parent
        location = path.relative_to(context).as_posix()
        location = "" if location == "." else location
        manifest, manifest_digest = read_json(repo_path, manifest_path) if exists else ({}, digest)
        declared = list(declarations(manifest)) if exists else list(declarations(records.get(location, {})))
        root = by_location.get(location)
        missing_record = root is None
        if root is None:
            root = Component(id=stable_id("application", repository_id, manifest_path),
                name=manifest.get("name") or "(unnamed application)", path=path.as_posix(), project=path.as_posix(),
                kind="application", resolution_status="unknown", version_source="manifest",
                evidence=[Evidence(file=manifest_path, pointer="", sha256=manifest_digest)])
            inventory.components.append(root)
        root.kind = "application"
        root.project = path.as_posix()
        if exists:
            if not isinstance(manifest.get("name", root.name), str):
                raise ValueError("Invalid manifest name")
            root.name = manifest.get("name") or root.name
            root.evidence.append(Evidence(file=manifest_path, pointer="", sha256=manifest_digest))
        inventory.roots.append(root.id)
        project = Project(id=stable_id("project", repository_id, path.as_posix(), "npm"), repository_id=repository_id,
            name=root.name, path=path.as_posix(), ecosystem="npm", root_id=root.id,
            manifest_path=manifest_path if exists else None, lockfile_path=lockfile,
            workspace_id=workspace_id if location else None, workspace_membership=context.as_posix() if location else None,
            completeness_status="verified", dependency_status="has_dependencies" if declared else "verified_empty", coverage_status="verified")
        if missing_record or not exists:
            project.warnings.append("Insufficient project metadata: manifest or workspace lockfile record is missing; ownership is unresolved")
        if exists:
            recorded = {(field, name, constraint) for field, _, name, constraint, _ in declarations(records.get(location, {}))}
            requested = {(field, name, constraint) for field, _, name, constraint, _ in declared}
            if recorded != requested:
                project.warnings.append("Manifest/lockfile inconsistency: dependency declarations differ")
            inventory.edges = [edge for edge in inventory.edges if edge.parent != root.id]
            for field, kind, name, constraint, optional in declared:
                evidence = Evidence(file=manifest_path, pointer=f"/{field}/{pointer(name)}", sha256=manifest_digest)
                target_path = resolve_location(records, location, name, kind == "peer") if not missing_record else None
                target = by_location.get(target_path)
                if target and records[target_path].get("link") and target.id not in aliases:
                    target = None
                if target:
                    child = aliases.get(target.id, target.id)
                    target_component = components_by_id[child]
                    inventory.edges.append(Edge(parent=root.id, child=child, dependency=name,
                        dependency_type=kind, workspace=target.id in aliases, constraint=constraint,
                        optional=optional, status="resolved", evidence=evidence))
                    if target_component.version is None:
                        project.warnings.append(f"Resolved location has no version: {name}")
                else:
                    add_declared_dependency(inventory, root, field, kind, name, constraint, optional, evidence)
                    project.warnings.append(f"Manifest/lockfile inconsistency: no resolved instance for {name}")
        inventory.projects.append(project)
    application_version_warnings = {f"Version unknown: {location}" for location, component in by_location.items()
                                    if component.kind == "application" or (component.id in aliases and
                                        components_by_id[aliases[component.id]].kind == "application")}
    inventory.warnings = [warning for warning in inventory.warnings if warning not in application_version_warnings]
    # Assess each app through dependency edges, never through workspace membership.
    adjacency = {}
    for edge in inventory.edges:
        if edge.status == "resolved":
            adjacency.setdefault(edge.parent, set()).add(edge.child)
    all_reachable = set()
    for project in inventory.projects:
        reachable, stack = set(), [project.root_id]
        while stack:
            identifier = stack.pop()
            if identifier not in reachable:
                reachable.add(identifier)
                stack.extend(adjacency.get(identifier, ()))
        all_reachable.update(reachable)
        if any(edge.parent in reachable and edge.status != "resolved" for edge in inventory.edges):
            project.warnings.append("Some dependency declarations have no verified lockfile relationship")
        if any(component.id in reachable and component.kind == "package" and component.version is None
               for component in inventory.components):
            project.warnings.append("Missing version metadata in reachable lockfile instances")
        if project.warnings:
            project.completeness_status = "partial"
            project.coverage_status = "partial"
            if project.dependency_status == "verified_empty":
                project.dependency_status = "unknown"
        elif not any(edge.parent == project.root_id for edge in inventory.edges):
            project.completeness_status = "verified_empty"
    orphans = [c for c in inventory.components if c.id not in all_reachable and c.resolution_status != "declared_only"]
    if orphans:
        warning = "Orphan lockfile records have unresolved application ownership; preserved as observations"
        inventory.warnings.append(warning)
        for project in inventory.projects:
            project.completeness_status = "partial"
            project.coverage_status = "partial"
            project.warnings.append(warning)
            if project.dependency_status == "verified_empty":
                project.dependency_status = "unknown"
    for project in inventory.projects:
        inventory.warnings.extend(f"{project.path}: {warning}" for warning in project.warnings)
    if len(inventory.components) > MAX_COMPONENTS or len(inventory.edges) > MAX_EDGES:
        raise ValueError("Project inventory limit exceeded")
    return inventory


def extract_npm(repo_path: Path, lockfile: str) -> Inventory:
    """Extract instances and declared edges from npm package-lock v2/v3.

    Resolution uses package locations, never name-only matching. Resolved means
    a lockfile location exists; it does not assert semver or runtime availability.
    """
    lock, digest = read_json(repo_path, lockfile)
    if type(lock.get("lockfileVersion")) is not int or lock["lockfileVersion"] not in {2, 3}:
        raise ValueError("Only npm package-lock v2/v3 is supported")
    records = lock.get("packages")
    if not isinstance(records, dict) or not isinstance(records.get(""), dict):
        raise ValueError("Lockfile must contain packages and a root record")
    if len(records) > MAX_COMPONENTS:
        raise ValueError("Lockfile component limit exceeded")
    if any(not isinstance(record, dict) for record in records.values()):
        raise ValueError("Package records must be objects")
    project = str(PurePosixPath(lockfile).parent)
    result = Inventory()
    instances = {}
    effective = {}
    targets = {}

    def evidence(path, suffix=""):
        return Evidence(file=lockfile, pointer=f"/packages/{pointer(path)}{suffix}", sha256=digest)

    for path, record in records.items():
        if (not isinstance(record, dict) or "\\" in path or path.startswith("/")
                or ".." in PurePosixPath(path).parts or str(PurePosixPath(path)) != (path or ".")):
            raise ValueError(f"Invalid package record path: {path}")
        target_path = path
        source = record
        if record.get("link"):
            target_path = record.get("resolved")
            if not isinstance(target_path, str) or target_path not in records or records[target_path].get("link"):
                result.warnings.append(f"Unsupported or missing link target: {path}")
                target_path = path
                source = {}
            else:
                source = records[target_path]
        if path:
            install_name = path.rsplit("node_modules/", 1)[-1]
            if "node_modules/" in path and not NAME.fullmatch(install_name):
                raise ValueError(f"Invalid package installation path: {path}")
            name = source.get("name") or install_name
        else:
            name = source.get("name") or lock.get("name") or "(unnamed application)"
        version = source.get("version")
        if not isinstance(name, str) or (version is not None and not isinstance(version, str)):
            raise ValueError(f"Invalid package name/version at {path}")
        identity = f"pkg:npm/{quote(name, safe='/')}@{quote(version, safe='')}" if version else None
        instance = Component(
            id="npm:" + hashlib.sha256(f"{lockfile}\0{path}".encode()).hexdigest()[:24],
            name=name, version=version, identity=identity,
            path=str(PurePosixPath(project) / path) if path else project,
            project=project, kind="application" if path == "" else "package",
            dev=bool(source.get("dev") or source.get("devOptional")),
            optional=bool(source.get("optional") or source.get("devOptional")),
            link_target=target_path if record.get("link") else None,
            resolution_status="unknown" if path and not version else "resolved",
            version_source="unknown" if path and not version else "lockfile",
            evidence=[evidence(path)] + ([evidence(target_path)] if target_path != path else []),
        )
        if path and not version:
            result.warnings.append(f"Version unknown: {path}")
        result.components.append(instance)
        instances[path] = instance
        effective[path] = source
        targets[path] = target_path
    result.roots = [instances[""].id]
    workspaces = records[""].get("workspaces", [])
    if isinstance(workspaces, dict):
        workspaces = workspaces.get("packages", [])
    if not isinstance(workspaces, list) or any(not isinstance(item, str) for item in workspaces):
        raise ValueError("Invalid workspace declarations")
    if any(any(token in pattern for token in ["**", "!", "{", "}", "(", ")"]) for pattern in workspaces):
        result.warnings.append("Complex workspace globs are unsupported; workspace membership may be incomplete")
    for path, instance in instances.items():
        if path and "node_modules/" not in path and any(matches_workspace(path, pattern) for pattern in workspaces):
            instance.kind = "workspace"
            result.edges.append(Edge(parent=instances[""].id, child=instance.id, dependency=instance.name,
                dependency_type="workspace", status="resolved", evidence=evidence("", "/workspaces"),
                version_satisfaction="not_applicable"))

    def resolve(parent_path, name, peer):
        current = PurePosixPath(targets[parent_path])
        if peer and "node_modules/" in str(current):
            prefix = str(current).rsplit("node_modules/", 1)[0].rstrip("/")
            current = PurePosixPath(prefix)
        for directory in [current, *current.parents]:
            if directory.name == "node_modules":
                continue
            candidate = str(directory / "node_modules" / name)
            if candidate in instances:
                if effective[candidate] == {} and records[candidate].get("link"):
                    return None
                return instances[candidate].id
        return None

    for path, record in effective.items():
        groups = [("dependencies", "production"), ("optionalDependencies", "optional"),
                  ("peerDependencies", "peer")]
        if not path or "node_modules/" not in path or records[path].get("link"):
            groups.append(("devDependencies", "development"))
        for field, kind in groups:
            declarations = record.get(field, {})
            if not isinstance(declarations, dict):
                raise ValueError(f"Invalid {field} at {path}")
            for name, constraint in declarations.items():
                if not NAME.fullmatch(name) or name in {".", ".."} or not isinstance(constraint, str):
                    raise ValueError(f"Invalid dependency declaration at {path}/{field}")
                if field == "dependencies" and name in record.get("optionalDependencies", {}):
                    continue
                if field == "devDependencies" and (name in record.get("dependencies", {})
                                                   or name in record.get("optionalDependencies", {})):
                    continue
                child = resolve(path, name, kind == "peer")
                metadata = record.get("peerDependenciesMeta", {}).get(name, {})
                edge = Edge(parent=instances[path].id, child=child, dependency=name,
                            dependency_type=kind, constraint=constraint,
                            optional=kind == "optional" or (kind == "peer" and metadata.get("optional") is True),
                            status="resolved" if child else "unresolved",
                            reason=None if child else "No reliable lockfile location found",
                            evidence=evidence(targets[path], f"/{field}/{pointer(name)}"))
                result.edges.append(edge)
                if len(result.edges) > MAX_EDGES:
                    raise ValueError("Lockfile edge limit exceeded")
    return result
