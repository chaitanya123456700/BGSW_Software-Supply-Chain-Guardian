"""Read Python dependency declarations as data; never execute a build backend or pip."""
import hashlib
import re
import tomllib
from pathlib import Path, PurePosixPath
from urllib.parse import quote

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .files import safe_file
from .models import Component, Edge, Evidence, Inventory, Project, stable_id
from .npm import MAX_COMPONENTS, MAX_EDGES, pointer


def extract_python(repo: Path, manifests: list[str], repository_id: str) -> Inventory:
    if not manifests:
        raise ValueError("Python manifest is missing")
    path = PurePosixPath(manifests[0]).parent.as_posix()
    if any(PurePosixPath(name).parent.as_posix() != path for name in manifests):
        raise ValueError("Python manifests must belong to one project directory")
    root = Component(id=stable_id("application", repository_id, path, "python"), name=path if path != "." else "(Python application)",
                     path=path, project=path, kind="application", ecosystem="python", evidence=[],
                     resolution_status="unknown", version_source="manifest")
    inventory = Inventory(components=[root], roots=[root.id], repository_id=repository_id)
    warnings = ["Python manifests declare requirements, not installed versions or a verified transitive graph."]
    incomplete = False

    def warn(message):
        nonlocal incomplete
        incomplete = True
        if len(warnings) < 100:
            warnings.append(message)

    def add(raw, evidence, group="production", optional=False):
        if len(inventory.components) >= MAX_COMPONENTS or len(inventory.edges) >= MAX_EDGES:
            raise ValueError("Python manifest dependency limit exceeded")
        if not isinstance(raw, str) or len(raw) > 8192:
            warn(f"{evidence.file}:{evidence.pointer}: invalid or oversized requirement was skipped")
            return
        try:
            requirement = Requirement(raw)
        except InvalidRequirement:
            warn(f"{evidence.file}:{evidence.pointer}: unsupported requirement syntax was skipped")
            return
        name = canonicalize_name(requirement.name)
        exact = None
        specifiers = list(requirement.specifier)
        if len(specifiers) == 1 and specifiers[0].operator == "==" and "*" not in specifiers[0].version:
            try:
                Version(specifiers[0].version)
                exact = specifiers[0].version
            except InvalidVersion:
                pass
        if requirement.url:
            warn(f"{evidence.file}:{evidence.pointer}: direct URL requirement retained but never fetched")
        component = Component(id=stable_id("declared", root.id, evidence.file, evidence.pointer), name=name,
            identity=f"pkg:pypi/{quote(name, safe='')}", ecosystem="python", path=path, project=path,
            requested_constraint=raw, declared_version=exact, resolution_status="declared_only",
            version_source="manifest_constraint", environment_marker=str(requirement.marker) if requirement.marker else None,
            extras=sorted(requirement.extras), declaration_group=group, optional=optional, evidence=[evidence])
        inventory.components.append(component)
        inventory.edges.append(Edge(parent=root.id, child=component.id, dependency=name,
            dependency_type="optional" if optional else "production", constraint=raw, optional=optional,
            status="declared_only", evidence=evidence, reason="Python requirement; installation and environment are unverified"))

    for manifest in manifests:
        raw = safe_file(repo, manifest).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        root.evidence.append(Evidence(file=manifest, pointer="", sha256=digest))

        def evidence(location):
            return Evidence(file=manifest, pointer=location, sha256=digest)

        try:
            text = raw.decode("utf-8")
        except UnicodeError as exc:
            raise ValueError(f"Invalid UTF-8 in {manifest}") from exc
        if manifest.endswith("pyproject.toml"):
            try:
                document = tomllib.loads(text)
            except (tomllib.TOMLDecodeError, RecursionError) as exc:
                raise ValueError(f"Invalid TOML in {manifest}") from exc
            project = document.get("project")
            if not isinstance(project, dict):
                warn(f"{manifest}: standard [project] metadata is missing; legacy tool configuration is detect-only")
                continue
            if not isinstance(project.get("name", root.name), str):
                raise ValueError(f"Invalid project name in {manifest}")
            root.name = project.get("name", root.name)
            dependencies, optional = project.get("dependencies", []), project.get("optional-dependencies", {})
            dynamic = project.get("dynamic", [])
            if not isinstance(dependencies, list) or not isinstance(optional, dict) or not isinstance(dynamic, list):
                raise ValueError(f"Invalid Python dependency metadata in {manifest}")
            if any(field in dynamic for field in ("dependencies", "optional-dependencies")):
                warn(f"{manifest}: dynamic dependency metadata is not executed or resolved")
            for index, requirement in enumerate(dependencies):
                add(requirement, evidence(f"/project/dependencies/{index}"))
            for group, requirements in optional.items():
                if not isinstance(requirements, list):
                    raise ValueError(f"Invalid optional dependency group in {manifest}")
                for index, requirement in enumerate(requirements):
                    add(requirement, evidence(f"/project/optional-dependencies/{pointer(group)}/{index}"), group, True)
        else:
            pending, first = "", 1
            for number, line in enumerate(text.splitlines(), 1):
                if not pending:
                    first = number
                line = line.strip()
                pending += line[:-1] + " " if line.endswith("\\") else line
                if len(pending) > 8192:
                    raise ValueError(f"Oversized requirement line in {manifest}")
                if line.endswith("\\"):
                    continue
                requirement, pending = pending, ""
                requirement = re.split(r"\s+#", requirement, maxsplit=1)[0].strip()
                if not requirement or requirement.startswith("#"):
                    continue
                if requirement.startswith("-"):
                    warn(f"{manifest}:line {first}: pip options/includes/editable inputs are not followed")
                    continue
                requirement = re.sub(r"\s+--hash=sha256:[0-9a-fA-F]{64}(?=\s|$)", "", requirement)
                add(requirement, evidence(f"line:{first}"))
            if pending:
                warn(f"{manifest}: unfinished requirement continuation was skipped")
    has_dependencies = len(inventory.components) > 1
    project = Project(id=stable_id("project", repository_id, path, "python"), repository_id=repository_id,
        name=root.name, path=path, ecosystem="python", root_id=root.id, manifest_path=manifests[0], manifest_paths=manifests,
        completeness_status="partial" if has_dependencies or incomplete else "declared_empty", coverage_status="partial",
        dependency_status="declared_only" if has_dependencies else "unknown" if incomplete else "declared_empty", warnings=warnings)
    inventory.projects = [project]
    inventory.warnings = warnings
    return inventory
