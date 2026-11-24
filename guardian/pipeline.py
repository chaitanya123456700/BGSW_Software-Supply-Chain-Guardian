import os
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from .detection import detect_ecosystems
from .depsdev import infer_dependencies
from .files import safe_file, walk_files, write_json
from .graph import build_graph
from .ingestion import ingest_repository
from .models import Component, Edge, Evidence, Inventory, Project, Repository, stable_id
from .npm import MAX_COMPONENTS, MAX_EDGES, extract_manifest, reconcile_npm_projects
from .process import SCAN_DEADLINE
from .python import extract_python
from .sbom import generate_sbom
from .verification import cross_check_npm


def now():
    return datetime.now(timezone.utc).isoformat()


def analyze_repository(repository: Repository, artifacts: Path, update=lambda stage: None, *, deps_transport=None) -> dict:
    """Analyze a trusted workspace handle; the HTTP API never accepts local paths."""
    artifacts.mkdir(parents=True, exist_ok=True)
    repo = Path(repository.path)
    repository_id = stable_id("repository", repository.url.removesuffix(".git").rstrip("/").casefold())
    report = {"repository": repository.model_dump(exclude={"path"}), "started_at": now(),
              "status": "running", "warnings": [], "errors": [], "native_checks": []}
    update("Detecting ecosystems")
    detected = detect_ecosystems(repo)
    report["ecosystems"] = [e.model_dump() for e in detected]
    report["repository"]["repository_id"] = repository_id
    inventory = Inventory(repository_id=repository_id)
    processed_locks = set()
    inference_roots = set()

    def observed_project(ecosystem, status, warning):
        evidence = []
        source = ecosystem.manifest_path or ecosystem.lockfile_path
        if source:
            try:
                evidence = [Evidence(file=source, pointer="", sha256=hashlib.sha256(safe_file(repo, source).read_bytes()).hexdigest())]
            except ValueError:
                pass
        identifier = stable_id("project", repository_id, ecosystem.project_root, ecosystem.ecosystem)
        # Different unsupported managers at one project share one application root.
        if any(project.id == identifier for project in inventory.projects):
            return Inventory()
        root = Component(id=identifier, name=ecosystem.project_root if ecosystem.project_root != "." else "(unknown application)",
            path=ecosystem.project_root, project=ecosystem.project_root, ecosystem=ecosystem.ecosystem,
            kind="application", resolution_status="unknown", version_source="unknown", evidence=evidence)
        project = Project(id=identifier, repository_id=repository_id, name=root.name, path=root.path,
            ecosystem=ecosystem.ecosystem, root_id=root.id, manifest_path=ecosystem.manifest_path,
            lockfile_path=ecosystem.lockfile_path, completeness_status=status, coverage_status=status, warnings=[warning])
        return Inventory(components=[root], roots=[root.id], projects=[project], warnings=[warning])
    if not detected:
        report["warnings"].append("Insufficient evidence: no supported manifest or lockfile found; dependency status is unknown")
        report["metadata_observations"] = [path.relative_to(repo).as_posix() for path in walk_files(repo)
            if path.name in {"Dockerfile", "sbom.json"} or path.name.endswith((".cdx.json", ".spdx.json"))][:100]
    for index, ecosystem in enumerate(detected):
        if index >= 30:
            report["warnings"].append("Project analysis limit reached (30); remaining projects were skipped")
            break
        if ecosystem.lockfile_path in processed_locks:
            continue
        try:
            update(f"Extracting metadata for {ecosystem.project_root}")
            if ecosystem.metadata_errors:
                raise ValueError("; ".join(ecosystem.metadata_errors))
            if ecosystem.ecosystem == "npm" and ecosystem.supported and ecosystem.lockfile_path:
                manifests = [item.manifest_path for item in detected if item.lockfile_path == ecosystem.lockfile_path and item.manifest_path]
                extracted = reconcile_npm_projects(repo, ecosystem.lockfile_path, manifests, repository_id)
                processed_locks.add(ecosystem.lockfile_path)
                report["native_checks"].append(cross_check_npm(repo, ecosystem.lockfile_path, extracted, artifacts, index))
            elif ecosystem.package_manager == "npm" and ecosystem.manifest_path and (ecosystem.supported or "Conflicting" not in (ecosystem.reason or "")):
                extracted = extract_manifest(repo, ecosystem.manifest_path, repository_id)
                if ecosystem.lockfile_path:
                    extracted.warnings.append("Lockfile inconsistency or unsupported format; only manifest declarations are displayed")
            elif ecosystem.ecosystem == "python" and ecosystem.supported and ecosystem.manifest_path:
                extracted = extract_python(repo, ecosystem.manifest_paths, repository_id)
            else:
                warning = f"{ecosystem.project_root}: {ecosystem.package_manager}: {ecosystem.reason}"
                extracted = observed_project(ecosystem, "unsupported", warning)
            if (len(inventory.components) + len(extracted.components) > MAX_COMPONENTS
                    or len(inventory.edges) + len(extracted.edges) > MAX_EDGES):
                report["warnings"].append("Combined inventory limit reached; remaining projects were skipped")
                break
            inventory.components.extend(extracted.components)
            inventory.edges.extend(extracted.edges)
            inventory.roots.extend(extracted.roots)
            inventory.projects.extend(extracted.projects)
            inventory.warnings.extend(extracted.warnings)
            if ecosystem.supported and not ecosystem.lockfile_path:
                inference_roots.update(extracted.roots)
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            error = f"{ecosystem.manifest_path or ecosystem.lockfile_path}: {exc}"
            report["errors"].append(error)
            try:
                extracted = extract_manifest(repo, ecosystem.manifest_path, repository_id) if ecosystem.package_manager == "npm" and ecosystem.manifest_path else observed_project(ecosystem, "failed", error)
                for project in extracted.projects:
                    project.completeness_status = "failed"
                    project.coverage_status = "failed"
                    project.warnings.append(error)
            except (ValueError, TypeError):
                extracted = observed_project(ecosystem, "failed", error)
            inventory.components.extend(extracted.components)
            inventory.edges.extend(extracted.edges)
            inventory.roots.extend(extracted.roots)
            inventory.projects.extend(extracted.projects)
            inventory.warnings.extend(extracted.warnings)
    update("Inferring unlocked dependency graphs with deps.dev")
    report["discovery_inference"] = infer_dependencies(inventory, inference_roots, artifacts,
                                                      repository.commit, transport=deps_transport)
    inventory.warnings.extend(report["discovery_inference"]["warnings"])
    if not inventory.projects or len(inventory.projects) > 1:
        root = Component(id=repository_id, name=repository.url.rstrip("/").split("/")[-1].removesuffix(".git"),
            path=".", project=".", kind="repository", ecosystem="unknown", resolution_status="unknown",
            version_source="unknown", evidence=[])
        inventory.components.insert(0, root)
        if not inventory.roots:
            inventory.roots = [root.id]
        for project in inventory.projects:
            node = next(component for component in inventory.components if component.id == project.root_id)
            if node.evidence:
                inventory.edges.append(Edge(parent=root.id, child=node.id, dependency=project.name,
                    dependency_type="containment", status="resolved", evidence=node.evidence[0], version_satisfaction="not_applicable"))
    update("Building dependency graph")
    graph = build_graph(inventory)
    write_json(artifacts / "components.json", inventory.model_dump())
    write_json(artifacts / "dependency_graph.json", graph)
    report["statistics"] = graph["statistics"]
    report["coverage_statistics"] = graph["coverage_statistics"]
    report["project_statistics"] = graph["project_statistics"]
    report["projects"] = [project.model_dump() for project in inventory.projects]
    report["warnings"].extend(inventory.warnings)
    if graph["unresolved"]:
        report["warnings"].append(f"{len(graph['unresolved'])} dependency declarations could not be resolved; see graph.unresolved")
    if graph["statistics"]["unreachable_components"]:
        report["warnings"].append("Some component observations are unreachable from application roots")
    if any(check["status"] != "completed" or check.get("adapter_only") or check.get("native_only")
           for check in report["native_checks"]):
        report["warnings"].append("npm cross-check was incomplete or differed; inspect native_checks and raw evidence")
    for directory, dirs, files in os.walk(repo, followlinks=False):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules"}]
        if any((Path(directory) / name).is_symlink() for name in dirs + files):
            report["warnings"].append("Symlink source entries were excluded from discovery and the Syft snapshot")
            break
    if (repo / ".gitmodules").exists():
        report["warnings"].append("Submodules are not fetched or analyzed")
    update("Generating and validating Syft SBOM")
    report["sbom"] = generate_sbom(repo, artifacts, repository.commit, inventory)
    if report["sbom"]["status"] != "completed":
        report["errors"].append("Syft failed: " + report["sbom"]["error"])
    elif report["sbom"]["reconciliation"]["unmatched_instances"]:
        report["warnings"].append("Some adapter instances did not match Syft identities; inspect SBOM reconciliation")
    if report["sbom"]["skipped_files"]:
        report["warnings"].append("Files over the per-file size limit were omitted from Syft")
    report["limitations"] = [
        "Verified topology covers npm lockfile v2/v3. Python requirements and standard pyproject metadata are declaration-only.",
        "deps.dev graphs use inferred_version, not version/resolved_version; no joint repository resolution or installation is proven.",
        "Yarn, pnpm, Poetry, uv, and other unsupported lock formats remain detect-only; legacy Python build code is never executed.",
        "Resolved edges prove lockfile placement, not semver satisfaction or installed/runtime availability.",
        "No package installation, source scripts, submodules, vulnerability scanning, or LLM calls.",
        "Process limits and sanitized snapshots are not an OS security sandbox. Use a disposable container/VM for hostile inputs.",
        "One shortest dependency path is exported per instance; predecessors preserve deeper paths and graph retains cycles.",
    ]
    statuses = {project.completeness_status for project in inventory.projects}
    dependency_statuses = {project.dependency_status for project in inventory.projects}
    report["coverage_status"] = ("insufficient_evidence" if not statuses else "failed" if report["errors"] else
        "verified" if statuses <= {"verified", "verified_empty"} and not report["warnings"] else
        "unsupported" if statuses == {"unsupported"} else "partial")
    report["dependency_status"] = ("unknown" if report["errors"] or not statuses else
        "verified_empty" if dependency_statuses == {"verified_empty"} else
        "declared_empty" if dependency_statuses <= {"declared_empty", "verified_empty"} else
        "declared_only" if dependency_statuses == {"declared_only"} else
        "unknown" if dependency_statuses == {"unknown"} else "has_dependencies")
    report["status"] = "incomplete" if report["errors"] or report["warnings"] or not inventory.roots else "completed"
    report["finished_at"] = now()
    write_json(artifacts / "discovery_report.json", report)
    return report


def scan_repository(repo_url: str, scan_directory: Path, update=lambda stage: None, *, deps_transport=None) -> dict:
    token = SCAN_DEADLINE.set(time.monotonic() + 300)
    try:
        update("Cloning public repository")
        repository = ingest_repository(repo_url, scan_directory / "workspaces")
        return analyze_repository(repository, scan_directory / "artifacts", update, deps_transport=deps_transport)
    finally:
        SCAN_DEADLINE.reset(token)
