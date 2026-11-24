import json

import httpx
import pytest

from guardian.detection import detect_ecosystems
from guardian.graph import build_graph
from guardian.models import Repository
from guardian.npm import extract_manifest, reconcile_npm_projects
from guardian.pipeline import analyze_repository
from guardian.process import ToolError


def put(root, path, data):
    file = root / path
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(json.dumps(data))


def names(graph):
    nodes = {node["id"]: node for node in graph["nodes"]}
    return {(nodes[e["parent"]]["name"], nodes[e["child"]]["name"]) for e in graph["edges"]}


@pytest.mark.parametrize("constraint", ["^4.18.0", "4.18.0"])
def test_manifest_only_never_claims_resolved_version(tmp_path, constraint):
    put(tmp_path, "package.json", {"name": "app", "dependencies": {"express": constraint}})
    inventory = extract_manifest(tmp_path, "package.json", "repo:test")
    graph = build_graph(inventory)
    package = next(n for n in graph["nodes"] if n["name"] == "express")
    assert package["requested_constraint"] == constraint
    assert package["version"] is None and package["resolved_version"] is None
    assert package["resolution_status"] == "declared_only"
    assert graph["edges"] == [] and graph["statistics"]["edge_count"] == 0
    assert len(graph["declared"]) == 1
    assert package["project_ids"] == [inventory.projects[0].id]
    assert graph["declared"][0]["relationship_type"] == "declares_dependency"
    assert inventory.projects[0].completeness_status == "partial"


def test_empty_manifest_without_lock_is_declared_empty(tmp_path):
    put(tmp_path, "package.json", {"name": "empty"})
    inventory = extract_manifest(tmp_path, "package.json", "repo:test")
    assert inventory.projects[0].dependency_status == "declared_empty"
    graph = build_graph(inventory)
    assert len(graph["nodes"]) == 1 and graph["edges"] == [] and graph["declared"] == []


def test_empty_manifest_and_compatible_empty_lock_are_verified_empty(tmp_path):
    put(tmp_path, "package.json", {"name": "empty"})
    put(tmp_path, "package-lock.json", {"lockfileVersion": 3, "packages": {"": {"name": "empty"}}})
    inventory = reconcile_npm_projects(tmp_path, "package-lock.json", ["package.json"], "repo:test")
    assert inventory.projects[0].dependency_status == "verified_empty"
    assert inventory.projects[0].completeness_status == "verified_empty"
    assert len(inventory.components) == 1 and inventory.edges == []


def test_empty_lock_preserves_manifest_declarations_and_is_not_verified_empty(tmp_path):
    put(tmp_path, "package.json", {"name": "app", "dependencies": {"missing": "^2"}})
    put(tmp_path, "package-lock.json", {"lockfileVersion": 3, "packages": {"": {"name": "app"}}})
    inventory = reconcile_npm_projects(tmp_path, "package-lock.json", ["package.json"], "repo:test")
    assert inventory.projects[0].completeness_status == "partial"
    assert any("inconsisten" in warning.lower() for warning in inventory.warnings)
    assert inventory.edges[0].status == "declared_only"
    assert inventory.components[-1].version is None


def workspace_fixture(root):
    put(root, "package.json", {"name": "monorepo", "workspaces": ["apps/*", "packages/*"]})
    put(root, "apps/web/package.json", {"name": "web", "dependencies": {"shared": "*", "web-only": "1"}})
    put(root, "apps/api/package.json", {"name": "api", "dependencies": {"shared": "*", "api-only": "2"}})
    put(root, "packages/shared/package.json", {"name": "shared", "version": "1.0.0", "dependencies": {"leaf": "3"}})
    records = {
        "": {"name": "monorepo", "workspaces": ["apps/*", "packages/*"]},
        "apps/web": {"name": "web", "dependencies": {"shared": "*", "web-only": "1"}},
        "apps/api": {"name": "api", "dependencies": {"shared": "*", "api-only": "2"}},
        "packages/shared": {"name": "shared", "version": "1.0.0", "dependencies": {"leaf": "3"}},
        "node_modules/shared": {"link": True, "resolved": "packages/shared"},
        "node_modules/web": {"link": True, "resolved": "apps/web"},
        "node_modules/api": {"link": True, "resolved": "apps/api"},
        "node_modules/web-only": {"version": "1.0.0"},
        "node_modules/api-only": {"version": "2.0.0"},
        "node_modules/leaf": {"version": "3.0.0"},
    }
    put(root, "package-lock.json", {"lockfileVersion": 3, "packages": records})
    return ["package.json", "apps/web/package.json", "apps/api/package.json", "packages/shared/package.json"]


def test_shared_lockfile_has_distinct_apps_and_only_evidence_backed_reachability(tmp_path):
    manifests = workspace_fixture(tmp_path)
    inventory = reconcile_npm_projects(tmp_path, "package-lock.json", manifests, "repo:test")
    assert len(inventory.projects) == 4
    assert len([c for c in inventory.components if c.name == "shared"]) == 1
    whole = build_graph(inventory)
    assert names(whole) == {("web", "shared"), ("web", "web-only"), ("api", "shared"),
                            ("api", "api-only"), ("shared", "leaf")}
    web = next(project for project in inventory.projects if project.name == "web")
    graph = build_graph(inventory, project_id=web.id)
    assert {node["name"] for node in graph["nodes"]} == {"web", "shared", "web-only", "leaf"}
    assert names(graph) == {("web", "shared"), ("web", "web-only"), ("shared", "leaf")}
    assert "api-only" not in {node["name"] for node in graph["nodes"]}
    assert next(node for node in whole["nodes"] if node["name"] == "leaf")["shared_by_projects"] >= 2


def test_orphan_records_are_preserved_as_observations(tmp_path):
    put(tmp_path, "package.json", {"name": "empty"})
    put(tmp_path, "package-lock.json", {"lockfileVersion": 3, "packages": {
        "": {"name": "empty"}, "node_modules/orphan": {"version": "1.0.0"}}})
    inventory = reconcile_npm_projects(tmp_path, "package-lock.json", ["package.json"], "repo:test")
    assert inventory.projects[0].completeness_status == "partial"
    graph = build_graph(inventory)
    assert next(n for n in graph["nodes"] if n["name"] == "orphan")["classification"] == "unreachable"
    assert graph["edges"] == []


def test_manifest_only_supports_all_declaration_groups_and_peer_metadata(tmp_path):
    put(tmp_path, "package.json", {"name": "app", "dependencies": {"prod": "^1"},
        "devDependencies": {"dev": "~2"}, "optionalDependencies": {"optional": "3"},
        "peerDependencies": {"peer": ">=4"}, "peerDependenciesMeta": {"peer": {"optional": True}}})
    inventory = extract_manifest(tmp_path, "package.json", "repo:test")
    assert {(edge.dependency, edge.dependency_type, edge.constraint) for edge in inventory.edges} == {
        ("prod", "production", "^1"), ("dev", "development", "~2"),
        ("optional", "optional", "3"), ("peer", "peer", ">=4")}
    assert next(edge for edge in inventory.edges if edge.dependency == "peer").optional
    assert len(inventory.components) == 5


def analyze(tmp_path):
    return analyze_repository(Repository(url="https://github.com/example/fixture", commit="a" * 40,
        path=str(tmp_path)), tmp_path.parent / (tmp_path.name + "-artifacts"),
        deps_transport=httpx.MockTransport(lambda request: httpx.Response(404, json={"error": "fixture unavailable"})))


@pytest.mark.parametrize("mode,status,coverage", [
    ("empty", "unknown", "insufficient_evidence"),
    ("manifest-empty", "declared_empty", "partial"),
    ("verified-empty", "verified_empty", "verified"),
    ("manifest-only", "declared_only", "partial"),
    ("unsupported", "unknown", "unsupported"),
])
def test_full_pipeline_empty_missing_and_unsupported_metadata(tmp_path, mode, status, coverage):
    if mode in {"manifest-empty", "verified-empty"}:
        put(tmp_path, "package.json", {"name": "empty"})
    if mode == "verified-empty":
        put(tmp_path, "package-lock.json", {"lockfileVersion": 3, "packages": {"": {"name": "empty"}}})
    if mode == "manifest-only":
        put(tmp_path, "package.json", {"name": "app", "dependencies": {"express": "4.18.0"}})
    if mode == "unsupported":
        (tmp_path / "pyproject.toml").write_text('[project]\nname="python-app"\ndependencies=["fastapi>=1"]\n')
        (tmp_path / "poetry.lock").write_text("")
    report = analyze(tmp_path)
    assert report["dependency_status"] == status, report
    assert report["coverage_status"] == coverage, report
    assert report["sbom"]["status"] == "completed", report["sbom"]
    graph = json.loads((tmp_path.parent / (tmp_path.name + "-artifacts/dependency_graph.json")).read_text())
    assert graph["edges"] == []
    assert len(graph["nodes"]) == (2 if mode == "manifest-only" else 1)
    if mode == "manifest-only":
        assert graph["declared"][0]["constraint"] == "4.18.0"
        assert graph["nodes"][-1]["version"] is None
        assert report["sbom"]["reconciliation"]["declared_only_instances"]


def test_independent_nested_locks_never_share_instances(tmp_path):
    for app, version in [("web", "1.0.0"), ("api", "2.0.0")]:
        put(tmp_path, f"apps/{app}/package.json", {"name": app, "dependencies": {"shared-name": version}})
        put(tmp_path, f"apps/{app}/package-lock.json", {"lockfileVersion": 3, "packages": {
            "": {"name": app, "dependencies": {"shared-name": version}},
            "node_modules/shared-name": {"version": version}}})
    report = analyze(tmp_path)
    assert len(report["projects"]) == 2
    assert report["statistics"]["component_count"] == 2
    artifacts = tmp_path.parent / (tmp_path.name + "-artifacts")
    from guardian.models import Inventory
    inventory = Inventory.model_validate_json((artifacts / "components.json").read_bytes())
    for project in inventory.projects:
        graph = build_graph(inventory, project.id)
        expected = "1.0.0" if project.name == "web" else "2.0.0"
        assert [(n["name"], n["version"]) for n in graph["nodes"] if n["name"] == "shared-name"] == [("shared-name", expected)]
        assert names(graph) == {(project.name, "shared-name")}


@pytest.mark.parametrize("file,payload", [("package.json", "{"), ("package-lock.json", "{"),
    ("package-lock.json", '{"lockfileVersion":3,"packages":{"":{},"node_modules/bad":false}}')])
def test_malformed_metadata_never_becomes_empty_success(tmp_path, file, payload):
    put(tmp_path, "package.json", {"name": "app", "dependencies": {"a": "^1"}})
    (tmp_path / file).write_text(payload)
    report = analyze(tmp_path)
    assert report["status"] == "incomplete"
    assert report["coverage_status"] == "failed"
    assert report["dependency_status"] != "verified_empty"
    assert report["projects"][0]["completeness_status"] == "failed"
    assert report["errors"]


def test_project_filter_api_matches_verified_shared_dependency_set(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from guardian.app import create_app
    from test_api import wait
    repo = tmp_path / "repo"
    repo.mkdir()
    workspace_fixture(repo)
    monkeypatch.setattr("guardian.pipeline.ingest_repository", lambda url, workspace:
        Repository(url=url, commit="a" * 40, path=str(repo)))
    with TestClient(create_app(tmp_path / "scans")) as client:
        scan = client.post("/api/scans", json={"repo_url": "https://github.com/test/fixture"}).json()["scan_id"]
        assert wait(client, scan)["status"] in {"completed", "incomplete"}
        report = client.get(f"/api/scans/{scan}/report").json()
        web = next(project for project in report["projects"] if project["name"] == "web")
        graph = client.get(f"/api/scans/{scan}/graph", params={"project_id": web["id"]}).json()
        assert {n["name"] for n in graph["nodes"]} == {"web", "shared", "web-only", "leaf"}
        assert names(graph) == {("web", "shared"), ("web", "web-only"), ("shared", "leaf")}
        assert client.get(f"/api/scans/{scan}/graph?project_id=unknown").status_code == 404
        assert len(client.get(f"/api/scans/{scan}/graph").json()["containment"]) == 4


def test_workspace_ids_are_stable_and_manifest_config_can_supply_membership(tmp_path):
    manifests = workspace_fixture(tmp_path)
    lock = json.loads((tmp_path / "package-lock.json").read_text())
    del lock["packages"][""]["workspaces"]
    put(tmp_path, "package-lock.json", lock)
    detected = detect_ecosystems(tmp_path)
    assert len([item for item in detected if item.covered_by]) == 3
    first = reconcile_npm_projects(tmp_path, "package-lock.json", manifests, "repo:test")
    second = reconcile_npm_projects(tmp_path, "package-lock.json", manifests, "repo:test")
    assert [p.id for p in first.projects] == [p.id for p in second.projects]
    assert names(build_graph(first)) == names(build_graph(second))


def test_every_exported_dependency_edge_resolves_to_literal_source_evidence(tmp_path):
    import hashlib
    manifests = workspace_fixture(tmp_path)
    inventory = reconcile_npm_projects(tmp_path, "package-lock.json", manifests, "repo:test")
    graph = build_graph(inventory)
    for edge in graph["edges"] + graph["declared"]:
        evidence = edge["evidence"]
        raw = (tmp_path / evidence["file"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == evidence["sha256"]
        value = json.loads(raw)
        for part in evidence["pointer"].split("/")[1:]:
            value = value[part.replace("~1", "/").replace("~0", "~")]
        assert value == edge["constraint"]
        assert edge["evidence_ids"] == [evidence["id"]]


def test_missing_transitive_version_marks_affected_project_partial(tmp_path):
    put(tmp_path, "package.json", {"name": "app", "dependencies": {"a": "1"}})
    put(tmp_path, "package-lock.json", {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"a": "1"}}, "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "*"}},
        "node_modules/b": {}}})
    inventory = reconcile_npm_projects(tmp_path, "package-lock.json", ["package.json"], "repo:test")
    assert inventory.projects[0].completeness_status == "partial"
    b = next(component for component in inventory.components if component.name == "b")
    assert b.version is None and b.resolution_status == "unknown"


def test_workspace_native_crosscheck_uses_safe_shared_manifest_context(tmp_path):
    workspace_fixture(tmp_path)
    report = analyze(tmp_path)
    check = report["native_checks"][0]
    assert check["status"] == "completed", check
    assert check["adapter_only"] == [] and check["native_only"] == [], check
    assert report["coverage_status"] == "verified", report["warnings"]


def test_instance_ids_are_scoped_to_repository_but_identities_are_not(tmp_path):
    manifests = workspace_fixture(tmp_path)
    first = reconcile_npm_projects(tmp_path, "package-lock.json", manifests, "repo:first")
    second = reconcile_npm_projects(tmp_path, "package-lock.json", manifests, "repo:second")
    a = next(component for component in first.components if component.name == "leaf")
    b = next(component for component in second.components if component.name == "leaf")
    assert a.id != b.id
    assert a.identity == b.identity == "pkg:npm/leaf@3.0.0"
