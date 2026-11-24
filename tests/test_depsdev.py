import hashlib
import json

import httpx
import pytest
from semantic_version import NpmSpec

from guardian.depsdev import DepsDevClient, DepsDevError, infer_dependencies, select_version
from guardian.evidence import EvidenceStore
from guardian.graph import build_graph
from guardian.models import Component, Inventory, Repository
from guardian.npm import extract_manifest
from guardian.osv import OSVClient
from guardian.pipeline import analyze_repository
from guardian.python import extract_python
from guardian.vulnerabilities import detect_vulnerabilities


def version_key(name, version, system="NPM"):
    return {"system": system, "name": name, "version": version}


def versions(name="alpha", system="NPM", values=("1.0.0", "1.2.0", "2.0.0")):
    return {"packageKey": {"system": system, "name": name},
            "versions": [{"versionKey": version_key(name, value, system)} for value in values]}


def provider_graph(name="alpha", version="1.2.0", system="NPM"):
    return {"nodes": [{"versionKey": version_key(name, version, system), "relation": "SELF"},
                      {"versionKey": version_key("leaf", "2.0.0", system), "relation": "DIRECT"}],
            "edges": [{"fromNode": 0, "toNode": 1, "requirement": "^2.0.0"},
                      {"fromNode": 1, "toNode": 0, "requirement": "^1.0.0"}]}


def manifest_inventory(repo):
    (repo / "package.json").write_text(json.dumps({"name": "app", "dependencies": {"alpha": "^1.0.0"}}))
    return extract_manifest(repo, "package.json", "repo")


def responder(request):
    assert request.url.host == "api.deps.dev"
    assert request.method == "GET"
    assert "advisories" not in request.url.path
    if request.url.path.endswith(":dependencies"):
        return httpx.Response(200, json=provider_graph())
    return httpx.Response(200, json=versions())


def test_inferred_cycle_paths_and_evidence_stay_separate_from_lockfile_truth(tmp_path):
    inventory = manifest_inventory(tmp_path)
    artifacts = tmp_path / "artifacts"
    report = infer_dependencies(inventory, set(inventory.roots), artifacts, "a" * 40,
                                transport=httpx.MockTransport(responder))
    assert report["requests"] == 2 and report["status"] == "partial"
    direct = next(c for c in inventory.components if c.name == "alpha")
    leaf = next(c for c in inventory.components if c.name == "leaf")
    assert direct.requested_constraint == "^1.0.0" and direct.inferred_version == "1.2.0"
    assert direct.version is None and direct.resolved_version is None
    assert direct.trust_tier == leaf.trust_tier == "externally_inferred"
    assert leaf.resolution_status == "inferred" and leaf.inferred_version == "2.0.0"
    graph = build_graph(inventory, inventory.projects[0].id)
    assert not graph["edges"] and len(graph["inferred"]) == 2
    assert len(graph["declared"]) == 1
    assert graph["paths"][leaf.id] == [inventory.roots[0], direct.id, leaf.id]
    assert graph["project_statistics"][inventory.projects[0].id]["reachable_instances"] == 0
    assert graph["project_statistics"][inventory.projects[0].id]["observed_instances"] == 2
    restored = Inventory.model_validate_json(inventory.model_dump_json())
    assert next(c for c in restored.components if c.id == leaf.id).version is None
    records = json.loads((artifacts / "discovery/evidence/index.json").read_text())
    assert len(records) == 2
    for component in (direct, leaf):
        for proof in component.inference_evidence:
            assert hashlib.sha256((artifacts / proof.file).read_bytes()).hexdigest() == proof.sha256
    assert all(record["retrieved_at"] and record["repository_commit"] == "a" * 40 for record in records.values())
    store = EvidenceStore(tmp_path / "evidence", "a" * 40)
    def forbidden(request):
        raise AssertionError("Inferred or declared versions must not be presented as installed OSV matches")
    with OSVClient(tmp_path / "cache", store, transport=httpx.MockTransport(forbidden)) as client:
        result = detect_vulnerabilities(inventory, graph, tmp_path, store, client, "scan", "a" * 40)
    assert result["queried_package_versions"] == 0 and len(result["skipped_components"]) == 2


@pytest.mark.parametrize("response", [
    httpx.Response(404, json={"message": "not found"}),
    httpx.Response(200, content=b"{"),
    httpx.Response(200, json=[]),
    httpx.Response(302, headers={"location": "http://127.0.0.1/private"}),
    httpx.Response(200, json={"packageKey": {"system": "NPM", "name": "wrong"}, "versions": []}),
])
def test_outages_bad_json_and_redirects_preserve_declarations(tmp_path, response):
    inventory = manifest_inventory(tmp_path)
    requests = []
    def respond(request):
        requests.append(request)
        return response
    report = infer_dependencies(inventory, set(inventory.roots), tmp_path / "artifacts", "commit",
                                transport=httpx.MockTransport(respond))
    assert len(requests) == 1
    assert report["outcomes"][0]["status"] == "unavailable"
    assert len(inventory.components) == 2 and len(inventory.edges) == 1
    assert inventory.components[1].trust_tier == "constraint_only"


@pytest.mark.parametrize("damage", ["root", "edge", "node-error", "graph-error", "bundled", "node-version"])
def test_provider_graph_is_validated_before_any_topology_is_added(tmp_path, damage):
    inventory = manifest_inventory(tmp_path)
    graph = provider_graph()
    if damage == "root": graph["nodes"][0]["versionKey"]["name"] = "wrong"
    if damage == "edge": graph["edges"][0]["toNode"] = 50
    if damage == "node-error": graph["nodes"][1]["errors"] = ["unresolved"]
    if damage == "graph-error": graph["error"] = "incomplete resolution"
    if damage == "bundled": graph["nodes"][1]["bundled"] = True
    if damage == "node-version": graph["nodes"][1]["versionKey"]["version"] = None
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=graph if request.url.path.endswith(":dependencies") else versions()))
    report = infer_dependencies(inventory, set(inventory.roots), tmp_path / "artifacts", "commit", transport=transport)
    assert report["outcomes"][0]["status"] == "unavailable"
    assert len(inventory.components) == 2 and len(inventory.edges) == 1
    assert inventory.components[1].inferred_version is None


def test_limits_cooldown_and_local_response_reuse(tmp_path):
    store = EvidenceStore(tmp_path / "evidence", "commit")
    with DepsDevClient(store, transport=httpx.MockTransport(responder), max_requests=1) as client:
        first = client.get("NPM", "alpha")
        assert client.get("NPM", "alpha") == first and client.reused_responses == 1
        with pytest.raises(DepsDevError, match="budget"):
            client.get("NPM", "alpha", "1.2.0")
    with DepsDevClient(store, transport=httpx.MockTransport(responder), budget=0) as client:
        with pytest.raises(DepsDevError, match="budget"):
            client.get("NPM", "alpha")
        assert client.requests == 0
    calls = []
    def limited(request):
        calls.append(request)
        return httpx.Response(429, headers={"retry-after": "3600"}, json={"error": "quota"})
    with DepsDevClient(store, transport=httpx.MockTransport(limited)) as client:
        with pytest.raises(DepsDevError, match="429"):
            client.get("NPM", "alpha")
        with pytest.raises(DepsDevError, match="unavailable"):
            client.get("NPM", "beta")
    assert len(calls) == 1


def test_transport_failure_oversized_response_and_unsafe_names_are_bounded(tmp_path):
    store = EvidenceStore(tmp_path / "evidence", "commit")
    def fail(request):
        raise httpx.ConnectError("offline")
    with DepsDevClient(store, transport=httpx.MockTransport(fail)) as client:
        with pytest.raises(DepsDevError, match="transport"):
            client.get("NPM", "alpha")
        assert len(store.records) == 1
        for name in ["../private", "https://evil.invalid", "@scope/../../private"]:
            with pytest.raises(DepsDevError, match="identity"):
                client.get("NPM", name)
    with DepsDevClient(store, transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b"a" * (4 * 1024 * 1024 + 1)))) as client:
        with pytest.raises(DepsDevError, match="size/time"):
            client.get("NPM", "alpha")


def test_scoped_names_are_encoded_and_no_url_or_git_requirements_are_fetched(tmp_path):
    requests = []
    def scoped(request):
        requests.append(request)
        return httpx.Response(404)
    with DepsDevClient(EvidenceStore(tmp_path / "evidence", "commit"), transport=httpx.MockTransport(scoped)) as client:
        with pytest.raises(DepsDevError):
            client.get("NPM", "@scope/name")
    assert b"%40scope%2Fname" in requests[0].url.raw_path
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"remote": "git+https://secret@github.com/a/b"}}))
    inventory = extract_manifest(tmp_path, "package.json", "repo")
    def forbidden(request):
        raise AssertionError("Remote references must not be fetched")
    report = infer_dependencies(inventory, set(inventory.roots), tmp_path / "artifacts", "commit", transport=httpx.MockTransport(forbidden))
    assert report["requests"] == 0 and "secret" not in json.dumps(report)


def test_python_pep440_version_selection_and_conditional_requirements(tmp_path):
    (tmp_path / "requirements.txt").write_text('Requests>=1,<2\nhttpx[http2]>=1\nconditional==1.0; sys_platform=="win32"\n')
    inventory = extract_python(tmp_path, ["requirements.txt"], "repo")
    def respond(request):
        return httpx.Response(200, json=provider_graph("requests", "1.9.0", "PYPI") if request.url.path.endswith(":dependencies")
                              else versions("requests", "PYPI", ("1.0", "1.9.0", "1.10.0rc1", "2.0")))
    report = infer_dependencies(inventory, set(inventory.roots), tmp_path / "artifacts", "commit", transport=httpx.MockTransport(respond))
    assert report["requests"] == 2
    assert [outcome["status"] for outcome in report["outcomes"]] == ["inferred", "unavailable", "unavailable"]
    package = next(c for c in inventory.components if c.name == "requests")
    assert package.inferred_version == "1.9.0" and package.version is None
    assert all(c.version is None for c in inventory.components if c.kind == "package")


def test_exact_manifest_versions_are_declarations_and_model_rejects_promoted_inference(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"alpha":"1.2.0"}}')
    inventory = extract_manifest(tmp_path, "package.json", "repo")
    assert inventory.components[1].trust_tier == "declared_exact" and inventory.components[1].resolved_version is None
    infer_dependencies(inventory, set(inventory.roots), tmp_path / "artifacts", "commit", transport=httpx.MockTransport(responder))
    assert inventory.components[1].trust_tier == "declared_exact"
    assert inventory.components[1].inferred_version == "1.2.0"
    with pytest.raises(ValueError, match="Inferred versions"):
        Component(id="bad", name="bad", path=".", project=".", evidence=[],
                  version="1.2.0", inferred_version="1.2.0", resolution_status="inferred")


@pytest.mark.parametrize("constraint,values,selected", [
    ("^0.2.0", ("0.2.1", "0.2.9", "0.3.0"), "0.2.9"),
    ("~1.2.0", ("1.2.9", "1.3.0", "1.10.0"), "1.2.9"),
    ("^1.0.0", ("1.9.0", "1.10.0", "1.11.0-beta.1", "2.0.0"), "1.10.0"),
    ("1.2.0 || >=3 <4", ("1.2.0", "3.5.0", "4.0.0"), "3.5.0"),
])
def test_npm_constraint_selection_uses_semver_not_text_order(constraint, values, selected):
    assert select_version(versions(values=values), "NPM", "alpha", NpmSpec(constraint)) == selected


def test_discovery_pipeline_uses_inference_and_keeps_original_syft_sbom(tmp_path):
    manifest_inventory(tmp_path)
    artifacts = tmp_path.parent / (tmp_path.name + "-artifacts")
    report = analyze_repository(Repository(url="https://github.com/test/fixture", path=str(tmp_path), commit="a" * 40),
                                artifacts, deps_transport=httpx.MockTransport(responder))
    assert report["status"] == "incomplete" and report["coverage_status"] == "partial"
    assert report["discovery_inference"]["requests"] == 2
    assert report["statistics"]["component_count"] == 2
    assert report["sbom"]["status"] == "completed", report["sbom"]
    graph = json.loads((artifacts / "dependency_graph.json").read_text())
    assert len(graph["inferred"]) == 2 and not graph["edges"]
    assert len(report["sbom"]["reconciliation"]["inferred_instances"]) == 2
    assert report["sbom"]["reconciliation"]["instance_to_sbom_refs"] == {}
    assert hashlib.sha256((artifacts / "sbom.json").read_bytes()).hexdigest() == report["sbom"]["sha256"]


def test_api_exports_inferred_graph_and_separate_raw_discovery_evidence(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from guardian.app import create_app
    from test_api import wait
    repo = tmp_path / "repo"
    repo.mkdir()
    manifest_inventory(repo)
    monkeypatch.setattr("guardian.pipeline.ingest_repository", lambda url, workspace:
                        Repository(url=url, commit="a" * 40, path=str(repo)))
    with TestClient(create_app(tmp_path / "scans", deps_transport=httpx.MockTransport(responder))) as client:
        scan_id = client.post("/api/scans", json={"repo_url": "https://github.com/test/fixture"}).json()["scan_id"]
        assert wait(client, scan_id)["status"] == "incomplete"
        graph = client.get(f"/api/scans/{scan_id}/graph").json()
        assert len(graph["inferred"]) == 2 and not graph["edges"]
        assert all(node["resolved_version"] is None for node in graph["nodes"] if node["kind"] == "package")
        index = client.get(f"/api/scans/{scan_id}/discovery-evidence").json()
        assert len(index) == 2
        evidence_id = next(iter(index))
        raw = client.get(f"/api/scans/{scan_id}/discovery-evidence/{evidence_id}")
        assert raw.status_code == 200 and raw.json()["metadata"]["sha256"] == index[evidence_id]["sha256"]
        assert client.get(f"/api/scans/{scan_id}/discovery-evidence/evidence:missing").status_code == 404
        assert client.get(f"/api/scans/{scan_id}/evidence").status_code == 409


def test_orchestrated_discovery_keeps_inference_evidence_through_detection(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from guardian.app import create_app
    from test_orchestrator import pipeline_wait
    def ingest(url, workspace):
        repo = workspace / "repo-fixture/source"
        repo.mkdir(parents=True)
        manifest_inventory(repo)
        return Repository(url=url, path=str(repo), commit="a" * 40)
    def forbidden(request):
        raise AssertionError("Inferred dependencies must not trigger exact installed-version OSV checks")
    monkeypatch.setattr("guardian.pipeline.ingest_repository", ingest)
    with TestClient(create_app(tmp_path / "scans", deps_transport=httpx.MockTransport(responder),
                               osv_transport=httpx.MockTransport(forbidden))) as client:
        scan_id = client.post("/api/pipelines", json={"repo_url": "https://github.com/test/fixture"}).json()["scan_id"]
        state = pipeline_wait(client, scan_id)
        assert state["status"] == "completed"
        assert state["modules"]["discover"]["status"] == "incomplete"
        assert state["modules"]["detect"]["status"] == "partial"
        index = client.get(f"/api/scans/{scan_id}/discovery-evidence").json()
        assert len(index) == 2
        assert client.get(f"/api/scans/{scan_id}/vulnerabilities").json()["queried_package_versions"] == 0
        assert client.app.state.orchestrator.valid_checkpoint(scan_id, "discover")
        evidence = next((tmp_path / "scans" / scan_id / "artifacts/discovery/evidence").glob("evidence-*.json"))
        evidence.write_text("tampered")
        assert not client.app.state.orchestrator.valid_checkpoint(scan_id, "discover")
