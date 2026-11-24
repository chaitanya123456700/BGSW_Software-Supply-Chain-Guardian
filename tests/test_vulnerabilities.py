import copy
import json

import httpx
import pytest

from guardian.evidence import EvidenceStore
from guardian.graph import build_graph
from guardian.npm import reconcile_npm_projects
from guardian.osv import OSVClient
from guardian.vulnerabilities import detect_vulnerabilities, same_modified_time, verify_advisory


def inventory_fixture(root):
    manifest = {"name": "app", "dependencies": {"lodash": "4.17.20", "parent": "1.0.0"}}
    lock = {"lockfileVersion": 3, "packages": {"": manifest,
        "node_modules/lodash": {"version": "4.17.20"},
        "node_modules/parent": {"version": "1.0.0", "dependencies": {"lodash": "4.17.21"}},
        "node_modules/parent/node_modules/lodash": {"version": "4.17.21"}}}
    (root / "package.json").write_text(json.dumps(manifest))
    (root / "package-lock.json").write_text(json.dumps(lock))
    return reconcile_npm_projects(root, "package-lock.json", ["package.json"], "repository:test")


def advisory(identifier="GHSA-test-1234-5678"):
    return {"id": identifier, "aliases": ["CVE-2099-0001"], "modified": "2026-01-01T00:00:00Z",
        "summary": "Synthetic fixture advisory", "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
            "versions": ["4.17.20"], "ranges": []}], "references": [], "severity": []}


def test_exact_matches_alias_dedup_versions_and_graph_paths(tmp_path):
    inventory = inventory_fixture(tmp_path)
    vulnerable = next(c for c in inventory.components if c.name == "lodash" and c.version == "4.17.20")
    def respond(request):
        if request.url.path.endswith("querybatch"):
            queries = json.loads(request.content)["queries"]
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-test-1234-5678"}, {"id": "CVE-2099-0001"}]} if q["version"] == "4.17.20" else {} for q in queries]})
        return httpx.Response(200, json=advisory(request.url.path.split("/")[-1]))
    store = EvidenceStore(tmp_path / "evidence", "a" * 40)
    with OSVClient(tmp_path / "cache", store, transport=httpx.MockTransport(respond)) as client:
        result = detect_vulnerabilities(inventory, build_graph(inventory), tmp_path, store, client, "scan", "a" * 40)
    assert result["status"] == "completed", result
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["component_instance_ids"] == [vulnerable.id]
    assert finding["verification_status"] == "verified_match"
    assert finding["aliases"] == ["CVE-2099-0001"]
    assert finding["dependency_paths"][0]["nodes"] == [inventory.roots[0], vulnerable.id]
    assert finding["reachability_status"] == "not_analyzed" and finding["priority_status"] == "not_assessed"
    assert set(finding["evidence_ids"]) <= set(store.records)


@pytest.mark.parametrize("change,status", [("withdrawn", "not_applicable"), ("ecosystem", "conflicting_evidence"),
    ("unaffected", "conflicting_evidence"), ("github", "conflicting_evidence")])
def test_advisory_verification_rejects_false_certainty(tmp_path, change, status):
    component = next(c for c in inventory_fixture(tmp_path).components if c.name == "lodash")
    record = advisory()
    github = None
    if change == "withdrawn": record["withdrawn"] = "2026-01-02T00:00:00Z"
    if change == "ecosystem": record["affected"][0]["package"]["ecosystem"] = "PyPI"
    if change == "unaffected": record["affected"][0]["versions"] = ["4.0.0"]
    if change == "github": github = {"vulnerabilities": [{"package": {"ecosystem": "npm", "name": "another-package"}}]}
    decision = verify_advisory(component, record, github_record=github)
    assert decision["verification_status"] == status


def test_osv_timestamp_precision_is_not_mistaken_for_source_conflict():
    assert same_modified_time("2026-10-17T02:55:38.085813Z", "2026-10-17T02:55:38.085813876Z")
    assert not same_modified_time("2026-10-17T02:55:37Z", "2026-10-17T02:55:38Z")


def test_monorepo_shared_instance_paths_and_stable_finding_ids(tmp_path):
    from test_metadata_upgrade import workspace_fixture, put
    manifests = workspace_fixture(tmp_path)
    lock = json.loads((tmp_path / "package-lock.json").read_text())
    lock["packages"]["packages/shared"]["dependencies"] = {"lodash": "4.17.20"}
    lock["packages"]["node_modules/lodash"] = {"version": "4.17.20"}
    del lock["packages"]["node_modules/leaf"]
    put(tmp_path, "package-lock.json", lock)
    put(tmp_path, "packages/shared/package.json", {"name": "shared", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}})
    inventory = reconcile_npm_projects(tmp_path, "package-lock.json", manifests, "repo:test")
    graph = build_graph(inventory)
    def respond(request):
        if request.url.path.endswith("querybatch"):
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-test-1234-5678"}]} if q["package"]["name"] == "lodash" else {} for q in json.loads(request.content)["queries"]]})
        return httpx.Response(200, json=advisory())
    store = EvidenceStore(tmp_path / "evidence", "a" * 40)
    with OSVClient(tmp_path / "cache", store, transport=httpx.MockTransport(respond)) as client:
        first = detect_vulnerabilities(inventory, graph, tmp_path, store, client, "first", "a" * 40)["findings"][0]
        second = detect_vulnerabilities(inventory, graph, tmp_path, store, client, "second", "a" * 40)["findings"][0]
    assert first["finding_id"] == second["finding_id"]
    projects = {project.id: project.name for project in inventory.projects}
    assert {projects[project] for project in first["affected_application_ids"]} == {"web", "api", "shared"}
    edges = {(edge["parent"], edge["child"]) for edge in graph["edges"]}
    assert all((a, b) in edges for path in first["dependency_paths"] for a, b in zip(path["nodes"], path["nodes"][1:]))
