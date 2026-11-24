import hashlib
import json
import os
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from guardian.app import create_app
from guardian.evidence import EvidenceStore
from guardian.files import write_json
from guardian.graph import build_graph
from guardian.models import Finding, Inventory
from guardian.npm import extract_manifest, reconcile_npm_projects
from guardian.osv import OSVClient
from guardian.phase2 import run_detection
from guardian.vulnerabilities import detect_vulnerabilities
from test_vulnerabilities import advisory, inventory_fixture


def scan_fixture(tmp_path):
    scan = tmp_path / ("a" * 32)
    repo = scan / "workspaces/repo-fixture/source"
    repo.mkdir(parents=True)
    inventory = inventory_fixture(repo)
    graph = build_graph(inventory)
    artifacts = scan / "artifacts"
    artifacts.mkdir()
    write_json(artifacts / "components.json", inventory.model_dump())
    write_json(artifacts / "dependency_graph.json", graph)
    write_json(artifacts / "sbom.json", {"original": "fixture artifact must remain intact"})
    write_json(artifacts / "discovery_report.json", {"repository": {"commit": "b" * 40}, "coverage_status": "verified", "dependency_status": "has_dependencies"})
    write_json(scan / "status.json", {"status": "completed"})
    return scan, repo, inventory, graph


def no_matches(request):
    queries = json.loads(request.content)["queries"]
    return httpx.Response(200, json={"results": [{} for _ in queries]})


def test_coordinator_and_api_keep_phase1_artifacts_and_evidence_integrity(tmp_path):
    scan, _, _, _ = scan_fixture(tmp_path)
    original = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (scan / "artifacts").glob("*.json")}
    def respond(request):
        if request.url.path.endswith("querybatch"):
            queries = json.loads(request.content)["queries"]
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-test-1234-5678"}]} if q["version"] == "4.17.20" else {} for q in queries]})
        return httpx.Response(200, json=advisory())
    with TestClient(create_app(tmp_path, osv_transport=httpx.MockTransport(respond))) as client:
        assert client.get(f"/api/scans/{scan.name}/detection").json()["status"] == "not_started"
        response = client.post(f"/api/scans/{scan.name}/detect", json={})
        assert response.status_code == 202
        for _ in range(100):
            state = client.get(f"/api/scans/{scan.name}/detection").json()
            if state["status"] not in {"queued", "running"}: break
            time.sleep(.03)
        assert state["status"] == "partial", state
        report = state["report"]
        assert report["verified_vulnerabilities"] == 1 and report["change_signals"] == 0
        finding = report["findings"][0]
        assert client.get(f"/api/scans/{scan.name}/findings/{finding['finding_id']}").json() == finding
        for evidence in finding["evidence_ids"]:
            assert client.get(f"/api/scans/{scan.name}/evidence/{evidence}").status_code == 200
        assert client.get(f"/api/scans/{scan.name}/evidence/evidence:nonexistent").status_code == 404
        assert client.get(f"/api/scans/{scan.name}/vulnerabilities").json()["verified_count"] == 1
        assert client.get(f"/api/scans/{scan.name}/suspicious-changes").json()["comparison_status"] == "comparison_unavailable"
        assert client.get(f"/api/scans/{scan.name}/evidence").status_code == 200
    assert all(hashlib.sha256((scan / "artifacts" / name).read_bytes()).hexdigest() == digest for name, digest in original.items())


def test_declared_only_and_empty_unknown_scopes_do_not_guess_versions(tmp_path):
    (tmp_path / "package.json").write_text('{"name":"app","dependencies":{"lodash":"4.17.20"}}')
    inventory = extract_manifest(tmp_path, "package.json", "repo")
    def forbidden(request):
        raise AssertionError("Declared-only dependencies must never query OSV")
    store = EvidenceStore(tmp_path / "evidence", "a" * 40)
    with OSVClient(tmp_path / "cache", store, transport=httpx.MockTransport(forbidden)) as client:
        report = detect_vulnerabilities(inventory, build_graph(inventory), tmp_path, store, client, "scan", "a" * 40)
        assert report["status"] == "partial" and report["findings"] == []
        assert report["queried_package_versions"] == 0 and report["skipped_components"]
        unknown = detect_vulnerabilities(Inventory(), {"nodes": [], "edges": []}, tmp_path, store, client, "scan", "a" * 40)
        assert unknown["status"] == "partial" and unknown["no_match_statement"] is None
        empty = detect_vulnerabilities(Inventory(), {"nodes": [], "edges": []}, tmp_path, store, client, "scan", "a" * 40, phase1_dependency_status="verified_empty")
        assert empty["status"] == "completed" and empty["queried_package_versions"] == 0


def test_source_tampering_and_unknown_evidence_ids_are_rejected(tmp_path):
    scan, repo, inventory, graph = scan_fixture(tmp_path)
    (repo / "package-lock.json").write_text('{"packages":{}}')
    store = EvidenceStore(scan / "artifacts/evidence", "a" * 40)
    with OSVClient(tmp_path / "cache", store, transport=httpx.MockTransport(no_matches)) as client:
        report = detect_vulnerabilities(inventory, graph, repo, store, client, scan.name, "a" * 40)
    assert report["queried_package_versions"] == 0 and report["status"] == "partial"
    finding = Finding(finding_id="test", scan_id="scan", finding_type="vulnerability", title="fixture", explanation="fixture",
        repository_commit="a" * 40, verification_status="undetermined", evidence_ids=["evidence:missing"], created_at="now")
    with pytest.raises(ValueError, match="nonexistent evidence"):
        store.validate([finding])


@pytest.mark.integration
@pytest.mark.skipif(os.getenv("GUARDIAN_OSV_INTEGRATION") != "1", reason="Opt-in real OSV request")
def test_real_osv_known_lodash_advisory(tmp_path):
    inventory = inventory_fixture(tmp_path)
    store = EvidenceStore(tmp_path / "evidence", "a" * 40)
    with OSVClient(tmp_path / "cache", store) as client:
        report = detect_vulnerabilities(inventory, build_graph(inventory), tmp_path, store, client, "osv-integration", "a" * 40)
    assert report["status"] == "completed", report
    assert any("GHSA-35jh-r3h4-6jhm" in finding["advisory_ids"] and finding["verification_status"] == "verified_match" for finding in report["findings"])
