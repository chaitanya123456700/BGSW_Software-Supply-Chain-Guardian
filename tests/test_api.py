import json
import time

from fastapi.testclient import TestClient

from guardian.app import create_app
from guardian.models import Repository
from test_npm import extract


def wait(client, scan_id):
    for _ in range(200):
        response = client.get(f"/api/scans/{scan_id}")
        state = response.json()
        if state["status"] not in {"queued", "running"}:
            return state
        assert client.get("/health").status_code == 200
        time.sleep(0.03)
    raise AssertionError("Scan did not finish")


def test_api_scans_real_fixture_and_downloads_stored_artifacts(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text('{"name":"app","version":"1.0.0","dependencies":{"a":"1.2.3"}}')
    extract(repo, {"": {"name": "app", "version": "1.0.0", "dependencies": {"a": "1.2.3"}},
                  "node_modules/a": {"version": "1.2.3"}})
    # GitHub is the system boundary; parser, npm, graph and Syft run unchanged.
    monkeypatch.setattr("guardian.pipeline.ingest_repository", lambda url, workspace:
                        Repository(url=url, commit="a" * 40, path=str(repo)))
    with TestClient(create_app(tmp_path / "scans")) as client:
        assert client.get("/").status_code == 200
        response = client.post("/api/scans", json={"repo_url": "https://github.com/test/fixture"})
        assert response.status_code == 202
        scan_id = response.json()["scan_id"]
        state = wait(client, scan_id)
        assert state["status"] == "completed", state
        for route, name in [("graph", "dependency_graph.json"), ("components", "components.json"),
                            ("sbom", "sbom.json"), ("report", "discovery_report.json")]:
            downloaded = client.get(f"/api/scans/{scan_id}/{route}")
            assert downloaded.status_code == 200
            assert downloaded.content == (tmp_path / "scans" / scan_id / "artifacts" / name).read_bytes()
        graph = client.get(f"/api/scans/{scan_id}/graph").json()
        assert graph["statistics"]["component_count"] == 1
        assert graph["statistics"]["edge_count"] == 1
        assert graph["inferred"] == []
        assert next(node for node in graph["nodes"] if node["kind"] == "package")["trust_tier"] == "verified_lockfile"
        assert client.get(f"/api/scans/{scan_id}/report").json()["discovery_inference"]["requests"] == 0


def test_ingestion_failure_never_becomes_success(tmp_path, monkeypatch):
    def fail(url, workspace):
        raise RuntimeError("Repository inaccessible")
    monkeypatch.setattr("guardian.pipeline.ingest_repository", fail)
    with TestClient(create_app(tmp_path / "scans")) as client:
        response = client.post("/api/scans", json={"repo_url": "https://github.com/test/missing"})
        scan_id = response.json()["scan_id"]
        assert wait(client, scan_id)["status"] == "failed"
        assert client.get(f"/api/scans/{scan_id}/sbom").status_code == 409
        assert client.get(f"/api/scans/{scan_id}/report").json()["errors"] == ["Repository inaccessible"]


def test_api_rejects_bad_urls_paths_and_cross_origin_requests(tmp_path):
    with TestClient(create_app(tmp_path / "scans")) as client:
        assert client.post("/api/scans", json={"repo_url": "file:///tmp"}).status_code == 422
        assert client.get("/api/scans/not-a-scan").status_code == 404
        assert client.post("/api/scans", json={"repo_url": "https://github.com/a/b"},
                           headers={"origin": "https://evil.example"}).status_code == 403
        assert client.get("/health", headers={"host": "evil.example"}).status_code == 400
