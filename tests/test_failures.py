import threading

from fastapi.testclient import TestClient

from guardian.app import create_app
from guardian.models import Repository
from guardian.pipeline import analyze_repository
from guardian.process import ToolError
from test_npm import extract


def test_syft_failure_preserves_graph_but_marks_analysis_incomplete(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    extract(repo, {"": {"dependencies": {"a": "1.0.0"}}, "node_modules/a": {"version": "1.0.0"}})

    def missing(*args, **kwargs):
        raise ToolError("Syft executable missing")
    monkeypatch.setattr("guardian.sbom.run_tool", missing)
    result = analyze_repository(Repository(url="https://github.com/test/fixture", commit="a" * 40, path=str(repo)), tmp_path / "artifacts")
    assert result["status"] == "incomplete"
    assert result["sbom"]["status"] == "failed"
    assert result["statistics"]["edge_count"] == 1
    assert result["errors"] == ["Syft failed: Syft executable missing"]
    assert (tmp_path / "artifacts/dependency_graph.json").is_file()


def test_scan_queue_is_bounded_and_health_remains_available(tmp_path, monkeypatch):
    gate = threading.Event()
    entered = threading.Event()

    def blocking_ingestion(url, workspace):
        entered.set()
        assert gate.wait(3)
        raise ToolError("Synthetic ingestion failure")
    monkeypatch.setattr("guardian.pipeline.ingest_repository", blocking_ingestion)
    with TestClient(create_app(tmp_path / "scans")) as client:
        try:
            body = {"repo_url": "https://github.com/test/fixture"}
            assert client.post("/api/scans", json=body).status_code == 202
            assert entered.wait(1)
            assert client.post("/api/scans", json=body).status_code == 202
            assert client.post("/api/scans", json=body).status_code == 202
            assert client.post("/api/scans", json=body).status_code == 429
            assert client.get("/health").json() == {"status": "ok", "phase": 1}
        finally:
            gate.set()
