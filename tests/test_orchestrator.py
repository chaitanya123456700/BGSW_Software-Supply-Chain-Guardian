import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from fastapi.testclient import TestClient

from guardian.app import create_app
from guardian.files import write_json
from guardian.graph import build_graph
from guardian.orchestrator import JobConflict, JobStore, Orchestrator
from guardian.process import run_tool
from test_phase2 import no_matches
from test_vulnerabilities import inventory_fixture

SCAN = "a" * 32
URL = "https://github.com/test/fixture"


def discovery(url, scan, update):
    repo = scan / "workspaces/repo-fixture/source"
    repo.mkdir(parents=True, exist_ok=True)
    inventory = inventory_fixture(repo)
    report = {"status": "completed", "repository": {"commit": "b" * 40, "url": url},
              "coverage_status": "verified", "dependency_status": "has_dependencies"}
    write_json(scan / "artifacts/components.json", inventory.model_dump())
    write_json(scan / "artifacts/dependency_graph.json", build_graph(inventory))
    write_json(scan / "artifacts/discovery_report.json", report)
    return report


def setup_job(tmp_path):
    store = JobStore(tmp_path / "guardian.sqlite3")
    (tmp_path / SCAN / "artifacts").mkdir(parents=True)
    store.create(SCAN, URL)
    runner = Orchestrator(store, tmp_path, osv_transport=httpx.MockTransport(no_matches))
    return store, runner


def test_pipeline_runs_real_detection_and_reuses_checked_artifacts(tmp_path, monkeypatch):
    monkeypatch.setattr("guardian.orchestrator.scan_repository", discovery)
    store, runner = setup_job(tmp_path)
    runner.run(SCAN)
    state = store.get(SCAN)
    assert state["status"] == "completed"
    assert state["modules"]["discover"]["status"] == "completed"
    assert state["modules"]["detect"]["status"] == "partial"
    assert state["modules"]["analyze"]["status"] == "partial"
    assert state["modules"]["remediate"]["status"] in {"completed", "partial"}
    assert state["modules"]["validate"]["status"] == "not_run"
    assert state["ai_budget"]["calls"] == 0
    original = (tmp_path / SCAN / "artifacts/discovery_report.json").read_bytes()
    store.resume(SCAN)
    runner.run(SCAN)
    assert store.get(SCAN)["modules"]["discover"]["attempts"] == 1
    assert store.get(SCAN)["modules"]["detect"]["attempts"] == 1
    assert original == (tmp_path / SCAN / "artifacts/discovery_report.json").read_bytes()
    evidence = next(p for p in (tmp_path / SCAN / "artifacts/evidence").glob("*.json") if p.name != "index.json")
    evidence.write_text("tampered")
    assert not runner.valid_checkpoint(SCAN, "detect")
    store.resume(SCAN)
    runner.run(SCAN)
    assert store.get(SCAN)["modules"]["discover"]["attempts"] == 1
    assert store.get(SCAN)["modules"]["detect"]["attempts"] == 2
    # An altered discovery artifact invalidates discovery and every downstream module.
    (tmp_path / SCAN / "artifacts/components.json").write_text("{}")
    store.resume(SCAN)
    runner.run(SCAN)
    assert store.get(SCAN)["modules"]["discover"]["attempts"] == 2
    assert store.get(SCAN)["modules"]["detect"]["attempts"] == 3
    assert (tmp_path / SCAN / "workspaces-before-attempt-2/repo-fixture/source/package-lock.json").is_file()
    assert len(list((tmp_path / SCAN / "workspaces").glob("repo-*/source"))) == 1


def test_failure_requires_explicit_resume_and_counts_attempts(tmp_path, monkeypatch):
    def fail(*args):
        raise RuntimeError("GitHub unavailable")
    monkeypatch.setattr("guardian.orchestrator.scan_repository", fail)
    store, runner = setup_job(tmp_path)
    runner.run(SCAN)
    state = store.get(SCAN)
    assert state["status"] == "failed"
    assert state["modules"]["discover"]["error"] == "GitHub unavailable"
    assert state["modules"]["detect"]["status"] == "not_started"
    monkeypatch.setattr("guardian.orchestrator.scan_repository", discovery)
    store.resume(SCAN)
    runner.run(SCAN)
    assert store.get(SCAN)["status"] == "completed"
    assert store.get(SCAN)["modules"]["discover"]["attempts"] == 2


def test_changed_local_policy_invalidates_detection_checkpoint(tmp_path, monkeypatch):
    from guardian.process import WORKSPACE
    policy_root = tmp_path / "trusted-config"
    policy_root.mkdir()
    (policy_root / "policy.yaml").write_bytes((WORKSPACE / "policy.yaml").read_bytes())
    monkeypatch.setattr("guardian.orchestrator.WORKSPACE", policy_root)
    monkeypatch.setattr("guardian.orchestrator.scan_repository", discovery)
    store, runner = setup_job(tmp_path)
    runner.run(SCAN)
    assert runner.valid_checkpoint(SCAN, "detect")
    with (policy_root / "policy.yaml").open("a") as handle:
        handle.write("\n# Local review policy changed\n")
    assert not runner.valid_checkpoint(SCAN, "detect")
    assert runner.valid_checkpoint(SCAN, "discover")


def test_changed_ai_configuration_invalidates_analysis_only(tmp_path, monkeypatch):
    from guardian.ai import AIConfig
    monkeypatch.setattr("guardian.orchestrator.scan_repository", discovery)
    store, runner = setup_job(tmp_path)
    runner.ai_config = AIConfig(enabled=False)
    runner.run(SCAN)
    assert runner.valid_checkpoint(SCAN, "analyze")
    runner.ai_config = AIConfig(enabled=True, credentials=())
    assert not runner.valid_checkpoint(SCAN, "analyze")
    assert runner.valid_checkpoint(SCAN, "discover") and runner.valid_checkpoint(SCAN, "detect")


def test_queued_cancellation_and_restart_recovery(tmp_path):
    store, runner = setup_job(tmp_path)
    with pytest.raises(JobConflict):
        store.resume(SCAN)
    store.cancel(SCAN)
    runner.run(SCAN)
    assert store.get(SCAN)["status"] == "cancelled"
    assert store.get(SCAN)["modules"]["discover"]["attempts"] == 0
    with pytest.raises(JobConflict):
        store.cancel(SCAN)
    store.resume(SCAN)
    store.change(SCAN, lambda state: state["modules"]["discover"].update(status="running"))
    reopened = JobStore(store.path)
    reopened.recover()
    assert reopened.get(SCAN)["status"] == "interrupted"
    assert reopened.get(SCAN)["modules"]["discover"]["status"] == "interrupted"
    assert reopened.resume(SCAN)["status"] == "queued"


def test_cancel_kills_running_tool_and_never_runs_detection(tmp_path, monkeypatch):
    entered = threading.Event()
    def slow_discovery(url, path, update):
        entered.set()
        run_tool([sys.executable, "-c", "import time; time.sleep(30)"], path, timeout=40)
        raise AssertionError("Cancelled tool should not return")
    monkeypatch.setattr("guardian.orchestrator.scan_repository", slow_discovery)
    store, runner = setup_job(tmp_path)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(runner.run, SCAN)
        assert entered.wait(timeout=3)
        assert store.cancel(SCAN)["status"] == "cancelling"
        future.result(timeout=5)
    assert store.get(SCAN)["status"] == "cancelled"
    assert store.get(SCAN)["modules"]["discover"]["status"] == "cancelled"
    assert store.get(SCAN)["modules"]["detect"]["attempts"] == 0


def test_persistent_scan_and_shared_daily_budgets_are_atomic(tmp_path):
    store, _ = setup_job(tmp_path)
    with ThreadPoolExecutor(max_workers=8) as executor:
        allowed = list(executor.map(lambda _: store.reserve_ai_call(SCAN), range(20)))
    assert sum(allowed) == 3
    assert JobStore(store.path).get(SCAN)["ai_budget"]["calls"] == 3
    store.create("b" * 32, URL)
    assert not store.reserve_ai_call("b" * 32, daily_limit=3)
    assert store.reserve_ai_call("b" * 32, daily_limit=4)
    store.cancel("b" * 32)
    assert not store.reserve_ai_call("b" * 32)


def pipeline_wait(client, scan_id):
    for _ in range(200):
        state = client.get(f"/api/scans/{scan_id}/pipeline").json()
        if state["status"] not in {"queued", "running", "cancelling"}:
            return state
        time.sleep(.01)
    raise AssertionError("Pipeline did not finish")


def test_pipeline_api_and_legacy_artifacts(tmp_path, monkeypatch):
    monkeypatch.setattr("guardian.orchestrator.scan_repository", discovery)
    with TestClient(create_app(tmp_path, osv_transport=httpx.MockTransport(no_matches))) as client:
        assert client.post("/api/pipelines", json={"repo_url": "file:///tmp"}).status_code == 422
        assert client.post("/api/pipelines", json={"repo_url": URL, "baseline_commit": "bad"}).status_code == 422
        response = client.post("/api/pipelines", json={"repo_url": URL})
        assert response.status_code == 202
        scan_id = response.json()["scan_id"]
        assert pipeline_wait(client, scan_id)["status"] == "completed"
        assert client.get(f"/api/scans/{scan_id}/graph").status_code == 200
        assert client.get(f"/api/scans/{scan_id}/detection-report").json()["status"] == "partial"
        assert client.get(f"/api/scans/{scan_id}").json()["status"] == "completed"
        assert client.get(f"/api/scans/{scan_id}").json()["pipeline_status"] == "completed"
        assert client.get("/api/pipelines").json()["pipelines"][0]["scan_id"] == scan_id
        assert client.post(f"/api/scans/{scan_id}/cancel").status_code == 409
        assert client.post(f"/api/scans/{scan_id}/resume").status_code == 202
        state = pipeline_wait(client, scan_id)
        assert state["modules"]["discover"]["attempts"] == 1
        assert state["modules"]["detect"]["attempts"] == 1
        assert client.get("/api/scans/not-a-scan/pipeline").status_code == 404
        assert client.post("/api/pipelines", json={"repo_url": URL}, headers={"origin": "https://evil.example"}).status_code == 403
    with TestClient(create_app(tmp_path)) as client:
        assert client.get(f"/api/scans/{scan_id}/pipeline").json()["status"] == "completed"


def test_api_rejects_duplicate_resume_and_manual_detection_while_active(tmp_path, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    def slow(url, path, update):
        entered.set()
        assert release.wait(timeout=5)
        return discovery(url, path, update)
    monkeypatch.setattr("guardian.orchestrator.scan_repository", slow)
    with TestClient(create_app(tmp_path, osv_transport=httpx.MockTransport(no_matches))) as client:
        scan_id = client.post("/api/pipelines", json={"repo_url": URL}).json()["scan_id"]
        try:
            assert entered.wait(timeout=3)
            assert client.post(f"/api/scans/{scan_id}/resume").status_code == 409
            assert client.post(f"/api/scans/{scan_id}/detect", json={}).status_code == 409
            assert client.post(f"/api/scans/{scan_id}/cancel").status_code == 200
        finally:
            release.set()
        assert pipeline_wait(client, scan_id)["status"] == "cancelled"


def test_unknown_database_schema_is_rejected(tmp_path):
    store = JobStore(tmp_path / "guardian.sqlite3")
    with store.connection() as db:
        db.execute("PRAGMA user_version = 99")
    with pytest.raises(RuntimeError, match="Unsupported Guardian database schema"):
        JobStore(store.path)
