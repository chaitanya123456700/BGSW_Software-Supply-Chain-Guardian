"""Six-view workspace integration and controlled demonstration boundaries."""
import hashlib
import json
import time
from dataclasses import replace
from html.parser import HTMLParser

import httpx
import pytest
from fastapi.testclient import TestClient

from guardian.ai import AIConfig, Credential
from guardian.app import create_app
from guardian.demo import DEMO_URL, create_fixture, warm_cache
from guardian.files import write_json
from guardian.graph import build_graph
from guardian.npm import reconcile_npm_projects
from guardian.orchestrator import JobStore
from test_ai import response as ai_response
from test_remediation import fake_discovery, fake_npm, metadata_response, osv_response, prepared


def wait_pipeline(client, scan_id):
    for _ in range(300):
        state = client.get(f"/api/scans/{scan_id}/pipeline").json()
        if state["status"] not in {"queued", "running", "cancelling"}:
            return state
        time.sleep(.01)
    raise AssertionError("Demo pipeline did not finish")


def demo_discovery(repository, artifacts, update):
    from pathlib import Path
    inventory = reconcile_npm_projects(Path(repository.path), "package-lock.json", ["package.json"], "repository:test")
    write_json(artifacts / "components.json", inventory.model_dump())
    write_json(artifacts / "dependency_graph.json", build_graph(inventory))
    report = {"status": "completed", "repository": repository.model_dump(exclude={"path"}),
              "coverage_status": "verified", "dependency_status": "has_dependencies", "statistics": build_graph(inventory)["statistics"],
              "sbom": {"status": "failed"}}
    write_json(artifacts / "discovery_report.json", report)
    return report


def test_controlled_demo_full_pipeline_requires_review_and_preserves_source(tmp_path, monkeypatch):
    monkeypatch.setattr("guardian.orchestrator.analyze_repository", demo_discovery)
    monkeypatch.setattr("guardian.remediation.run_tool", fake_npm)
    monkeypatch.setattr("guardian.validation.analyze_repository", fake_discovery)
    monkeypatch.setattr("guardian.validation.shutil.which", lambda name: None)
    with TestClient(create_app(tmp_path, osv_transport=httpx.MockTransport(osv_response),
                               metadata_transport=httpx.MockTransport(metadata_response), ai_config=AIConfig(enabled=False))) as client:
        assert client.post("/api/demo", headers={"origin": "https://evil.invalid"}).status_code == 403
        started = client.post("/api/demo")
        assert started.status_code == 202
        assert started.json()["approval"] == "required" and started.json()["providers"] == "live"
        scan_id = started.json()["scan_id"]
        base = f"/api/scans/{scan_id}"
        state = wait_pipeline(client, scan_id)
        assert state["status"] == "awaiting_approval", state
        assert state["modules"]["validate"]["attempts"] == 0
        summary = client.get(base + "/summary").json()
        assert summary["controlled_fixture"] and summary["advisories"] == 1
        assert summary["analysis"]["findings_count"] > 0
        assert summary["remediation"]["proposals_count"] == 1
        assert summary["remediation"]["pending_review_count"] == 1
        assert summary["remediation"]["approved_count"] == 0
        history = client.get("/api/scans").json()["scans"]
        assert history[0]["controlled_fixture"] and history[0]["commit"] == "6" * 40
        assert history[0]["repo_url"] == DEMO_URL
        assert "sbom" not in summary["available_artifacts"]
        scan = tmp_path / scan_id
        repo = scan / "workspaces/repo-controlled/source"
        before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in repo.iterdir()}
        assert client.post(base + "/validate", json={}).status_code == 409
        proposal = client.get(base + "/remediation").json()["report"]["proposals"][0]
        decision = {"digest": proposal["digest"], "decision": "approve", "reviewed_diff": True,
                    "reason": "Automated controlled test approval only"}
        assert client.post(base + f"/remediation/{proposal['id']}/decision", json=decision).status_code == 200
        reviewed = client.get(base + "/summary").json()["remediation"]
        assert reviewed["approved_count"] == 1 and reviewed["pending_review_count"] == 0
        assert client.post(base + "/resume", json={"run_tests": True}).status_code == 202
        state = wait_pipeline(client, scan_id)
        assert state["status"] == "completed", state
        assert state["validation_run_tests"] is True
        assert state["modules"]["discover"]["attempts"] == 1
        assert state["modules"]["remediate"]["attempts"] == 1
        report = client.get(base + "/verified-report").json()
        assert report["status"] == "partial" and report["fully_verified"] is False
        assert report["results"][0]["tests"]["status"] == "not_run"
        assert report["results"][0]["dependency_verification"] == "passed"
        assert report["results"][0]["finding_diff"]["remaining"]
        assert "verified-report" in client.get(base + "/summary").json()["available_artifacts"]
        assert not (repo / "SCRIPT_EXECUTED").exists()
        assert before == {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in repo.iterdir()}
        (repo / "index.js").write_text("Source changed after validation")
        stale = client.get(base + "/summary").json()
        assert stale["validation"]["status"] == "stale" and not stale["validation"]["results"]
        assert client.get("/api/scans/not-a-scan/summary").status_code == 404
        assert client.post("/api/pipelines", json={"repo_url": DEMO_URL}).status_code == 422


def test_demo_fixture_never_accepts_an_arbitrary_local_source(tmp_path):
    scan = tmp_path / "a"
    result = create_fixture(scan)
    assert result.url == DEMO_URL and result.commit == "6" * 40
    assert json.loads((scan / "demo.json").read_text())["approval"] == "required"
    assert (scan / "workspaces/repo-controlled/source/.npmrc").exists()
    assert not (scan / "workspaces/repo-controlled/source/SCRIPT_EXECUTED").exists()
    with pytest.raises(FileExistsError):
        create_fixture(scan)


def test_demo_cache_warms_needed_tasks_and_replays_without_requests(tmp_path, monkeypatch):
    scan, _, store, _ = prepared(tmp_path, monkeypatch)
    config = AIConfig(credentials=(Credential(1, "synthetic-test-project", "synthetic-test-key"),), interval=0)
    calls = []
    def respond(request):
        calls.append(request)
        return ai_response(request)
    warmed = warm_cache(scan, store, config=config, transport=httpx.MockTransport(respond))
    assert len(calls) == 2 and warmed["usage"]["requests"] == 2
    assert [task["provider"] for task in warmed["tasks"]] == ["gemini", "not_needed", "gemini"]
    def forbidden(request):
        pytest.fail("A warmed demo replay must make zero provider requests")
    replay = warm_cache(scan, JobStore(store.path), config=replace(config, enabled=False), transport=httpx.MockTransport(forbidden))
    assert replay["usage"]["cache_hits"] == 2 and replay["usage"]["requests"] == 0
    assert all(task["cache_hit"] for task in replay["tasks"] if task["provider"] != "not_needed")


def test_demo_without_credentials_uses_templates_and_never_fakes_cache(tmp_path, monkeypatch):
    scan, _, store, _ = prepared(tmp_path, monkeypatch)
    result = warm_cache(scan, store, config=AIConfig(enabled=False))
    assert result["usage"]["requests"] == 0 and result["usage"]["cache_hits"] == 0
    assert all(task["provider"] in {"template", "not_needed"} for task in result["tasks"])
    with store.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM ai_cache").fetchone()[0] == 0


def test_workspace_six_views_keep_legacy_controls_and_csp(tmp_path):
    class Document(HTMLParser):
        def __init__(self):
            super().__init__()
            self.ids, self.views, self.routes = [], [], []
        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if attrs.get("id"): self.ids.append(attrs["id"])
            if attrs.get("data-view"): self.views.append(attrs["data-view"])
            if attrs.get("data-route"): self.routes.append(attrs["data-route"])
    with TestClient(create_app(tmp_path)) as client:
        page = client.get("/")
        parser = Document()
        parser.feed(page.text)
        assert len(parser.ids) == len(set(parser.ids))
        assert set(parser.views) == set(parser.routes) == {"overview", "pipeline", "dependencies", "findings", "remediation", "reports"}
        assert {"graph", "scene", "finding-detail", "prepare-fixes", "validate-fixes", "ai-status-button", "pipeline-cancel", "pipeline-resume"} <= set(parser.ids)
        assert "script-src 'self'" in page.headers["content-security-policy"]
        assert "https://" not in page.text.replace("https://github.com/owner/repository", "").replace("http://www.w3.org/2000/svg", "")
        assert client.get("/static/workspace.js").status_code == 200
        assert client.get("/api/scans").json() == {"scans": []}


def test_history_ignores_invalid_scan_names_and_corrupt_statuses(tmp_path):
    for name, value in [("a" * 32, "not-json"), ("b" * 32, json.dumps({"status": "partial", "repo_url": "https://github.com/test/fixture"})), ("not-valid", "{}")]:
        (tmp_path / name).mkdir()
        (tmp_path / name / "status.json").write_text(value)
    with TestClient(create_app(tmp_path)) as client:
        rows = client.get("/api/scans").json()["scans"]
        assert len(rows) == 1 and rows[0]["scan_id"] == "b" * 32
