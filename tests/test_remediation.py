import copy
import json
import subprocess
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from guardian.ai import AIConfig
from guardian.analysis import run_analysis
from guardian.app import create_app
from guardian.files import write_json
from guardian.graph import build_graph
from guardian.npm import reconcile_npm_projects
from guardian.orchestrator import JobStore, Orchestrator
from guardian.phase2 import run_detection
from guardian.remediation import digest, npm_operation, preflight, registry_url, review_plan, reviews, run_remediation, snapshot, verify_plan
from guardian.validation import container_tests, run_validation
from test_phase2 import scan_fixture
from test_vulnerabilities import advisory


def osv_response(request):
    if request.url.path.endswith("querybatch"):
        queries = json.loads(request.content)["queries"]
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-test-1234-5678"}]} if q["package"]["name"] == "lodash" and q["version"] == "4.17.20" else {} for q in queries]})
    record = advisory()
    record["affected"][0]["ranges"] = [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]
    return httpx.Response(200, json=record)


def metadata_response(request):
    if request.url.host == "registry.npmjs.org":
        name, version = request.url.path.strip("/").rsplit("/", 1)
        return httpx.Response(200, json={"name": name, "version": version,
            "dist": {"tarball": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz", "integrity": "sha512-" + "a" * 86 + "=="}})
    return httpx.Response(404)


def fake_npm(args, cwd, **kwargs):
    assert args[0] == "npm" and "--ignore-scripts" in args
    assert "--registry=https://registry.npmjs.org" in args
    assert not (cwd / ".npmrc").exists() and not (cwd / ".env").exists()
    assert kwargs["extra_env"]["NPM_CONFIG_IGNORE_SCRIPTS"] == "true"
    for argument in args:
        if argument.startswith(("--userconfig=", "--globalconfig=")):
            from pathlib import Path
            assert Path(argument.split("=", 1)[1]).read_text() == ""
    if "--package-lock-only" in args:
        assert "--offline" in args
    return subprocess.CompletedProcess(args, 0, "fixture npm completed", "")


def prepared(tmp_path, monkeypatch):
    scan, repo, inventory, _ = scan_fixture(tmp_path)
    lock = json.loads((repo / "package-lock.json").read_text())
    for path, entry in lock["packages"].items():
        if path:
            name = path.rsplit("node_modules/", 1)[-1]
            entry.update(resolved=f"https://registry.npmjs.org/{name}/-/{name}-{entry['version']}.tgz", integrity="sha512-" + "a" * 86 + "==")
    write_json(repo / "package-lock.json", lock)
    inventory = reconcile_npm_projects(repo, "package-lock.json", ["package.json"], "repository:test")
    write_json(scan / "artifacts/components.json", inventory.model_dump())
    write_json(scan / "artifacts/dependency_graph.json", build_graph(inventory))
    (repo / "index.js").write_text("require('lodash');")
    (repo / ".npmrc").write_text("registry=https://evil.invalid\n//registry.npmjs.org/:_authToken=SECRET")
    (repo / ".env").write_text("SECRET=hidden")
    store = JobStore(tmp_path / "guardian.sqlite3")
    transport = httpx.MockTransport(osv_response)
    metadata = httpx.MockTransport(metadata_response)
    run_detection(scan, transport=transport, metadata_transport=metadata)
    assert run_analysis(scan, store, config=AIConfig(enabled=False))["status"] == "partial"
    monkeypatch.setattr("guardian.remediation.run_tool", fake_npm)
    report = run_remediation(scan, store, osv_transport=transport, metadata_transport=metadata, config=AIConfig(enabled=False))
    assert report["status"] == "completed", report
    assert len(report["proposals"]) == 1, report
    return scan, repo, store, report


@pytest.mark.parametrize("reference", ["git+https://github.com/x/y", "github:x/y", "https://evil.invalid/pkg.tgz", "file:../pkg", "workspace:*", "npm:other@1.0.0", "latest"])
def test_refuse_fetching_references_before_npm(tmp_path, monkeypatch, reference):
    write_json(tmp_path / "package.json", {"dependencies": {"pkg": reference}})
    write_json(tmp_path / "package-lock.json", {"lockfileVersion": 3, "packages": {"": {}}})
    monkeypatch.setattr("guardian.remediation.run_tool", lambda *a, **k: pytest.fail("Unsafe dependency reached npm"))
    with pytest.raises(ValueError):
        npm_operation(tmp_path, ["ci"])


@pytest.mark.parametrize("url", ["http://registry.npmjs.org/pkg", "https://evil.invalid/pkg", "https://registry.npmjs.org@evil.invalid/pkg", "https://registry.npmjs.org/../pkg", "https://registry.npmjs.org/%2e%2e/pkg", "https://registry.npmjs.org/pkg?auth=x"])
def test_lock_urls_refuse_external_hosts_and_traversal(url):
    with pytest.raises(ValueError):
        registry_url(url)


def test_nested_lock_reference_and_links_are_checked():
    manifest = {"dependencies": {"pkg": "1.0.0"}}
    lock = {"lockfileVersion": 3, "packages": {"": manifest, "node_modules/pkg": {"version": "1.0.0", "dependencies": {"remote": "https://evil.invalid/pkg.tgz"}}}}
    with pytest.raises(ValueError): preflight(manifest, lock)
    lock["packages"]["node_modules/pkg"] = {"version": "1.0.0", "link": True}
    with pytest.raises(ValueError): preflight(manifest, lock)
    with pytest.raises(ValueError): preflight({**manifest, "overrides": {"pkg": "file:../x"}}, lock)


def test_proposal_is_source_bound_and_decisions_are_explicit_immutable(tmp_path, monkeypatch):
    scan, repo, store, report = prepared(tmp_path, monkeypatch)
    proposal = report["proposals"][0]
    assert proposal["to_version"] == "4.17.21" and proposal["constraint_change_required"]
    assert report["ai"]["task"] == "fix_notes"
    assert report["ai"]["provider"] == "template"
    assert "SECRET" not in json.dumps(report)
    assert verify_plan(scan) == report
    with pytest.raises(ValueError, match="confirmation"):
        review_plan(scan, store, proposal["id"], proposal_digest=proposal["digest"], decision="approve")
    with pytest.raises(ValueError, match="reason"):
        review_plan(scan, store, proposal["id"], proposal_digest=proposal["digest"], decision="accepted_risk")
    record = review_plan(scan, store, proposal["id"], proposal_digest=proposal["digest"], decision="approve", reviewed_diff=True, reason="Synthetic test review")
    assert JobStore(store.path) and reviews(store, scan.name)[proposal["id"]] == record
    with pytest.raises(ValueError, match="immutable"):
        review_plan(scan, store, proposal["id"], proposal_digest=proposal["digest"], decision="reject")
    diff = scan / f"artifacts/remediation/proposals/{proposal['id']}/patch.diff"
    diff.write_text("tampered")
    with pytest.raises(ValueError, match="bytes changed"): verify_plan(scan)


def test_source_and_analysis_changes_invalidate_plan(tmp_path, monkeypatch):
    scan, repo, _, _ = prepared(tmp_path, monkeypatch)
    (repo / "index.js").write_text("changed")
    with pytest.raises(ValueError, match="Source changed"): verify_plan(scan)


@pytest.mark.parametrize("failure", ["outage", "deprecated", "topology", "new_advisory", "wrong_identity"])
def test_uncertain_candidates_never_produce_patch(tmp_path, monkeypatch, failure):
    scan, _, store, _ = prepared(tmp_path, monkeypatch)
    def registry(request):
        data = metadata_response(request).json()
        if failure == "deprecated": data["deprecated"] = "Do not use"
        if failure == "topology": data["dependencies"] = {"remote": "git+https://github.com/test/untrusted"}
        if failure == "wrong_identity": data["name"] = "other"
        return httpx.Response(200, json=data)
    def osv(request):
        if failure == "outage": return httpx.Response(503)
        if failure == "new_advisory" and request.url.path.endswith("querybatch"):
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-newx-1234-5678"}]}]})
        if failure == "new_advisory":
            record = advisory("GHSA-newx-1234-5678")
            record["affected"][0]["ranges"] = []
            return httpx.Response(200, json=record)
        return osv_response(request)
    # Fresh per-plan query cache makes the simulated provider failure observable.
    import shutil
    shutil.rmtree(scan / "artifacts/remediation/osv-cache")
    monkeypatch.setattr("guardian.remediation.npm_operation", lambda *a: pytest.fail("Unverified candidate reached npm"))
    plan = run_remediation(scan, store, osv_transport=httpx.MockTransport(osv), metadata_transport=httpx.MockTransport(registry), config=AIConfig(enabled=False))
    assert plan["status"] == "partial" and not plan["proposals"], plan
    assert plan["recommendations"][0]["status"] == "manual_review"


def test_candidate_evidence_tampering_invalidates_approval(tmp_path, monkeypatch):
    scan, _, _, plan = prepared(tmp_path, monkeypatch)
    index = json.loads((scan / "artifacts/remediation/evidence/index.json").read_text())
    proof = index[plan["proposals"][0]["evidence_ids"][0]]
    (scan / "artifacts/remediation/evidence" / proof["raw_artifact"].split("/")[-1]).write_text("tamper")
    with pytest.raises(ValueError, match="Candidate evidence changed"): verify_plan(scan)


def test_new_vulnerability_in_rescan_fails_validation(tmp_path, monkeypatch):
    scan, _, store, plan = prepared(tmp_path, monkeypatch)
    proposal = plan["proposals"][0]
    review_plan(scan, store, proposal["id"], proposal_digest=proposal["digest"], decision="approve", reviewed_diff=True)
    monkeypatch.setattr("guardian.validation.analyze_repository", fake_discovery)
    def new_advisory(request):
        if request.url.path.endswith("querybatch"):
            queries = json.loads(request.content)["queries"]
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-newx-1234-5678"}]} if q["package"]["name"] == "lodash" else {} for q in queries]})
        record = advisory("GHSA-newx-1234-5678")
        record["aliases"] = ["CVE-2099-0002"]
        record["affected"][0]["versions"] = ["4.17.21"]
        return httpx.Response(200, json=record)
    report = run_validation(scan, store, osv_transport=httpx.MockTransport(new_advisory), metadata_transport=httpx.MockTransport(metadata_response))
    assert report["status"] == "failed", report
    assert report["results"][0]["finding_diff"]["introduced"]
    assert report["results"][0]["dependency_verification"] == "failed"


def test_incomplete_lock_is_refused_before_rebuild(tmp_path, monkeypatch):
    write_json(tmp_path / "package.json", {"dependencies": {"pkg": "1.0.0"}})
    write_json(tmp_path / "package-lock.json", {"lockfileVersion": 3, "packages": {"": {}, "node_modules/pkg": {"version": "1.0.0"}}})
    monkeypatch.setattr("guardian.remediation.run_tool", lambda *a, **k: pytest.fail("Incomplete lock reached npm ci"))
    with pytest.raises(ValueError, match="integrity"):
        npm_operation(tmp_path, ["ci"])


def test_docker_test_runner_uses_digest_pinning_no_network_and_cleanup(tmp_path, monkeypatch):
    write_json(tmp_path / "package.json", {"scripts": {"test": "node test.js", "build": "node build.js"}})
    monkeypatch.setattr("guardian.validation.shutil.which", lambda name: "/bin/docker")
    monkeypatch.setenv("GUARDIAN_TEST_IMAGE", "node@sha256:" + "a" * 64)
    calls = []
    def execute(args, cwd, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "ok", "")
    monkeypatch.setattr("guardian.validation.run_tool", execute)
    result = container_tests(tmp_path, requested=True)
    assert result["status"] == "passed" and result["commands"] == ["build", "test"]
    assert "--network=none" in calls[0] and "--pull=never" in calls[0] and "--read-only" in calls[0]
    assert "--cap-drop=ALL" in calls[0] and "--security-opt=no-new-privileges" in calls[0]
    assert calls[1][:3] == ["docker", "rm", "-f"]


def fake_discovery(repository, artifacts, update):
    from pathlib import Path
    inventory = reconcile_npm_projects(Path(repository.path), "package-lock.json", ["package.json"], "repository:test")
    write_json(artifacts / "components.json", inventory.model_dump())
    write_json(artifacts / "dependency_graph.json", build_graph(inventory))
    result = {"status": "completed", "repository": {"commit": repository.commit}, "coverage_status": "verified", "dependency_status": "has_dependencies", "sbom": {"status": "completed"}}
    write_json(artifacts / "discovery_report.json", result)
    write_json(artifacts / "sbom.json", {"components": [{"purl": "pkg:npm/lodash@4.17.21"}]})
    return result


def test_approved_rebuild_rescans_without_modifying_original_and_reports_missing_tests(tmp_path, monkeypatch):
    scan, repo, store, plan = prepared(tmp_path, monkeypatch)
    before = snapshot(repo)
    assert run_validation(scan, store)["status"] == "failed"
    proposal = plan["proposals"][0]
    review_plan(scan, store, proposal["id"], proposal_digest=proposal["digest"], decision="approve", reviewed_diff=True, reason="Synthetic test approval")
    monkeypatch.setattr("guardian.validation.analyze_repository", fake_discovery)
    monkeypatch.setattr("guardian.validation.shutil.which", lambda _: None)
    result = run_validation(scan, store, osv_transport=httpx.MockTransport(osv_response), metadata_transport=httpx.MockTransport(metadata_response), run_tests=True)
    assert result["status"] == "partial", result
    verified = result["results"][0]
    assert verified["rebuild"]["status"] == "passed"
    assert verified["dependency_verification"] == "passed"
    assert verified["tests"]["status"] == "not_run"
    assert verified["sbom_diff"]["status"] == "not_run"
    assert verified["finding_diff"]["resolved"] and not verified["finding_diff"]["introduced"]
    assert snapshot(repo) == before and not (repo / "node_modules").exists()
    assert not json.loads((scan / "artifacts/verified_report.json").read_text())["fully_verified"]


@pytest.mark.parametrize("decision", ["reject", "accepted_risk"])
def test_rejected_and_accepted_risk_never_run_rebuild(tmp_path, monkeypatch, decision):
    scan, _, store, plan = prepared(tmp_path, monkeypatch)
    proposal = plan["proposals"][0]
    review_plan(scan, store, proposal["id"], proposal_digest=proposal["digest"], decision=decision, reason="Synthetic review")
    monkeypatch.setattr("guardian.validation.npm_operation", lambda *a: pytest.fail("Unapproved patch was rebuilt"))
    result = run_validation(scan, store)
    assert result["status"] == "not_run" and result["results"][0]["decision"] == decision


def test_api_diff_approval_validation_staleness_and_exports(tmp_path, monkeypatch):
    scan, repo, _, plan = prepared(tmp_path, monkeypatch)
    proposal = plan["proposals"][0]
    with TestClient(create_app(tmp_path)) as client:
        base = f"/api/scans/{scan.name}"
        assert client.get(base + "/remediation").json()["report"]["proposals"]
        assert "4.17.21" in client.get(base + f"/remediation/{proposal['id']}/diff").text
        assert client.post(base + "/validate", json={}).status_code == 409
        body = {"digest": proposal["digest"], "decision": "approve"}
        assert client.post(base + f"/remediation/{proposal['id']}/decision", json=body).status_code == 409
        body["decision"] = "reject"
        assert client.post(base + f"/remediation/{proposal['id']}/decision", json=body).status_code == 200
        assert client.post(base + "/validate", json={}).status_code == 202
        for _ in range(100):
            state = client.get(base + "/validation").json()
            if state["status"] not in {"queued", "running"}: break
            time.sleep(.01)
        assert state["status"] == "not_run", state
        assert client.get(base + "/verified-report").json()["fully_verified"] is False
        (repo / "index.js").write_text("changed")
        assert client.get(base + "/remediation").json()["status"] == "stale"
        assert client.post(base + "/validate", json={}).status_code == 409


def test_orchestrator_waits_for_exact_review_then_reuses_plan(tmp_path, monkeypatch):
    scan, _, store, _ = prepared(tmp_path, monkeypatch)
    store.create(scan.name, "https://github.com/test/fixture")
    runner = Orchestrator(store, tmp_path, ai_config=AIConfig(enabled=False))
    for stage, filename in [("discover", "discovery_report.json"), ("detect", "detection_report.json"), ("analyze", "analysis_report.json"), ("remediate", "remediation_report.json")]:
        report = json.loads((scan / "artifacts" / filename).read_text())
        report.setdefault("status", "completed")
        runner.checkpoint(scan.name, stage, report)
        store.change(scan.name, lambda state, stage=stage: state["modules"][stage].update(status=report["status"]))
    runner.run(scan.name)
    assert store.get(scan.name)["status"] == "awaiting_approval"
    plan = verify_plan(scan)
    proposal = plan["proposals"][0]
    review_plan(scan, store, proposal["id"], proposal_digest=proposal["digest"], decision="reject")
    store.resume(scan.name)
    runner.run(scan.name)
    assert store.get(scan.name)["status"] == "completed"
    assert verify_plan(scan)["proposals"][0]["id"] == proposal["id"]
    assert store.get(scan.name)["modules"]["validate"]["status"] == "not_run"
