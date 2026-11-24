import hashlib
import json
import time

import httpx
from fastapi.testclient import TestClient

from guardian.ai import AIConfig
from guardian.analysis import prioritize, run_analysis, severity
from guardian.app import create_app
from guardian.evidence import EvidenceStore
from guardian.graph import build_graph
from guardian.models import Finding
from guardian.orchestrator import JobStore
from guardian.phase2 import run_detection
from guardian.reachability import imports, package_reachability
from test_phase2 import no_matches, scan_fixture
from test_vulnerabilities import advisory, inventory_fixture


def test_import_lexer_skips_comments_strings_and_builtins_and_preserves_types():
    source = '''// require('bad-comment')
/* import bad from 'bad-block'; */
const text = "require('bad-string')";
import item from 'lodash/fp';
export {item} from '@scope/pkg/child';
import type {Type} from 'types';
const parent = require('parent');
const lazy = import('lazy');
import fs from 'fs/promises';
'''
    found, dynamic = imports(source)
    assert [item["package"] for item in found] == ["lodash", "@scope/pkg", "types", "parent", "lazy"]
    assert found[2]["type_only"] and not dynamic
    assert imports("require(variable); import(`name-${id}`)")[1]


def test_package_reachability_inherits_possible_paths_and_preserves_negative_scope(tmp_path):
    inventory = inventory_fixture(tmp_path)
    (tmp_path / "index.ts").write_text("import parent from 'parent';\n")
    store = EvidenceStore(tmp_path / "evidence", "commit")
    report = package_reachability(tmp_path, inventory, build_graph(inventory), store)
    states = {(c.name, c.version): report["components"][c.id]["status"] for c in inventory.components if c.kind == "package"}
    assert states[("parent", "1.0.0")] == "reachable"
    assert states[("lodash", "4.17.21")] == "possibly_reachable"
    assert states[("lodash", "4.17.20")] == "not_reachable"
    leaf = next(c for c in inventory.components if c.version == "4.17.21")
    witness = report["components"][leaf.id]["witnesses"][0]
    assert witness["inherited_from"] and witness["evidence_ids"]
    assert all(e in store.records for e in witness["evidence_ids"])


def test_dynamic_loading_aliases_missing_sources_and_tests_preserve_uncertainty(tmp_path):
    inventory = inventory_fixture(tmp_path)
    graph = build_graph(inventory)
    source = tmp_path / "index.js"
    source.write_text("import lodash from 'lodash'; require(variable);")
    store = EvidenceStore(tmp_path / "evidence", "commit")
    report = package_reachability(tmp_path, inventory, graph, store)
    lodash = next(c for c in inventory.components if c.version == "4.17.20")
    assert report["components"][lodash.id]["status"] == "possibly_reachable"
    assert "not_reachable" not in {item["status"] for item in report["components"].values()}
    source.unlink()
    (tmp_path / "index.test.ts").write_text("import lodash from 'lodash';")
    report = package_reachability(tmp_path, inventory, graph, store)
    assert report["components"][lodash.id]["status"] == "possibly_reachable"
    (tmp_path / "tsconfig.json").write_text('{"compilerOptions":{"paths":{"lodash":["./local"]}}}')
    assert package_reachability(tmp_path, inventory, graph, store)["status"] == "partial"
    report = package_reachability(None, inventory, graph, store)
    assert all(item["status"] == "unknown" for item in report["components"].values())


def finding():
    return Finding(finding_id="finding:" + "a" * 24, scan_id="scan", finding_type="vulnerability", title="fixture",
        explanation="Source-backed fixture", component_instance_ids=["component"], repository_commit="a" * 40,
        verification_status="verified_match", evidence_ids=["evidence:" + "b" * 24], created_at="now",
        source_metadata=[{"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}])


def test_cvss_deterministic_scoring_preserves_original_severity_and_ai_cannot_score():
    original = finding()
    before = original.model_dump_json()
    number, label, supplied = severity(original)
    assert number == 9.8 and label == "critical"
    scored = prioritize([original], {"component": {"status": "reachable"}})[0]
    assert scored["risk_score"] == 74
    assert scored["source_metadata"] == original.source_metadata
    assert original.model_dump_json() == before
    unknown = finding().model_copy(update={"source_metadata": [{"severity": [{"type": "CVSS_V3", "score": "invalid"}]}]})
    assert severity(unknown)[1] == "unknown"
    assert prioritize([unknown], {})[0]["risk_confidence"] < scored["risk_confidence"]


def test_exploitation_policy_and_verification_evidence_affect_scores_deterministically():
    base = finding()
    base.source_metadata[0]["database_specific"] = {"known_exploited": True}
    policy = base.model_copy(deep=True, update={"finding_id": "finding:" + "c" * 24, "finding_type": "policy_violation"})
    scored = prioritize([base, policy], {"component": {"status": "reachable"}})
    result = next(f for f in scored if f["finding_type"] == "vulnerability")
    assert result["risk_score"] == 99
    provisional = base.model_copy(update={"verification_status": "provisional"})
    assert prioritize([provisional], {})[0]["risk_score"] < result["risk_score"]


def detected_scan(tmp_path):
    scan, repo, inventory, _ = scan_fixture(tmp_path)
    (repo / "index.js").write_text("const lodash = require('lodash');\n")
    def osv(request):
        if request.url.path.endswith("querybatch"):
            queries = json.loads(request.content)["queries"]
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-test-1234-5678"}]} if q["version"] == "4.17.20" else {} for q in queries]})
        return httpx.Response(200, json=advisory())
    run_detection(scan, transport=httpx.MockTransport(osv))
    return scan


def test_full_analysis_preserves_detection_and_uses_labeled_templates_without_keys(tmp_path):
    scan = detected_scan(tmp_path)
    original = {p.name: p.read_bytes() for p in (scan / "artifacts").glob("*.json")}
    store = JobStore(tmp_path / "guardian.sqlite3")
    report = run_analysis(scan, store, config=AIConfig(enabled=True, credentials=(), interval=0))
    assert report["status"] == "partial" and report["findings"][0]["reachability_status"] == "reachable"
    assert report["ai"]["tasks"][0]["provider"] == "template"
    assert report["ai"]["usage"]["requests"] == 0
    assert (scan / "artifacts/risk_scores.json").is_file()
    assert all((scan / "artifacts" / name).read_bytes() == raw for name, raw in original.items())
    index = json.loads((scan / "artifacts/analysis/evidence/index.json").read_text())
    assert any(value["source_type"] == "javascript_source" for value in index.values())
    for record in index.values():
        raw = scan / "artifacts/analysis" / record["raw_artifact"]
        assert hashlib.sha256(raw.read_bytes()).hexdigest() == record["sha256"]


def test_analysis_rejects_tampered_evidence(tmp_path):
    scan = detected_scan(tmp_path)
    index = json.loads((scan / "artifacts/evidence/index.json").read_text())
    report = json.loads((scan / "artifacts/detection_report.json").read_text())
    proof = report["findings"][0]["evidence_ids"][0]
    (scan / "artifacts" / index[proof]["raw_artifact"]).write_text("tampered")
    result = run_analysis(scan, JobStore(tmp_path / "guardian.sqlite3"), config=AIConfig(enabled=False))
    assert result["status"] == "failed" and "hash mismatch" in result["errors"][0]


def test_analysis_api_and_settings_do_not_call_providers_at_startup(tmp_path):
    scan = detected_scan(tmp_path)
    def forbidden(request):
        raise AssertionError("No configured keys: no provider HTTP should occur")
    with TestClient(create_app(tmp_path, ai_config=AIConfig(credentials=()), ai_transport=httpx.MockTransport(forbidden))) as client:
        assert client.get("/api/ai/status").json()["daily_requests"] == 0
        assert client.get(f"/api/scans/{scan.name}/analysis").json()["status"] == "not_started"
        assert client.post(f"/api/scans/{scan.name}/analyze").status_code == 202
        for _ in range(200):
            state = client.get(f"/api/scans/{scan.name}/analysis").json()
            if state["status"] not in {"queued", "running"}: break
            time.sleep(.01)
        assert state["status"] == "partial"
        finding_id = state["report"]["findings"][0]["finding_id"]
        assert client.get(f"/api/scans/{scan.name}/findings/{finding_id}").json()["risk_score"] >= 0
        for artifact in ("analysis-report", "risk-scores", "reachability", "ai-notes", "analysis-evidence"):
            assert client.get(f"/api/scans/{scan.name}/{artifact}").status_code == 200
        evidence_id = next(iter(client.get(f"/api/scans/{scan.name}/analysis-evidence").json()))
        assert client.get(f"/api/scans/{scan.name}/analysis-evidence/{evidence_id}").status_code == 200
        assert client.post("/api/ai/check-models").json()["models"] == []
        path = scan / "artifacts/detection_report.json"
        path.write_text(path.read_text() + "\n")
        assert client.get(f"/api/scans/{scan.name}/analysis").json()["status"] == "stale"
