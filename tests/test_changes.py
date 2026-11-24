import json

from guardian.changes import detect_changes
from guardian.evidence import EvidenceStore
from guardian.graph import build_graph
from guardian.models import Inventory
from guardian.process import run_tool


def git(repo, *args):
    return run_tool(["git", "-c", "user.name=Guardian Fixture", "-c", "user.email=fixture@example.test",
                     "-c", "core.hooksPath=/dev/null", *args], repo, timeout=10).stdout.strip()


def test_actual_git_changes_have_before_after_evidence(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init")
    (repo / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.20"}}))
    (repo / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20", "integrity": "old", "resolved": "https://registry.npmjs.org/lodash/old.tgz"}}}))
    workflow = repo / ".github/workflows/test.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("permissions: read-all\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n")
    (repo / "Dockerfile").write_text("FROM node:20\n")
    git(repo, "add", "."); git(repo, "commit", "-m", "baseline")
    baseline = git(repo, "rev-parse", "HEAD")
    (repo / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.21", "exress": "1.0.0"}, "scripts": {"postinstall": "node setup.js"}}))
    (repo / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.21", "integrity": "new", "resolved": "https://mirror.example.test/lodash/new.tgz"}, "node_modules/exress": {"version": "1.0.0", "hasInstallScript": True}}}))
    workflow.write_text(workflow.read_text().replace("read-all", "write-all"))
    (repo / "Dockerfile").write_text("FROM node:22\n")
    git(repo, "add", "."); git(repo, "commit", "-m", "current")
    current = git(repo, "rev-parse", "HEAD")
    inventory = Inventory(repository_id="repository:test")
    store = EvidenceStore(tmp_path / "evidence", current)
    report = detect_changes(repo, inventory, build_graph(inventory), store, "scan", current, baseline)
    rules = {finding["rule_id"] for finding in report["findings"]}
    assert rules == {"RULE_NEW_DEPENDENCY", "RULE_VERSION_CHANGE", "RULE_NEW_INSTALL_SCRIPT", "RULE_REGISTRY_CHANGE",
                     "RULE_INTEGRITY_CHANGE", "RULE_WORKFLOW_PERMISSION_CHANGE", "RULE_UNPINNED_ACTION", "RULE_SIMILAR_PACKAGE_NAME", "RULE_BASE_IMAGE_CHANGE"}
    assert report["comparison_status"] == "available"
    assert all(f["baseline_commit"] == baseline for f in report["findings"] if f["classification"] == "observed_change")
    assert all(set(f["evidence_ids"]) <= set(store.records) for f in report["findings"])


def test_no_baseline_skips_change_claims_but_inspects_workflows(tmp_path):
    workflow = tmp_path / ".github/workflows/test.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("jobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./local-action\n      - uses: actions/cache@" + "a" * 40 + "\n")
    (tmp_path / "package.json").write_text('{"dependencies":{"exress":"1.0.0"},"scripts":{"postinstall":"node x.js"}}')
    inventory = Inventory(repository_id="repo")
    report = detect_changes(tmp_path, inventory, build_graph(inventory), EvidenceStore(tmp_path / "evidence", "a" * 40), "scan", "a" * 40)
    assert report["comparison_status"] == "comparison_unavailable"
    assert [f["rule_id"] for f in report["findings"]] == ["RULE_UNPINNED_ACTION"]
    assert not any("new" in f["title"].lower() for f in report["findings"])
