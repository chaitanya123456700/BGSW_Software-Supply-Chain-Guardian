"""Phase 2 coordinator and CLI. Phase 1 artifacts are read, never rewritten."""
import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from pathlib import Path

from .changes import detect_changes
from .evidence import EvidenceStore, timestamp
from .files import read_json, write_json
from .models import Finding, Inventory, Project, stable_id
from .osv import OSVClient
from .process import SCAN_DEADLINE
from .signals import detect_signals
from .vulnerabilities import detect_vulnerabilities

DETECTION_VERSION = "guardian-detection/0.3.0"


def run_detection(scan_directory: Path, baseline_commit=None, *, transport=None, metadata_transport=None, update=lambda stage: None):
    artifacts = scan_directory / "artifacts"
    report = {"scan_id": scan_directory.name, "status": "running", "started_at": timestamp(),
              "baseline_commit": baseline_commit, "errors": [], "warnings": [], "findings": [],
              "reachability_status": "not_analyzed", "priority_status": "not_assessed",
              "tool_version": DETECTION_VERSION, "github_cross_check": "not_configured"}
    store = None
    token = SCAN_DEADLINE.set(time.monotonic() + 180)
    try:
        update("Validating Phase 1 artifacts")
        inventory = Inventory.model_validate(read_json(artifacts, "components.json")[0])
        graph = read_json(artifacts, "dependency_graph.json")[0]
        phase1 = read_json(artifacts, "discovery_report.json")[0]
        commit = phase1["repository"]["commit"]
        if not inventory.repository_id:
            inventory.repository_id = stable_id("repository", phase1["repository"].get("url", scan_directory.name).removesuffix(".git").rstrip("/").casefold())
        if not inventory.projects:
            components = {component.id: component for component in inventory.components}
            for root_id in inventory.roots:
                root = components.get(root_id)
                if root and root.kind == "application":
                    inventory.projects.append(Project(id=stable_id("project", inventory.repository_id, root.path, root.ecosystem),
                        repository_id=inventory.repository_id, name=root.name, path=root.path, ecosystem=root.ecosystem,
                        root_id=root.id, completeness_status="partial", coverage_status="partial"))
        report["repository_commit"] = commit
        report["phase1_coverage"] = phase1.get("coverage_status", "unknown")
        node_ids = {node["id"] for node in graph["nodes"]}
        if node_ids != {component.id for component in inventory.components}:
            raise ValueError("Phase 1 inventory and graph node sets disagree")
        if any(edge["parent"] not in node_ids or edge["child"] not in node_ids or edge.get("status") != "resolved" for edge in graph["edges"]):
            raise ValueError("Invalid Phase 1 resolved graph edges")
        sources = list((scan_directory / "workspaces").glob("repo-*/source"))
        repo = sources[0] if len(sources) == 1 and not sources[0].is_symlink() else None
        store = EvidenceStore(artifacts / "evidence", commit)

        def vulnerabilities():
            with OSVClient(scan_directory.parent / "osv-cache", store, transport=transport) as client:
                result = detect_vulnerabilities(inventory, graph, repo or scan_directory / "source-unavailable", store, client,
                    scan_directory.name, commit, phase1_dependency_status=phase1.get("dependency_status"))
                result["client"] = {"version": "guardian-osv/0.2.0", "requests": client.request_count,
                                    "cache_hits": client.cache_hits, "cache_ttl_seconds": 3600, "api": "https://api.osv.dev/v1"}
                return result

        def changes():
            if repo is None:
                return {"status": "partial", "comparison_status": "comparison_unavailable", "findings": [], "inspections": [],
                    "errors": [], "warnings": ["Original repository workspace is unavailable; source/change inspection was skipped"]}
            return detect_changes(repo, inventory, graph, store, scan_directory.name, commit, baseline_commit)

        def signals():
            if repo is None:
                return {"status": "partial", "policy_status": "not_run", "findings": [], "inspections": [],
                        "errors": [], "warnings": ["Repository workspace unavailable; static signals and policies were not evaluated"]}
            return detect_signals(repo, inventory, graph, store, scan_directory.name, commit, transport=metadata_transport)

        update("Querying OSV and inspecting repository evidence")
        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="guardian-detection") as executor:
            futures = {"vulnerabilities": executor.submit(copy_context().run, vulnerabilities),
                       "suspicious_changes": executor.submit(copy_context().run, changes),
                       "static_signals": executor.submit(copy_context().run, signals)}
            results = {}
            for name, future in futures.items():
                try:
                    results[name] = future.result()
                except Exception as exc:
                    results[name] = {"status": "failed", "findings": [], "errors": [str(exc)[:2000]], "warnings": [], "inspections": []}
        for name, result in results.items():
            write_json(artifacts / (name + ".json"), result)
            report[name] = {key: value for key, value in result.items() if key not in {"findings", "decisions", "query_results"}}
            report["errors"].extend(f"{name}: {error}" for error in result.get("errors", []))
            report["warnings"].extend(result.get("warnings", []))
            report["findings"].extend(result["findings"])
        findings = [Finding.model_validate(finding) for finding in report["findings"]]
        store.validate(findings)
        store.save()
        report["evidence_count"] = len(store.records)
        report["verified_vulnerabilities"] = sum(f.finding_type == "vulnerability" and f.advisory_category != "malicious_package" and f.verification_status == "verified_match" for f in findings)
        report["verified_malicious_packages"] = sum(f.advisory_category == "malicious_package" and f.verification_status == "verified_match" for f in findings)
        report["change_signals"] = sum(f.finding_type == "suspicious_change" for f in findings)
        report["review_signals"] = sum(f.finding_type != "vulnerability" for f in findings)
        report["policy_status"] = results["static_signals"].get("policy_status", "not_run")
        report["policy_violations"] = sum(f.finding_type == "policy_violation" for f in findings)
        report["coverage_status"] = "verified_scoped" if all(result["status"] == "completed" for result in results.values()) and phase1.get("coverage_status") == "verified" else "partial"
        report["status"] = "failed" if all(result["status"] == "failed" for result in results.values()) else "partial" if report["coverage_status"] == "partial" else "completed"
        report["limitations"] = ["Exact npm package versions only; declared constraints are not treated as installed versions.",
            "A verified advisory match does not establish runtime code-path reachability.",
            "No priority/risk scoring, remediation, GitHub publishing, or LLM calls.",
            "GitHub cross-check is optional and not enabled; OSV/GitHub provenance is not independent.",
            "Shallow clones may not contain a supplied baseline; unavailable comparisons never create change claims."]
    except Exception as exc:
        report.update(status="failed", coverage_status="unknown")
        report["errors"].append(str(exc)[:3000])
    finally:
        if store is not None:
            store.save()
        SCAN_DEADLINE.reset(token)
    report["finished_at"] = timestamp()
    write_json(artifacts / "detection_report.json", report)
    write_json(artifacts / "detection_status.json", {"scan_id": scan_directory.name, "status": report["status"],
        "stage": "Detection finished", "finished_at": report["finished_at"]})
    return report


def main():
    parser = argparse.ArgumentParser(description="Run evidence-backed Phase 2 on an existing Guardian scan")
    parser.add_argument("--scan-dir", type=Path, required=True)
    parser.add_argument("--baseline", default=None)
    args = parser.parse_args()
    report = run_detection(args.scan_dir.resolve(), args.baseline)
    print(json.dumps({key: report.get(key) for key in ["status", "verified_vulnerabilities", "change_signals", "evidence_count", "errors", "warnings"]}, indent=2))
    raise SystemExit(1 if report["status"] == "failed" else 0)


if __name__ == "__main__":
    main()
