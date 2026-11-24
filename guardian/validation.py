"""Rebuild and rescan explicitly approved patches without changing source checkouts."""
import json
import os
import re
import shutil
import tempfile
import time
import uuid
from pathlib import Path

from .evidence import timestamp
from .files import read_json, safe_file, write_json
from .models import Repository
from .phase2 import run_detection
from .pipeline import analyze_repository
from .process import SCAN_CANCEL_CHECK, SCAN_DEADLINE, run_tool
from .remediation import digest, npm_operation, reviews, snapshot, source, verify_plan


def component_set(document):
    return {f"{c['ecosystem']}:{c['name']}@{c['version']}" for c in document.get("components", []) if c.get("kind") == "package" and c.get("version")}


def sbom_set(document):
    return {c.get("purl") or f"{c.get('name')}@{c.get('version')}" for c in document.get("components", [])}


def difference(before, after):
    return {"removed": sorted(before - after), "added": sorted(after - before), "unchanged_count": len(before & after)}


def finding_comparison(before, after, before_inventory, after_inventory):
    def entries(findings, inventory):
        names = {c["id"]: c["name"] for c in inventory["components"]}
        result = []
        for finding in findings:
            labels = set(finding.get("advisory_ids", []) + finding.get("aliases", []))
            for identifier in finding["component_instance_ids"] or ["repository"]:
                result.append({"finding_id": finding["finding_id"], "name": names.get(identifier, identifier),
                    "type": finding["finding_type"], "rule": finding.get("rule_id"), "advisories": sorted(labels)})
        return result
    old, new = entries(before, before_inventory), entries(after, after_inventory)
    def matches(left, right):
        return left["name"] == right["name"] and left["type"] == right["type"] and (
            bool(set(left["advisories"]) & set(right["advisories"])) if left["advisories"] else left["rule"] == right["rule"])
    return {"resolved": [f for f in old if not any(matches(f, other) for other in new)],
            "remaining": [f for f in old if any(matches(f, other) for other in new)],
            "introduced": [f for f in new if not any(matches(f, other) for other in old)]}


def container_tests(repo, *, requested):
    if not requested:
        return {"status": "not_run", "reason": "Build and tests were not requested"}
    image = os.environ.get("GUARDIAN_TEST_IMAGE", "")
    if not shutil.which("docker") or not re.fullmatch(r"(?:[A-Za-z0-9._:/-]+@)?sha256:[0-9a-f]{64}", image):
        return {"status": "not_run", "reason": "Docker and a preloaded digest-pinned GUARDIAN_TEST_IMAGE are required"}
    scripts = read_json(repo, "package.json")[0].get("scripts", {})
    commands = [name for name in ("build", "test") if isinstance(scripts.get(name), str)]
    if not commands:
        return {"status": "not_run", "reason": "No build or test script is declared"}
    name = "guardian-test-" + uuid.uuid4().hex
    driver = 'cp -R /source/. /work/ && cd /work && ' + " && ".join("npm run " + command + " --ignore-scripts" for command in commands)
    try:
        completed = run_tool(["docker", "run", "--rm", "--name", name, "--pull=never", "--network=none",
            "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=64",
            "--memory=512m", "--cpus=1", "--user=65534:65534", "--tmpfs=/work:rw,exec,size=256m,mode=1777",
            "--tmpfs=/tmp:rw,noexec,size=64m,mode=1777", "--mount", f"type=bind,src={repo.resolve()},dst=/source,readonly",
            "--env=HOME=/tmp", "--env=NPM_CONFIG_CACHE=/tmp/npm-cache", "--entrypoint=sh", image, "-c", driver], repo, timeout=90, check=False)
        return {"status": "passed" if completed.returncode == 0 else "failed", "commands": commands,
                "image": image, "network": "none", "stdout_sha256": digest(completed.stdout.encode()),
                "stderr_sha256": digest(completed.stderr.encode()), "exit_code": completed.returncode}
    finally:
        # A killed CLI does not necessarily stop its Docker daemon container.
        cancellation = SCAN_CANCEL_CHECK.set(lambda: None)
        deadline = SCAN_DEADLINE.set(None)
        try:
            run_tool(["docker", "rm", "-f", name], repo, timeout=10, check=False)
        except RuntimeError:
            pass
        finally:
            SCAN_DEADLINE.reset(deadline)
            SCAN_CANCEL_CHECK.reset(cancellation)


def run_validation(scan, store, *, osv_transport=None, metadata_transport=None, run_tests=False, update=lambda stage: None):
    artifacts = scan / "artifacts"
    report = {"scan_id": scan.name, "status": "running", "started_at": timestamp(), "results": [], "errors": [],
              "mode": "independent_proposals", "original_checkout_modified": False}
    deadline = SCAN_DEADLINE.set(time.monotonic() + 420)
    try:
        plan = verify_plan(scan)
        decisions = reviews(store, scan.name)
        pending = [p["id"] for p in plan["proposals"] if p["id"] not in decisions]
        if pending:
            raise ValueError("Every proposed diff requires approve, reject, or accepted-risk review before validation")
        report.update(repository_commit=plan["repository_commit"], plan_sha256=digest(plan),
                      audit=[decisions[p["id"]] for p in plan["proposals"]], ai=plan.get("ai"), ai_usage=plan.get("ai_usage"),
                      manual_recommendations=[r for r in plan["recommendations"] if r["status"] == "manual_review"])
        report["analysis_ai"] = read_json(artifacts, "analysis_report.json")[0].get("ai")
        with store.connection() as db:
            row = db.execute("SELECT requests FROM ai_scan WHERE scan_id=?", (scan.name,)).fetchone()
        report["ai_scan_requests_total"] = row[0] if row else 0
        before_inventory = read_json(artifacts, "components.json")[0]
        before = read_json(artifacts, "detection_report.json")[0]
        repo = source(scan)
        files = snapshot(repo)
        for proposal in plan["proposals"]:
            SCAN_CANCEL_CHECK.get()()
            decision = decisions[proposal["id"]]
            result = {"proposal_id": proposal["id"], "patch_digest": proposal["digest"], "status": "not_run",
                      "decision": decision["decision"], "tests": {"status": "not_run"}, "errors": []}
            report["results"].append(result)
            if decision["digest"] != proposal["digest"]:
                raise ValueError("Review digest does not match proposed patch")
            if decision["decision"] != "approve":
                result["reason"] = "Rejected or accepted risk; no fix applied or claimed"
                continue
            result_id = uuid.uuid4().hex
            saved = artifacts / "validation" / result_id
            saved.mkdir(parents=True)
            result["artifacts_directory"] = f"validation/{result_id}"
            try:
                with tempfile.TemporaryDirectory(prefix="guardian-validation-") as directory:
                    temporary_scan = Path(directory) / scan.name
                    copy = temporary_scan / "workspaces/repo-validation/source"
                    copy.mkdir(parents=True)
                    for relative, checksum in files.items():
                        raw = safe_file(repo, relative).read_bytes()
                        if digest(raw) != checksum:
                            raise ValueError("Source changed during validation")
                        target = copy / relative
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(raw)
                    for original in proposal["before"]:
                        if digest(safe_file(copy, original).read_bytes()) != proposal["before"][original]:
                            raise ValueError("Original file does not match approved patch")
                        name = Path(original).name
                        new = safe_file(artifacts, f"remediation/proposals/{proposal['id']}/{name}").read_bytes()
                        if digest(new) != proposal["after"][original]:
                            raise ValueError("Patch bytes do not match approval")
                        (copy / original).write_bytes(new)
                    update(f"Rebuilding approved patch for {proposal['name']} with scripts disabled")
                    project = copy / Path(proposal["manifest_path"]).parent
                    approved_snapshot = snapshot(copy)
                    result["rebuild"] = npm_operation(project, ["ci"])
                    result["rebuild"]["status"] = "passed"
                    # Installed package contents are never scanned as repository source.
                    result["tests"] = container_tests(project, requested=run_tests)
                    shutil.rmtree(project / "node_modules", ignore_errors=True)
                    if snapshot(copy) != approved_snapshot:
                        raise ValueError("Rebuild changed the approved source snapshot")
                    update("Regenerating SBOM and rescanning the patched snapshot")
                    derived = Repository(url="fixture://approved-derived-snapshot", commit=plan["repository_commit"], path=str(copy))
                    discovery = analyze_repository(derived, saved, update)
                    # Detection expects artifacts next to workspaces. Keep its raw evidence permanently.
                    (temporary_scan / "artifacts").symlink_to(saved.resolve(), target_is_directory=True)
                    after = run_detection(temporary_scan, transport=osv_transport, metadata_transport=metadata_transport, update=update)
                    after_inventory = read_json(saved, "components.json")[0]
                    result["dependency_diff"] = difference(component_set(before_inventory), component_set(after_inventory))
                    result["finding_diff"] = finding_comparison(before["findings"], after["findings"], before_inventory, after_inventory)
                    result["rescan"] = {"status": after["status"], "coverage_status": after.get("coverage_status"),
                        "vulnerabilities": after.get("vulnerabilities"), "policy_status": after.get("policy_status"),
                        "source": "Derived temporary snapshot; repository_commit identifies the original base, not a new Git commit"}
                    baseline_discovery = read_json(artifacts, "discovery_report.json")[0]
                    if baseline_discovery.get("sbom", {}).get("status") == "completed" and discovery.get("sbom", {}).get("status") == "completed":
                        result["sbom_diff"] = {"status": "completed", **difference(sbom_set(read_json(artifacts, "sbom.json")[0]), sbom_set(read_json(saved, "sbom.json")[0]))}
                    else:
                        result["sbom_diff"] = {"status": "not_run", "reason": "Both validated Syft SBOMs are required"}
                    differences = result["finding_diff"]
                    target_remaining = any(f["type"] == "vulnerability" and f["name"] == proposal["name"] for f in differences["remaining"])
                    new_vulnerabilities = any(f["type"] == "vulnerability" for f in differences["introduced"])
                    exact_complete = after.get("vulnerabilities", {}).get("status") == "completed"
                    result["dependency_verification"] = "passed" if exact_complete and not target_remaining and not new_vulnerabilities else "failed" if target_remaining or new_vulnerabilities else "partial"
                    result["status"] = ("failed" if result["dependency_verification"] == "failed" or result["tests"]["status"] == "failed" or after["status"] == "failed"
                        else "passed" if result["dependency_verification"] == "passed" and result["tests"]["status"] == "passed" and result["sbom_diff"]["status"] == "completed" and after["status"] == "completed"
                        else "partial")
            except Exception as exc:
                SCAN_CANCEL_CHECK.get()()
                result.update(status="failed")
                result["errors"].append(str(exc)[:1500])
            write_json(saved / "validation_result.json", result)
        if digest(snapshot(repo)) != plan["source_sha256"]:
            raise ValueError("Original source changed during validation")
        statuses = {r["status"] for r in report["results"]}
        report["status"] = "failed" if "failed" in statuses else "not_run" if not statuses or statuses == {"not_run"} else "passed" if statuses == {"passed"} and not report["manual_recommendations"] else "partial"
        report["limitations"] = ["Each patch is validated independently against the original snapshot; results are not a combined fixed checkout.",
            "Risk acceptance and rejection do not resolve findings. Missing Docker tests, baseline comparison, or coverage leaves verification partial.",
            "Package installation uses temporary directories, fixed registry and disabled scripts; host npm is not an OS sandbox."]
    except Exception as exc:
        SCAN_CANCEL_CHECK.get()()
        report.update(status="failed")
        report["errors"].append(str(exc)[:1500])
    finally:
        SCAN_DEADLINE.reset(deadline)
    report["finished_at"] = timestamp()
    write_json(artifacts / "validation_report.json", report)
    write_json(artifacts / "verified_report.json", {**report, "verification_status": report["status"], "fully_verified": report["status"] == "passed"})
    write_json(artifacts / "validation_status.json", {"status": report["status"], "stage": "Validation finished"})
    return report
