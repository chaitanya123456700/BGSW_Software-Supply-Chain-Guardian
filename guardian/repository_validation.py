"""Apply reviewed dependency files to a local checkout and rescan its resolved tree."""
import json
import shutil
import time
import uuid
from pathlib import Path

from .evidence import timestamp
from .files import read_json, safe_file, write_json
from .models import Repository
from .phase2 import run_detection
from .pipeline import analyze_repository
from .process import SCAN_DEADLINE
from .remediation import checkout_target, digest, npm_operation, snapshot
from .remediation_preview import apply_selection
from .validation import container_tests, finding_comparison


def vulnerability_count(report):
    return sum(item["finding_type"] == "vulnerability" for item in report.get("findings", []))


def resolved_coverage(discovery, detection, inventory, graph):
    advisory = detection.get("vulnerabilities", {})
    projects = inventory.get("projects", [])
    packages = [item for item in inventory.get("components", []) if item.get("kind") == "package"]
    return (bool(projects) and discovery.get("status") != "failed"
            and all(item.get("ecosystem") == "npm" and item.get("completeness_status") in {"verified", "verified_empty"} for item in projects)
            and all(item.get("version") and item.get("resolution_status") == "resolved" for item in packages)
            and graph.get("statistics", {}).get("unresolved_edges") == 0
            and advisory.get("status") == "completed" and not advisory.get("errors") and not advisory.get("skipped_components")
            and advisory.get("completed_package_versions") == advisory.get("queried_package_versions")
            and (not packages or advisory.get("queried_package_versions", 0) > 0))


def run_repository_validation(scan, selection_digest, selected, receipt, *, run_tests=False,
                              osv_transport=None, metadata_transport=None, update=lambda message: None):
    artifacts = scan / "artifacts"
    report = {"scan_id": scan.name, "status": "running", "started_at": timestamp(), "applied": False,
              "scope": "known_vulnerabilities_in_resolved_npm_tree", "errors": [], "checks": {}, "tests": [],
              "limitations": "Zero matches applies only to the completed advisory-query scope. It is not proof of no undiscovered vulnerabilities."}
    token = SCAN_DEADLINE.set(time.monotonic() + 420)
    child = None
    try:
        update("Checking reviewed draft and pinned source")
        selection, _ = apply_selection(scan, selection_digest, selected)
        if not selected or selection["validation"].get("receipt_sha256") != receipt:
            raise ValueError("Review and apply the current exact draft before updating the repository")
        report["receipt_sha256"] = receipt
        report["selected"] = selected
        origin, repo = checkout_target(scan)
        report["origin_scan_id"] = origin.name
        report["repository_path"] = str(repo.resolve())
        original = snapshot(repo)
        if digest(original) != selection["validation"]["source_sha256"]:
            raise ValueError("The actual checkout changed since this scan; rescan it before applying more fixes")
        before_inventory = read_json(artifacts, "components.json")[0]
        before_detection = read_json(artifacts, "detection_report.json")[0]
        before_discovery = read_json(artifacts, "discovery_report.json")[0]
        report["before_vulnerabilities"] = vulnerability_count(before_detection)
        child = scan.parent / uuid.uuid4().hex
        staged = child / "workspaces/repo-remediated/source"
        staged.mkdir(parents=True)
        child_artifacts = child / "artifacts"
        child_artifacts.mkdir()
        for relative, checksum in original.items():
            raw = safe_file(repo, relative).read_bytes()
            if digest(raw) != checksum:
                raise ValueError("Source changed while preparing remediation")
            destination = staged / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
        for item in selection["files"]:
            safe_file(staged, item["path"]).write_text(item["content"], encoding="utf-8")
        manifests = sorted({item["path"] for item in selection["files"] if Path(item["path"]).name == "package.json"})
        for manifest in manifests:
            project = staged / Path(manifest).parent
            update(f"Regenerating {Path(manifest).parent / 'package-lock.json'} with scripts disabled")
            # Offline resolution keeps unreviewed package metadata from introducing new fetch references.
            npm_operation(project, ["install", "--package-lock-only", "--offline"])
            approved = snapshot(staged)
            update(f"Rebuilding {manifest} with scripts disabled")
            npm_operation(project, ["ci"])
            report["tests"].append({"manifest": manifest, **container_tests(project, requested=run_tests)})
            shutil.rmtree(project / "node_modules", ignore_errors=True)
            if snapshot(staged) != approved:
                raise ValueError("Rebuild or tests changed reviewed dependency files")
        report["checks"].update(lockfile="passed", rebuild="passed")
        expected_files = {item["path"] for item in selection["files"]} | {
            (Path(manifest).parent / "package-lock.json").as_posix() for manifest in manifests}
        staged_files = snapshot(staged)
        changed = {name for name in original.keys() | staged_files.keys() if original.get(name) != staged_files.get(name)}
        if not changed <= expected_files:
            raise ValueError("Resolver changed files outside the reviewed manifests and lockfiles")
        for manifest in manifests:
            value = read_json(staged, manifest)[0]
            exported = next(item for item in selection["files"] if item["path"] == manifest)
            if value != json.loads(exported["content"]):
                raise ValueError("Resolver changed the selected manifest edits")
        update("Rescanning every resolved dependency, including transitive packages")
        repository = Repository(url=before_discovery["repository"].get("url", "fixture://local-remediated-checkout"),
                                commit=before_discovery["repository"]["commit"], path=str(staged))
        discovery = analyze_repository(repository, child_artifacts, update)
        after = run_detection(child, transport=osv_transport, metadata_transport=metadata_transport, update=update)
        inventory = read_json(child_artifacts, "components.json")[0]
        graph = read_json(child_artifacts, "dependency_graph.json")[0]
        report["finding_diff"] = finding_comparison(before_detection["findings"], after["findings"], before_inventory, inventory)
        report["remaining_vulnerabilities"] = vulnerability_count(after)
        coverage = resolved_coverage(discovery, after, inventory, graph)
        report["checks"]["advisory_coverage"] = "passed" if coverage else "incomplete"
        report["checks"]["zero_vulnerabilities"] = "passed" if report["remaining_vulnerabilities"] == 0 and coverage else "failed" if report["remaining_vulnerabilities"] else "incomplete"
        report["advisory_queries"] = after.get("vulnerabilities", {})
        if discovery.get("status") == "failed" or after.get("status") == "failed":
            raise ValueError("The updated repository could not be rescanned; original checkout was not changed")
        if digest(snapshot(repo)) != digest(original):
            raise ValueError("Local checkout changed during validation; no remediation was written")
        backup = artifacts / "repository-backup" / child.name
        backup.mkdir(parents=True)
        before_bytes = {name: safe_file(repo, name).read_bytes() if name in original else None for name in changed}
        for name, raw in before_bytes.items():
            if raw is not None:
                saved = backup / name
                saved.parent.mkdir(parents=True, exist_ok=True)
                saved.write_bytes(raw)
        write_json(backup / "backup-index.json", {"before": {name: digest(raw) if raw is not None else None for name, raw in before_bytes.items()},
                   "after": {name: staged_files[name] for name in changed}})
        update("Writing selected changes and regenerated lockfiles to the local repository")
        written, temporary_files = [], []
        try:
            for name in sorted(changed):
                target = safe_file(repo, name) if name in original else safe_file(repo, (Path(name).parent / "package.json").as_posix()).parent / "package-lock.json"
                if target.is_symlink():
                    raise ValueError("Repository target became a symlink")
                temporary = target.with_name(target.name + ".guardian-tmp")
                if temporary.exists() or temporary.is_symlink():
                    raise ValueError("A pending repository write already exists")
                with temporary.open("xb") as handle:
                    temporary_files.append(temporary)
                    handle.write(safe_file(staged, name).read_bytes())
                if target.exists():
                    temporary.chmod(target.stat().st_mode & 0o777)
                temporary.replace(target)
                written.append(name)
            if snapshot(repo) != staged_files:
                raise ValueError("Applied checkout does not match the rescanned snapshot")
        except Exception:
            for name in reversed(written):
                target = repo / name
                if before_bytes[name] is None:
                    target.unlink()
                else:
                    target.write_bytes(before_bytes[name])
            raise
        finally:
            for temporary in temporary_files:
                temporary.unlink(missing_ok=True)
        report.update(applied=True, after_scan_id=child.name, changed_files=sorted(changed),
                      before_sha256=digest(original), after_sha256=digest(staged_files), backup_directory=str(backup.resolve()))
        report["checks"]["applied_snapshot"] = "passed"
        tests_failed = any(item["status"] == "failed" for item in report["tests"])
        tests_missing = run_tests and any(item["status"] != "passed" for item in report["tests"])
        report["status"] = "failed" if report["remaining_vulnerabilities"] or tests_failed else "incomplete" if not coverage or tests_missing else "passed"
        report["fully_verified"] = (report["status"] == "passed" and run_tests and not tests_missing
                                    and discovery.get("status") == "completed" and after.get("status") == "completed")
        report["derived_source"] = {"base_commit": repository.commit, "modified_local_checkout": True, "source_sha256": report["after_sha256"]}
        write_json(child / "checkout-target.json", {"origin_scan_id": origin.name})
        write_json(child / "status.json", {"scan_id": child.name, "repo_url": repository.url, "status": "completed",
                   "commit": repository.commit, "stage": "Remediated local checkout rescanned", "finished_at": timestamp(),
                   "modified_local_checkout": True, "parent_scan_id": scan.name})
    except Exception as exc:
        report["status"] = "failed"
        report["errors"].append(str(exc)[:2000])
    finally:
        SCAN_DEADLINE.reset(token)
    report["finished_at"] = timestamp()
    write_json(artifacts / "repository_validation_report.json", report)
    if report.get("after_scan_id"):
        write_json(child / "artifacts/repository_validation_report.json", report)
        write_json(child / "artifacts/repository_validation_status.json", {"status": report["status"], "stage": "Repository validation finished", "report": report})
    return report
