"""Deterministic npm patch proposals, bound to source bytes and explicit reviews."""
import difflib
import hashlib
import json
import re
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import unquote, urlsplit

from semantic_version import NpmSpec, Version

from .ai import AIConfig, AIGateway
from .analysis import ai_fact
from .evidence import EvidenceStore, timestamp
from .files import read_json, safe_file, walk_files, write_json
from .metadata import MetadataClient
from .models import Finding, Inventory
from .npm import NAME
from .osv import OSVClient
from .process import SCAN_CANCEL_CHECK, SCAN_DEADLINE, run_tool

REMEDIATION_VERSION = "guardian-remediation/0.5.0"
FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def source(scan):
    sources = list((scan / "workspaces").glob("repo-*/source"))
    if len(sources) != 1 or sources[0].is_symlink():
        raise ValueError("One pinned repository source is required")
    return sources[0]


def snapshot(repo):
    # Secrets and tool configuration are never copied into a validation workspace.
    files = {}
    for path in walk_files(repo):
        relative = path.relative_to(repo).as_posix()
        if any(part.startswith(".env") or part in {".npmrc", ".yarnrc", ".yarnrc.yml", ".netrc", ".pypirc", ".aws", ".ssh"} for part in path.relative_to(repo).parts):
            continue
        files[relative] = digest(safe_file(repo, relative).read_bytes())
    return files


def registry_reference(value):
    if not isinstance(value, str) or len(value) > 500 or not value.strip():
        raise ValueError("Missing registry version constraint")
    try:
        NpmSpec(value)
    except ValueError as exc:
        raise ValueError("Automatic patches refuse non-registry references, aliases, tags, and unsupported constraints") from exc


def registry_url(value):
    if not isinstance(value, str):
        raise ValueError("Invalid lockfile URL")
    url = urlsplit(value)
    if (url.scheme != "https" or url.hostname != "registry.npmjs.org" or url.username or url.password
            or url.port not in {None, 443} or url.query or url.fragment or "\\" in value
            or any(part in {".", ".."} for part in unquote(url.path).split("/"))):
        raise ValueError("Only fixed public npm registry URLs are allowed")


def preflight(manifest, lock):
    """Reject every supported fetch-bearing field before any npm invocation."""
    if manifest.get("workspaces") or manifest.get("overrides") or manifest.get("resolutions"):
        raise ValueError("Workspaces, overrides, and resolutions require manual remediation")
    if lock.get("lockfileVersion") not in {2, 3} or not isinstance(lock.get("packages"), dict):
        raise ValueError("Automatic patches require npm package-lock v2/v3")
    for document in [manifest, *lock["packages"].values()]:
        if not isinstance(document, dict) or document.get("link") or document.get("workspaces"):
            raise ValueError("Linked or malformed lockfile package")
        for field in FIELDS:
            values = document.get(field, {})
            if not isinstance(values, dict):
                raise ValueError("Malformed dependency declarations")
            for name, constraint in values.items():
                if not NAME.fullmatch(name):
                    raise ValueError("Invalid package name")
                registry_reference(constraint)
        if document.get("resolved") is not None:
            registry_url(document["resolved"])
    for path, record in lock["packages"].items():
        if path == "":
            continue
        if not isinstance(path, str) or not re.fullmatch(r"(?:node_modules/(?:@[a-z0-9._-]+/)?[a-z0-9._-]+)(?:/node_modules/(?:@[a-z0-9._-]+/)?[a-z0-9._-]+)*", path):
            raise ValueError("Unsupported lockfile package path")
        Version(record.get("version", ""))
    def legacy(entries):
        if not isinstance(entries, dict):
            raise ValueError("Malformed legacy lock entries")
        for record in entries.values():
            if not isinstance(record, dict) or record.get("link"):
                raise ValueError("Unsupported legacy lock entry")
            Version(record.get("version", ""))
            if "resolved" in record:
                registry_url(record["resolved"])
            for value in record.get("requires", {}).values():
                registry_reference(value)
            legacy(record.get("dependencies", {}))
    legacy(lock.get("dependencies", {}))


def npm_operation(project, operation):
    manifest, _ = read_json(project, "package.json")
    lock, _ = read_json(project, "package-lock.json")
    preflight(manifest, lock)
    if operation == ["ci"]:
        for path, record in lock["packages"].items():
            if path and (not record.get("resolved") or not re.fullmatch(r"sha(?:1|256|384|512)-[A-Za-z0-9+/]+={0,2}", record.get("integrity", ""))):
                raise ValueError("Rebuild requires registry URLs and integrity hashes for every locked package")
    with tempfile.TemporaryDirectory(prefix="guardian-npm-config-") as directory:
        config = Path(directory)
        for name in ("user", "global"):
            (config / name).write_text("")
        args = ["npm", *operation, "--ignore-scripts", "--no-audit", "--no-fund", "--workspaces=false",
                "--registry=https://registry.npmjs.org", f"--userconfig={config / 'user'}",
                f"--globalconfig={config / 'global'}", f"--cache={config / 'cache'}", "--fetch-retries=0",
                "--fetch-timeout=15000", "--update-notifier=false", "--progress=false"]
        result = run_tool(args, project, timeout=90, monitor=project,
                          extra_env={"NPM_CONFIG_IGNORE_SCRIPTS": "true", "NPM_CONFIG_REGISTRY": "https://registry.npmjs.org"})
    preflight(read_json(project, "package.json")[0], read_json(project, "package-lock.json")[0])
    return {"command": [a for a in args if not a.startswith(("--cache=", "--userconfig=", "--globalconfig="))],
            "exit_code": result.returncode, "stdout_sha256": digest(result.stdout.encode()),
            "isolation": "temporary directory, clean environment, empty npm configs; no host OS network sandbox"}


def fixed_versions(records, name):
    versions = set()
    for record in records:
        for affected in record.get("affected", []):
            if affected.get("package", {}).get("ecosystem") != "npm" or affected.get("package", {}).get("name") != name:
                continue
            for item in affected.get("ranges", []):
                if item.get("type") not in {"SEMVER", "ECOSYSTEM"}:
                    continue
                for event in item.get("events", []):
                    try:
                        value = Version(event["fixed"])
                        if not value.prerelease:
                            versions.add(value)
                    except (ValueError, KeyError, TypeError):
                        continue
    return versions


def candidate(component, findings, constraints, osv, metadata):
    records = [s for finding in findings for s in finding["source_metadata"] if "affected" in s]
    pending, checked, proofs = fixed_versions(records, component.name), set(), []
    for _ in range(5):
        choices = [v for v in pending - checked if v > Version(component.version)]
        if not choices:
            break
        version = min(choices, key=lambda v: (not all(NpmSpec(c).match(v) for c in constraints), v))
        checked.add(version)
        details, registry_proof = metadata.version("registry.npmjs.org", component.name, str(version))
        proofs.append(registry_proof)
        if details.get("deprecated"):
            continue
        response = osv.query_batch([{"package": {"ecosystem": "npm", "name": component.name}, "version": str(version)}])[0]
        proofs.extend(response["evidence_ids"])
        if not response["complete"] or response["error"]:
            raise ValueError("Candidate OSV query is incomplete; no patch can be proposed")
        active = []
        for identifier in response["advisories"]:
            record, proof = osv.advisory(identifier)
            proofs.append(proof)
            if not record.get("withdrawn"):
                active.append(record)
        if not active:
            return str(version), list(dict.fromkeys(proofs)), details
        pending |= fixed_versions(active, component.name)
    raise ValueError("No published, non-deprecated candidate with a complete no-match OSV result was found within five checks")


def verify_plan(scan):
    artifacts = scan / "artifacts"
    plan = read_json(artifacts, "remediation_report.json")[0]
    if plan.get("status") not in {"completed", "partial"}:
        raise ValueError("A usable remediation plan is required")
    if plan["analysis_sha256"] != digest(safe_file(artifacts, "analysis_report.json").read_bytes()):
        raise ValueError("Analysis changed; prepare a new remediation plan")
    analysis = read_json(artifacts, "analysis_report.json")[0]
    if analysis["detection_sha256"] != digest(safe_file(artifacts, "detection_report.json").read_bytes()):
        raise ValueError("Detection changed; rerun analysis and remediation")
    if plan["source_sha256"] != digest(snapshot(source(scan))):
        raise ValueError("Source changed; prepare a new remediation plan")
    records = read_json(artifacts, "remediation/evidence/index.json")[0]
    for record in records.values():
        if digest(safe_file(artifacts / "remediation/evidence", Path(record["raw_artifact"]).name).read_bytes()) != record["sha256"]:
            raise ValueError("Candidate evidence changed")
    for proposal in plan["proposals"]:
        expected = proposal["digest"]
        if digest({k: v for k, v in proposal.items() if k != "digest"}) != expected:
            raise ValueError("Proposal metadata changed")
        for relative, checksum in proposal["artifacts"].items():
            if digest(safe_file(artifacts, relative).read_bytes()) != checksum:
                raise ValueError("Proposal bytes changed; approval is invalid")
        if any(identifier not in records for identifier in proposal["evidence_ids"]):
            raise ValueError("Candidate evidence is missing")
    return plan


def reviews(store, scan_id):
    with store.connection() as db:
        rows = db.execute("SELECT proposal_id, review FROM remediation_reviews WHERE scan_id=?", (scan_id,)).fetchall()
    return {key: json.loads(value) for key, value in rows}


def review_plan(scan, store, proposal_id, *, proposal_digest, decision, reviewed_diff=False, reason=""):
    plan = verify_plan(scan)
    proposal = next((p for p in plan["proposals"] if p["id"] == proposal_id), None)
    if not proposal or proposal["digest"] != proposal_digest:
        raise ValueError("Exact proposal digest is required")
    if decision not in {"approve", "reject", "accepted_risk"} or decision == "approve" and not reviewed_diff:
        raise ValueError("Approval requires explicit confirmation that the exact diff was reviewed")
    if decision == "accepted_risk" and not reason.strip():
        raise ValueError("Accepted risk requires a reason")
    record = {"proposal_id": proposal_id, "digest": proposal_digest, "decision": decision,
              "reason": reason[:2000], "reviewed_diff": reviewed_diff, "at": timestamp(), "via": "explicit_local_api"}
    with store.connection() as db:
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT 1 FROM remediation_reviews WHERE scan_id=? AND proposal_id=?", (scan.name, proposal_id)).fetchone():
            raise ValueError("Review is immutable; prepare a new plan to reconsider")
        db.execute("INSERT INTO remediation_reviews VALUES (?, ?, ?)", (scan.name, proposal_id, json.dumps(record)))
    return record


def remediation_facts(analysis, recommendations):
    facts = []
    for finding in analysis["findings"][:10]:
        options = sorted({option for item in recommendations if finding["finding_id"] in item["finding_ids"] for option in item["options"]})
        if options:
            facts.append({**ai_fact(finding), "options": options})
    return facts


def run_remediation(scan, store, *, osv_transport=None, metadata_transport=None, config=None, ai_transport=None, update=lambda stage: None):
    artifacts = scan / "artifacts"
    report = {"scan_id": scan.name, "status": "running", "tool_version": REMEDIATION_VERSION,
              "started_at": timestamp(), "proposals": [], "recommendations": [], "errors": []}
    deadline = SCAN_DEADLINE.set(time.monotonic() + 240)
    evidence = EvidenceStore(artifacts / "remediation/evidence", "unknown")
    try:
        update("Checking analysis and original source hashes")
        analysis = read_json(artifacts, "analysis_report.json")[0]
        detection = read_json(artifacts, "detection_report.json")[0]
        if analysis.get("status") not in {"completed", "partial"} or analysis["detection_sha256"] != digest(safe_file(artifacts, "detection_report.json").read_bytes()):
            raise ValueError("Fresh usable analysis is required")
        original_evidence = EvidenceStore(artifacts / "evidence", detection["repository_commit"])
        original_evidence.records = read_json(artifacts, "evidence/index.json")[0]
        original_evidence.validate([Finding.model_validate(f) for f in detection["findings"]])
        repo = source(scan)
        inventory = Inventory.model_validate(read_json(artifacts, "components.json")[0])
        report.update(repository_commit=detection["repository_commit"], source_sha256=digest(snapshot(repo)),
                      analysis_sha256=digest(safe_file(artifacts, "analysis_report.json").read_bytes()))
        evidence.commit = detection["repository_commit"]
        groups = {}
        for finding in analysis["findings"]:
            for identifier in finding["component_instance_ids"] or ["repository"]:
                groups.setdefault(identifier, []).append(finding)
        with OSVClient(artifacts / "remediation/osv-cache", evidence, transport=osv_transport, budget=60) as osv, MetadataClient(evidence, transport=metadata_transport, budget=45, max_requests=25) as metadata:
            for identifier, findings in groups.items():
                SCAN_CANCEL_CHECK.get()()
                component = next((c for c in inventory.components if c.id == identifier), None)
                recommendation = {"component_id": identifier, "finding_ids": [f["finding_id"] for f in findings],
                    "options": ["investigate", "accepted_risk"], "status": "manual_review", "reason": "No automatic fix for heuristic or unsupported findings"}
                report["recommendations"].append(recommendation)
                if any("DOCKER" in (f.get("rule_id") or "") or "BASE_IMAGE" in (f.get("rule_id") or "") for f in findings):
                    recommendation.update(options=["base_image", "investigate", "accepted_risk"], reason="Review a digest-pinned base-image update; no verified replacement image is available from npm evidence")
                vulnerable = [f for f in findings if f["finding_type"] == "vulnerability" and f["verification_status"] == "verified_match"]
                if any(f.get("advisory_category") == "malicious_package" for f in vulnerable):
                    recommendation.update(options=["block", "remove", "replace", "investigate"], reason="Malicious package advisory: block and review removal or replacement; no automatic trust decision")
                    continue
                if not component or not vulnerable or component.ecosystem != "npm" or not component.version:
                    continue
                try:
                    if len(report["proposals"]) >= 5:
                        raise ValueError("Five-proposal limit reached")
                    project = next(p for p in inventory.projects if p.path == component.project)
                    manifest_path, lock_path = project.manifest_path, project.lockfile_path
                    if not manifest_path or not lock_path or Path(lock_path).name != "package-lock.json":
                        raise ValueError("Automatic patches require package-lock.json")
                    manifest, _ = read_json(repo, manifest_path)
                    lock, _ = read_json(repo, lock_path)
                    preflight(manifest, lock)
                    fields = [f for f in FIELDS if component.name in manifest.get(f, {})]
                    if not fields or not any(e.parent == project.root_id and e.child == identifier and e.status == "resolved" for e in inventory.edges):
                        raise ValueError("Transitive-only fix requires reviewing an ancestor upgrade")
                    # Bind discovery identities to current lock bytes before using their version.
                    if not all(digest(safe_file(repo, e.file).read_bytes()) == e.sha256 for e in component.evidence):
                        raise ValueError("Discovery source evidence changed")
                    constraints = [manifest[f][component.name] for f in fields]
                    update(f"Checking fixed versions for {component.name}")
                    version, proofs, details = candidate(component, vulnerable, constraints, osv, metadata)
                    updated = json.loads(json.dumps(manifest))
                    for field in fields:
                        updated[field][component.name] = version
                    prepared_lock = json.loads(json.dumps(lock))
                    entry = prepared_lock["packages"]["node_modules/" + component.name]
                    # Offline regeneration prevents new package metadata from causing Git/URL fetches.
                    for field in ("dependencies", "optionalDependencies", "peerDependencies", "peerDependenciesMeta", "bundledDependencies", "bundleDependencies"):
                        if details.get(field, {}) != entry.get(field, {}):
                            raise ValueError("Candidate changes dependency topology; manual lock resolution is required")
                    dist = details.get("dist", {})
                    registry_url(dist.get("tarball"))
                    integrity = dist.get("integrity", "")
                    if not re.fullmatch(r"sha512-[A-Za-z0-9+/]+={0,2}", integrity):
                        raise ValueError("Candidate requires a registry SHA-512 integrity value")
                    entry.update(version=version, resolved=dist["tarball"], integrity=integrity)
                    for field in ("engines", "os", "cpu", "bin", "license", "funding"):
                        entry.pop(field, None)
                        if field in details:
                            entry[field] = details[field]
                    entry["hasInstallScript"] = bool(set(details.get("scripts", {})) & {"preinstall", "install", "postinstall"})
                    for field in fields:
                        prepared_lock["packages"].setdefault("", {}).setdefault(field, {})[component.name] = version
                    if "dependencies" in prepared_lock:
                        legacy = prepared_lock["dependencies"].get(component.name)
                        if legacy is None:
                            raise ValueError("Legacy lock entry is unavailable")
                        legacy.update(version=version, resolved=dist["tarball"], integrity=integrity)
                    with tempfile.TemporaryDirectory(prefix="guardian-patch-") as directory:
                        temporary = Path(directory)
                        write_json(temporary / "package.json", updated)
                        write_json(temporary / "package-lock.json", prepared_lock)
                        tool = npm_operation(temporary, ["install", "--package-lock-only", "--offline"])
                        new_lock = read_json(temporary, "package-lock.json")[0]
                        if new_lock["packages"].get("node_modules/" + component.name, {}).get("version") != version:
                            raise ValueError("Regenerated lock does not contain the proposed exact version")
                        proposal_id = uuid.uuid4().hex
                        relative = f"remediation/proposals/{proposal_id}"
                        directory = artifacts / relative
                        directory.mkdir(parents=True)
                        files, before, after, diff = {}, {}, {}, ""
                        for name, original in [("package.json", manifest_path), ("package-lock.json", lock_path)]:
                            old = safe_file(repo, original).read_bytes()
                            new = safe_file(temporary, name).read_bytes()
                            (directory / name).write_bytes(new)
                            files[f"{relative}/{name}"] = digest(new)
                            before[original], after[original] = digest(old), digest(new)
                            diff += "".join(difflib.unified_diff(old.decode().splitlines(True), new.decode().splitlines(True), fromfile="a/" + original, tofile="b/" + original))
                        (directory / "patch.diff").write_text(diff)
                        files[f"{relative}/patch.diff"] = digest(diff.encode())
                    proposal = {"id": proposal_id, "component_id": identifier, "name": component.name,
                        "from_version": component.version, "to_version": version, "action": "upgrade", "finding_ids": recommendation["finding_ids"],
                        "manifest_path": manifest_path, "lockfile_path": lock_path, "before": before, "after": after,
                        "artifacts": files, "evidence_ids": proofs, "source_sha256": report["source_sha256"],
                        "constraint_change_required": not all(NpmSpec(c).match(Version(version)) for c in constraints),
                        "major_change": Version(version).major != Version(component.version).major,
                        "original_constraints": constraints, "target_constraint": version, "tool": tool,
                        "rollback": "Discard the temporary validation copy. Original checkout is unchanged; exported patch can be reversed.",
                        "candidate_check": "Published registry identity and complete exact-version OSV no-match; not proof of safety"}
                    proposal["digest"] = digest(proposal)
                    report["proposals"].append(proposal)
                    recommendation.update(status="patch_proposed", options=["upgrade", "accepted_risk"], proposal_id=proposal_id,
                                          reason="Exact version pinned in all direct declarations; lock regenerated with scripts disabled")
                except (ValueError, RuntimeError, OSError, StopIteration, KeyError, TypeError) as exc:
                    SCAN_CANCEL_CHECK.get()()
                    recommendation["reason"] = str(exc)[:1000] or "Unsupported project"
        if digest(snapshot(repo)) != report["source_sha256"]:
            raise ValueError("Source changed during planning")
        facts = remediation_facts(analysis, report["recommendations"])
        gateway = AIGateway(store, config or AIConfig.load(), transport=ai_transport)
        report["ai"] = gateway.explain(scan.name, "fix_notes", facts)
        report["ai_usage"] = gateway.stats
        report["approval_status"] = "required" if report["proposals"] else "no_automatic_patch"
        report["status"] = "partial" if any(r["status"] == "manual_review" for r in report["recommendations"]) else "completed"
        report["limitations"] = ["Automatic patches support direct npm registry dependencies in independent package-lock v2/v3 projects.",
            "Candidates that change runtime dependency declarations require manual lock resolution; offline regeneration never fetches new references.",
            "Proposals validate independently, not as one combined patch.", "Replacement, removal, trusted pin, base-image updates, block, escalation and risk acceptance require human selection; versions are never invented."]
    except Exception as exc:
        SCAN_CANCEL_CHECK.get()()
        report.update(status="failed", proposals=[])
        report["errors"].append(str(exc)[:1000])
    finally:
        evidence.save()
        SCAN_DEADLINE.reset(deadline)
    report["finished_at"] = timestamp()
    write_json(artifacts / "remediation_report.json", report)
    write_json(artifacts / "remediation_status.json", {"status": report["status"], "stage": "Remediation planning finished"})
    return report
