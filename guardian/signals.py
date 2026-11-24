"""Current-state lifecycle, typosquat, and local policy checks backed by raw evidence."""
import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from packaging.requirements import Requirement

from .changes import one_edit, workflow_data
from .evidence import correlate_paths, timestamp
from .files import safe_file, walk_files
from .metadata import MetadataClient, MetadataError
from .models import Finding, stable_id
from .npm import declarations, pointer
from .process import SCAN_CANCEL_CHECK, WORKSPACE

LIFECYCLES = {"preinstall", "install", "postinstall", "prepare"}
SNAPSHOT_SHA256 = "8370f55b39946fb727b6e4d4720bb5a621f39ac2119ddb6e240a360a0ca8e7dd"
PATTERNS = {
    "download_and_execute": re.compile(r"\b(?:curl|wget)\b.{0,1024}(?:\||&&|;)\s*(?:sh|bash|node|python)\b", re.I),
    "dynamic_code": re.compile(r"\b(?:eval|Function)\s*\("),
    "encoded_payload": re.compile(r"(?:Buffer\.from|atob)\s*\(.{0,512}base64", re.I),
    "credential_access": re.compile(r"process\.env|\.npmrc|(?:AWS|GITHUB|NPM)_TOKEN"),
}


def git_reference(value):
    if not isinstance(value, str):
        return False
    value = value.strip()
    return bool(re.match(r"^(?:git\+|git://|git@|ssh://|github:|gitlab:|bitbucket:|gist:)", value, re.I)
                or re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:#\S*)?", value)
                or re.match(r"https?://", value, re.I) and (
                    re.search(r"\.git(?:#|$)", value) or urlsplit(value).hostname in {"github.com", "gitlab.com", "bitbucket.org"}))


def load_policy(path):
    if path.stat().st_size > 256 * 1024:
        raise ValueError("Policy size limit exceeded")
    raw = path.read_bytes()
    value = workflow_data(raw)
    if set(value) != {"version", "rules", "reviewed_install_scripts"} or type(value["version"]) is not int or value["version"] != 1:
        raise ValueError("Unsupported or invalid Guardian policy schema")
    rules = value["rules"]
    if not isinstance(rules, dict) or set(rules) != {"no_git_dependencies", "no_unreviewed_install_scripts"} or any(type(v) is not bool for v in rules.values()):
        raise ValueError("Policy rules must be explicit booleans")
    reviews = value["reviewed_install_scripts"]
    if not isinstance(reviews, list) or len(reviews) > 1000:
        raise ValueError("Invalid or oversized script review list")
    for review in reviews:
        if (not isinstance(review, dict) or set(review) not in (
                {"file", "lifecycle", "sha256"}, {"package", "version", "lifecycle", "sha256"})
                or any(not isinstance(v, str) or len(v) > 500 for v in review.values())
                or review["lifecycle"] not in LIFECYCLES or not re.fullmatch(r"[0-9a-f]{64}", review["sha256"])):
            raise ValueError("Invalid exact script review entry")
    return value, raw


def load_snapshot():
    path = Path(__file__).with_name("policies") / "npm_top_snapshot.json"
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SNAPSHOT_SHA256:
        raise ValueError("Pinned npm popularity snapshot hash mismatch")
    value = json.loads(raw)
    names = value["packages"]
    if len(names) != 1000 or len(set(names)) != 1000 or any(not isinstance(n, str) for n in names):
        raise ValueError("Invalid pinned npm popularity snapshot")
    return value, raw


def typo_index(names):
    index = defaultdict(set)
    for name in names:
        index[name].add(name)
        for position in range(len(name)):
            index[name[:position] + name[position + 1:]].add(name)
    return index


def similar_names(name, names, index):
    if name in names or len(name.rsplit("/", 1)[-1]) < 4 or len(name) > 214:
        return []
    candidates = set(index.get(name, ()))
    for position in range(len(name)):
        candidates.update(index.get(name[:position] + name[position + 1:], ()))
        if position + 1 < len(name):
            swap = name[:position] + name[position + 1] + name[position] + name[position + 2:]
            if swap in names:
                candidates.add(swap)
    scope = name.split("/", 1)[0] if name.startswith("@") else None
    return sorted(candidate for candidate in candidates
        if (candidate.split("/", 1)[0] if candidate.startswith("@") else None) == scope
        and (one_edit(name, candidate) or any(name[:i] + name[i + 1] + name[i] + name[i + 2:] == candidate
                                             for i in range(len(name) - 1))))[:3]


def enrichment(client, name, version):
    details = {"indexed_history_age_days": None, "project_stars": None, "missing_evidence": []}
    evidence = []
    try:
        package, proof = client.package(name)
        evidence.append(proof)
        versions = package.get("versions", [])
        if not isinstance(versions, list) or len(versions) > 10000:
            raise MetadataError("Invalid or oversized package history")
        dates = []
        for item in versions:
            if not isinstance(item, dict) or item.get("versionKey", {}).get("name") != name or item.get("versionKey", {}).get("system") != "NPM":
                raise MetadataError("Package history identity mismatch")
            if item.get("publishedAt"):
                date = datetime.fromisoformat(item["publishedAt"].replace("Z", "+00:00"))
                if date.tzinfo and date <= datetime.now(timezone.utc):
                    dates.append(date)
        if dates:
            details["indexed_history_age_days"] = (datetime.now(timezone.utc) - min(dates)).days
        else:
            details["missing_evidence"].append("No indexed publication timestamps")
    except (ValueError, TypeError, AttributeError):
        details["missing_evidence"].append("Package history unavailable or invalid")
    try:
        if not version:
            raise MetadataError("No exact observed version for project enrichment")
        data, proof = client.version("api.deps.dev", name, version)
        evidence.append(proof)
        projects = data.get("relatedProjects", [])
        if not isinstance(projects, list):
            raise MetadataError("Invalid related projects")
        project = next((p for p in projects[:100] if isinstance(p, dict) and p.get("relationType") == "SOURCE_REPO"), None)
        if project is None:
            raise MetadataError("Source project is not available")
        identifier = project.get("projectKey", {}).get("id")
        data, proof = client.project(identifier)
        evidence.append(proof)
        stars = data.get("starsCount")
        if type(stars) is not int or stars < 0:
            raise MetadataError("Project popularity proxy unavailable")
        details.update(project_stars=stars, project_id=identifier,
                       project_mapping_provenance=project.get("relationProvenance", "unknown"))
    except (ValueError, TypeError, AttributeError):
        details["missing_evidence"].append("Project-star popularity proxy unavailable")
    details["interpretation"] = "Indexed history is not package creation age; repository stars are not package downloads or proof of legitimacy"
    return details, evidence


def detect_signals(repo, inventory, graph, store, scan_id, commit, *, transport=None, policy_path=None):
    report = {"status": "completed", "findings": [], "inspections": [], "errors": [], "warnings": [],
              "policy_status": "not_run", "scope": "Current-state npm scripts, Git references, and offline name similarity; no baseline required"}
    policy_path = policy_path or WORKSPACE / "policy.yaml"
    try:
        policy, raw = load_policy(policy_path)
        report["policy_sha256"] = hashlib.sha256(raw).hexdigest()
        policy_evidence = store.add("guardian_policy", "guardian:policy.yaml", None, raw=raw, reliability="local_review_policy")
    except (ValueError, OSError, yaml.YAMLError) as exc:
        report.update(status="failed", policy_status="not_run")
        report["errors"].append(f"Guardian policy unavailable or invalid: {exc}")
        return report
    expected = defaultdict(set)
    by_source = defaultdict(list)
    for component in inventory.components:
        for proof in component.evidence:
            expected[proof.file].add(proof.sha256)
            by_source[(proof.file, proof.pointer)].append(component)
    sources = {}

    def load(path):
        if path not in sources:
            raw = safe_file(repo, path).read_bytes()
            if expected[path] and hashlib.sha256(raw).hexdigest() not in expected[path]:
                raise ValueError("Source changed since discovery; current-state checks skipped")
            proof = store.add("repository_source", path, None, raw=raw, reliability="verified_observation" if expected[path] else "current_source_observation")
            sources[path] = raw, proof
        return sources[path]

    def emit(kind, rule, title, details, proofs, components=(), *, confidence=None, verified="provisional"):
        observation = store.add("policy_observation" if kind == "policy_violation" else "static_signal", rule, details,
                                reliability="policy_observation" if kind == "policy_violation" else "heuristic_suspicion")
        finding = Finding(finding_id=stable_id("finding", inventory.repository_id or "repository", rule, json.dumps(details, sort_keys=True)),
            scan_id=scan_id, finding_type=kind, title=title, explanation=details["interpretation"], repository_commit=commit,
            component_instance_ids=sorted({c.id for c in components}), evidence_ids=sorted(set([*proofs, observation])),
            verification_status=verified, classification="policy_violation" if kind == "policy_violation" else "heuristic_signal",
            version_applicability="not_applicable", rule_id=rule, confidence=confidence, source_metadata=[details], created_at=timestamp())
        correlate_paths(finding, inventory, graph)
        store.validate([finding])
        report["findings"].append(finding.model_dump())

    script_names = set()

    def inspect_scripts(scripts, target, proofs, components=()):
        if not isinstance(scripts, dict) or len(scripts) > 200 or any(not isinstance(k, str) or not isinstance(v, str) or len(v) > 8192 for k, v in scripts.items()):
            raise ValueError("Invalid or oversized lifecycle script metadata")
        found = False
        for lifecycle in sorted(LIFECYCLES & scripts.keys()):
            found = True
            command = scripts[lifecycle]
            digest = hashlib.sha256(command.encode()).hexdigest()
            review = {**target, "lifecycle": lifecycle, "sha256": digest}
            reviewed = review in policy["reviewed_install_scripts"]
            patterns = [name for name, pattern in PATTERNS.items() if pattern.search(command)]
            details = {**target, "lifecycle": lifecycle, "command": command, "script_sha256": digest,
                "patterns": patterns, "reviewed": reviewed,
                "interpretation": "Lifecycle script observed statically; matching patterns are review signals, not proof of malicious behavior or execution"}
            emit("install_script", "RULE_INSTALL_SCRIPT", "Installation lifecycle script requires inspection", details, proofs, components, confidence=0.6 if patterns else 0.3)
            script_names.update(c.name for c in components)
            if policy["rules"]["no_unreviewed_install_scripts"] and not reviewed:
                emit("policy_violation", "POLICY_UNREVIEWED_INSTALL_SCRIPT", "Installation script has no exact command review", details,
                     [*proofs, policy_evidence], components, verified="verified_match")
        return found

    def check_git(value, details, proofs, components=()):
        if policy["rules"]["no_git_dependencies"] and git_reference(value):
            details = {**details, "reference": value, "interpretation": "Git-based dependency reference violates the local no-Git-dependencies policy; no remote content was fetched"}
            emit("policy_violation", "POLICY_GIT_DEPENDENCY", "Git-based dependency is blocked by policy", details,
                 [*proofs, policy_evidence], components, verified="verified_match")

    flagged = defaultdict(list)
    files = [p.relative_to(repo).as_posix() for p in walk_files(repo) if p.name in {"package.json", "package-lock.json"}]
    if len(files) > 150:
        report["warnings"].append("Static inspection limited to 150 npm metadata files")
    with MetadataClient(store, transport=transport) as client:
        for path in files[:150]:
            SCAN_CANCEL_CHECK.get()()
            try:
                raw, proof = load(path)
                data = json.loads(raw)
                if not isinstance(data, dict):
                    raise ValueError("npm metadata must be an object")
                if path.endswith("package.json"):
                    inspect_scripts(data.get("scripts", {}), {"file": path}, [proof])
                    for field, _, name, value, _ in declarations(data):
                        owners = by_source[(path, f"/{field}/{pointer(name)}")]
                        check_git(value, {"file": path, "pointer": f"/{field}/{pointer(name)}", "package": name}, [proof], owners)
                else:
                    if data.get("lockfileVersion") not in {2, 3} or not isinstance(data.get("packages"), dict):
                        raise ValueError("Only npm v2/v3 lockfile records support static inspection")
                    for location, record in data["packages"].items():
                        if not isinstance(record, dict):
                            raise ValueError("Invalid npm lockfile record")
                        owners = [c for c in by_source[(path, "/packages/" + pointer(location))] if c.kind == "package"]
                        for field in ("resolved", "version"):
                            check_git(record.get(field), {"file": path, "pointer": f"/packages/{pointer(location)}/{field}"}, [proof], owners)
                        if location and record.get("hasInstallScript") is True:
                            if not owners:
                                report["warnings"].append(f"{path}: install-script flag has no corroborated component identity")
                            for component in owners:
                                source_name = record.get("name") or location.rsplit("node_modules/", 1)[-1]
                                if source_name != component.name or record.get("version") != component.version:
                                    report["warnings"].append(f"{path}: install-script component identity does not match its lockfile record")
                                elif component.resolution_status == "resolved" and component.version:
                                    flagged[(component.name, component.version)].append((component, proof))
                report["inspections"].append({"file": path, "status": "inspected", "evidence_id": proof})
            except (ValueError, OSError, TypeError) as exc:
                report["errors"].append(f"{path}: {str(exc)[:500]}")
        for component in inventory.components:
            if component.ecosystem == "python" and component.kind == "package" and component.requested_constraint:
                try:
                    proofs = [load(p.file)[1] for p in component.evidence]
                    requirement = Requirement(component.requested_constraint)
                    if requirement.url:
                        check_git(requirement.url, {"file": component.evidence[0].file, "package": component.name}, proofs, [component])
                except (ValueError, OSError, IndexError) as exc:
                    report["errors"].append(f"Python dependency policy inspection incomplete: {str(exc)[:200]}")
        for index, ((name, version), entries) in enumerate(flagged.items()):
            SCAN_CANCEL_CHECK.get()()
            if index >= 30:
                report["warnings"].append("Dependency lifecycle metadata limited to 30 exact package versions")
                break
            components, proofs = [c for c, _ in entries], [p for _, p in entries]
            details = {"package": name, "version": version, "hasInstallScript": True,
                "interpretation": "Lockfile declares hasInstallScript; presence is not proof of malicious behavior or execution"}
            emit("install_script", "RULE_INSTALL_SCRIPT_FLAG", "Dependency lockfile declares an install script", details, proofs, components, confidence=0.3, verified="verified_match")
            try:
                data, metadata_proof = client.version("registry.npmjs.org", name, version)
                present = inspect_scripts(data.get("scripts", {}), {"package": name, "version": version}, [*proofs, metadata_proof], components)
                if not present:
                    raise MetadataError("Flagged script is implicit or not present in registry lifecycle metadata")
            except ValueError as exc:
                report["warnings"].append(f"{name}@{version}: lifecycle metadata incomplete: {str(exc)[:200]}")
                if policy["rules"]["no_unreviewed_install_scripts"]:
                    details = {**details, "metadata_status": "unavailable_or_implicit", "interpretation": "Install-script flag has no inspectable exact command; script-review policy cannot be satisfied with missing evidence"}
                    emit("policy_violation", "POLICY_UNREVIEWED_INSTALL_SCRIPT", "Flagged dependency script lacks review evidence", details, [*proofs, policy_evidence], components, verified="undetermined")
        try:
            snapshot, raw = load_snapshot()
            snapshot_proof = store.add("pinned_npm_popularity_snapshot", snapshot["source"], None, raw=raw, reliability="pinned_comparison_data")
            report["typosquat_snapshot"] = {key: snapshot[key] for key in ("name", "upstream_commit", "collected_at", "source")}
            report["typosquat_snapshot"]["sha256"] = SNAPSHOT_SHA256
            names = set(snapshot["packages"])
            index = typo_index(names)
            packages = defaultdict(list)
            for component in inventory.components:
                if component.kind == "package" and component.ecosystem == "npm" and component.resolution_status != "inferred":
                    packages[component.name].append(component)
            if len(packages) > 2000:
                report["warnings"].append("Offline typo inspection limited to 2000 package names")
            enriched = 0
            for name, components in list(packages.items())[:2000]:
                SCAN_CANCEL_CHECK.get()()
                similar = similar_names(name, names, index)
                if not similar:
                    continue
                proofs = []
                try:
                    for component in components:
                        proofs.extend(load(p.file)[1] for p in component.evidence)
                    if not proofs:
                        raise ValueError("No repository source evidence for candidate name")
                except (ValueError, OSError) as exc:
                    report["warnings"].append(f"Typosquat candidate skipped: {str(exc)[:200]}")
                    continue
                metadata = {"indexed_history_age_days": None, "project_stars": None, "missing_evidence": ["Enrichment limit reached"]}
                if enriched < 10:
                    version = components[0].version or components[0].declared_version or components[0].inferred_version
                    metadata, extra = enrichment(client, name, version)
                    proofs.extend(extra)
                    enriched += 1
                confidence = 0.35
                if metadata.get("indexed_history_age_days") is not None and metadata["indexed_history_age_days"] <= 30:
                    confidence += 0.1
                if metadata.get("project_stars") is not None and metadata["project_stars"] <= 10:
                    confidence += 0.1
                if name in script_names or any(key[0] == name for key in flagged):
                    confidence += 0.2
                details = {"package": name, "comparison_names": similar, "snapshot_sha256": SNAPSHOT_SHA256,
                    "metadata": metadata, "has_install_script_signal": name in script_names or any(key[0] == name for key in flagged),
                    "interpretation": "Name resembles a pinned popular package; heuristic confidence ranks review signals, not malware probability or proof of typosquatting"}
                emit("typosquat", "RULE_TYPOSQUAT_NAME", "Package name resembles a pinned popular package", details,
                     [*proofs, snapshot_proof], components, confidence=round(confidence, 2))
        except (ValueError, OSError, KeyError) as exc:
            report["errors"].append(f"Typosquat checks unavailable: {str(exc)[:300]}")
        report["metadata_client"] = {"requests": client.requests, "cache_hits": client.cache_hits, "max_requests": client.max_requests}
    report["findings"].sort(key=lambda finding: (-(finding["confidence"] or 0), finding["finding_id"]))
    violations = sum(f["finding_type"] == "policy_violation" for f in report["findings"])
    unsupported = not inventory.projects or any(p.completeness_status not in {"verified", "verified_empty"} for p in inventory.projects)
    if unsupported:
        report["warnings"].append("Unsupported or failed project metadata prevents complete policy coverage")
    report["policy_status"] = "failed" if violations else "partial" if report["errors"] or report["warnings"] else "passed"
    report["policy_violations"] = violations
    report["status"] = "partial" if report["errors"] or report["warnings"] else "completed"
    report["limitations"] = ["Regex matches and name similarity are review signals, never malware conclusions.",
        "Registry scripts can differ from tarball content; tarballs are never downloaded or executed.",
        "npm hasInstallScript can reflect implicit native-build behavior; missing commands remain unreviewed.",
        "Pinned popularity data can be stale or gamed; indexed history and project stars are imperfect proxies.",
        "Policy is loaded only from Guardian's trusted configuration, never from the scanned repository."]
    return report
