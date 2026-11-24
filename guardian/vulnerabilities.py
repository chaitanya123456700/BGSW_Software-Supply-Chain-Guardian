import hashlib
import json
import re
from datetime import datetime
from collections import defaultdict
from urllib.parse import unquote

import networkx as nx

from .evidence import EvidenceStore, correlate_paths, timestamp
from .files import safe_file
from .models import Finding, Inventory, stable_id
from .npm import NAME
from .osv import ADVISORY_ID, OSVClient, OSVError

NPM_VERSION = re.compile(r"(?:v)?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\Z")


def same_modified_time(left, right):
    try:
        # OSV batch timestamps truncate nanoseconds to microseconds; full records can retain all nine digits.
        a, b = (datetime.fromisoformat(value.replace("Z", "+00:00")) for value in (left, right))
        return a.tzinfo is not None and b.tzinfo is not None and a == b
    except (ValueError, AttributeError, TypeError):
        return False


def verify_advisory(component, record: dict, *, github_record=None) -> dict:
    """The exact-version OSV query is authoritative matching evidence, not code reachability."""
    result = {"verification_status": "undetermined", "source_consistency": "single_source", "reason": "Invalid affected metadata"}
    if record.get("withdrawn"):
        return {**result, "verification_status": "not_applicable", "reason": "Advisory was withdrawn"}
    if component.resolution_status != "resolved" or not component.version:
        return {**result, "reason": "Exact resolved version is unknown"}
    affected = record.get("affected")
    if not isinstance(affected, list):
        return result
    matched = [item for item in affected if isinstance(item, dict) and isinstance(item.get("package"), dict)
               and item["package"].get("ecosystem") == "npm" and item["package"].get("name") == component.name]
    if component.ecosystem != "npm" or not matched:
        return {**result, "verification_status": "conflicting_evidence", "reason": "OSV query and advisory package identity disagree"}
    if any(not isinstance(item.get("versions", []), list) or not isinstance(item.get("ranges", []), list) for item in matched):
        return result
    for item in matched:
        if any(not isinstance(version, str) for version in item.get("versions", [])):
            return result
        for affected_range in item.get("ranges", []):
            if not isinstance(affected_range, dict) or not isinstance(affected_range.get("events"), list):
                return result
            if any(not isinstance(event, dict) or len(event) != 1 or next(iter(event)) not in {"introduced", "fixed", "last_affected", "limit"}
                   or not isinstance(next(iter(event.values())), str) for event in affected_range["events"]):
                return result
    if any(item.get("ranges") for item in matched) and not any(component.version in item.get("versions", []) or any(
            r.get("type") in {"SEMVER", "ECOSYSTEM"} for r in item.get("ranges", [])) for item in matched):
        return {**result, "reason": "Affected range scheme cannot corroborate npm applicability"}
    # Never compare range/version strings lexicographically. OSV supplied the exact-version match.
    if not any(component.version in item.get("versions", []) or any(
            isinstance(r, dict) and r.get("type") in {"SEMVER", "ECOSYSTEM"} and isinstance(r.get("events"), list) and r["events"]
            for r in item.get("ranges", [])) for item in matched):
        return {**result, "verification_status": "conflicting_evidence", "reason": "Full advisory does not corroborate the exact-version query"}
    result.update(verification_status="verified_match", reason="Exact-version OSV query and full advisory agree on package identity")
    if github_record is not None:
        vulnerabilities = github_record.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list) or not any(isinstance(item, dict) and isinstance(item.get("package"), dict) and
                item["package"].get("ecosystem") == "npm" and item["package"].get("name") == component.name for item in vulnerabilities):
            result.update(verification_status="conflicting_evidence", source_consistency="conflicting_evidence", reason="GitHub and OSV package metadata disagree")
        else:
            result.update(source_consistency="shared_provenance_package_agreement_range_not_compared",
                          verification_status="provisional", reason="GitHub package identity agrees, but affected-range agreement was not established")
    return result


def detect_vulnerabilities(inventory: Inventory, graph: dict, repo_path, store: EvidenceStore,
                           client: OSVClient, scan_id: str, commit: str, *, phase1_dependency_status=None) -> dict:
    result = {"status": "completed", "provider": "OSV.dev", "findings": [], "decisions": [],
              "errors": [], "warnings": [], "skipped_components": [], "queried_package_versions": 0,
              "completed_package_versions": 0, "verified_count": 0, "query_results": []}
    nodes = {node["id"]: node for node in graph["nodes"]}
    source_cache, source_evidence, component_evidence, groups = {}, {}, {}, defaultdict(list)
    packages = [c for c in inventory.components if c.kind not in {"application", "repository", "workspace"}]
    for component in packages:
        reason = None
        if component.resolution_status != "resolved" or not component.version:
            reason = "Declared-only or unknown version; no exact-version query was made"
        elif component.ecosystem != "npm":
            reason = "Native exact-version verification currently supports npm only"
        elif not NPM_VERSION.fullmatch(component.version) or not component.identity or not NAME.fullmatch(component.name):
            reason = "Reliable exact npm package identity/version is unavailable"
        elif unquote(component.identity) != f"pkg:npm/{component.name}@{component.version}":
            reason = "Package identity does not agree with normalized name/version"
        elif component.id not in nodes or nodes[component.id].get("version") != component.version or nodes[component.id].get("name") != component.name:
            reason = "Inventory and graph component metadata disagree"
        else:
            try:
                proof = None
                for evidence in component.evidence:
                    if evidence.file not in source_cache:
                        raw = safe_file(repo_path, evidence.file).read_bytes()
                        source_cache[evidence.file] = (json.loads(raw), hashlib.sha256(raw).hexdigest())
                        source_evidence[evidence.file] = store.add("repository_source", evidence.file, None, raw=raw,
                            reliability="verified_observation")
                    document, digest = source_cache[evidence.file]
                    if digest != evidence.sha256:
                        continue
                    value = document
                    for token in evidence.pointer.split("/")[1:]:
                        value = value[token.replace("~1", "/").replace("~0", "~")]
                    record_path = evidence.pointer.split("/")[2].replace("~1", "/").replace("~0", "~") if evidence.pointer.startswith("/packages/") else ""
                    source_name = value.get("name") if isinstance(value, dict) else None
                    if not source_name and "node_modules/" in record_path:
                        source_name = record_path.rsplit("node_modules/", 1)[-1]
                    if isinstance(value, dict) and value.get("version") == component.version and source_name == component.name:
                        proof = source_evidence[evidence.file]
                        break
                if proof is None:
                    raise ValueError("Version/source digest could not be corroborated")
                snapshot = store.add("phase1_component", "components.json", component.model_dump(),
                    reliability="verified_observation", context={"component_instance_id": component.id})
                component_evidence[component.id] = [proof, snapshot]
            except (ValueError, KeyError, TypeError, OSError) as exc:
                reason = f"Source evidence unavailable or invalid: {exc}"
        if reason:
            result["skipped_components"].append({"id": component.id, "name": component.name,
                "constraint": component.requested_constraint, "reason": reason})
        else:
            groups[(component.name, component.version)].append(component)
    keys = sorted(groups)
    if len(keys) > 2000:
        result["warnings"].append("Exact-version query limit reached; remaining package versions were not checked")
        keys = keys[:2000]
    candidates, advisory_cache = [], {}
    union = nx.utils.UnionFind()
    for offset in range(0, len(keys), 100):
        subset = keys[offset:offset + 100]
        queries = [{"package": {"ecosystem": "npm", "name": name}, "version": version} for name, version in subset]
        responses = client.query_batch(queries)
        result["queried_package_versions"] += len(queries)
        for key, response in zip(subset, responses):
            result["query_results"].append({"name": key[0], "version": key[1], **response})
            if response["complete"]:
                result["completed_package_versions"] += 1
            if response["error"]:
                result["errors"].append(f"{key[0]}@{key[1]}: {response['error']}")
            for identifier in response["advisories"]:
                try:
                    if identifier not in advisory_cache:
                        advisory_cache[identifier] = client.advisory(identifier)
                    record, record_evidence = advisory_cache[identifier]
                except OSVError as exc:
                    result["errors"].append(f"{identifier}: {exc}")
                    continue
                aliases = record.get("aliases", [])
                if not isinstance(aliases, list) or any(not isinstance(alias, str) or not ADVISORY_ID.fullmatch(alias) for alias in aliases):
                    result["errors"].append(f"{identifier}: invalid advisory aliases")
                    continue
                labels = [identifier, *aliases]
                union.union(*labels)
                for component in groups[key]:
                    decision = verify_advisory(component, record)
                    batch_modified = response.get("modified", {}).get(identifier)
                    if decision["verification_status"] == "verified_match" and batch_modified and not same_modified_time(batch_modified, record["modified"]):
                        decision.update(verification_status="provisional", reason="Advisory changed between query and full-record retrieval")
                    result["decisions"].append({"component_instance_id": component.id, "advisory_id": identifier, **decision})
                    if decision["verification_status"] == "not_applicable":
                        continue
                    candidates.append((component, record, decision, [*response["evidence_ids"], record_evidence, *component_evidence[component.id]]))
    correlated = defaultdict(list)
    for candidate in candidates:
        correlated[union[candidate[1]["id"]]].append(candidate)
    for candidates in correlated.values():
        ids = sorted({record["id"] for _, record, _, _ in candidates})
        aliases = sorted({alias for _, record, _, _ in candidates for alias in record.get("aliases", [])})
        labels = sorted(set(ids + aliases), key=lambda value: (not value.startswith("CVE-"), not value.startswith("GHSA-"), value))
        statuses = {decision["verification_status"] for _, _, decision, _ in candidates}
        malicious = any(label.startswith("MAL-") for label in ids + aliases)
        verification = "conflicting_evidence" if "conflicting_evidence" in statuses else "undetermined" if "undetermined" in statuses else "provisional" if "provisional" in statuses else "verified_match"
        finding = Finding(finding_id=stable_id("finding", inventory.repository_id or "repository", "vulnerability", labels[0]),
            scan_id=scan_id, finding_type="vulnerability", title=candidates[0][1].get("summary") or labels[0],
            explanation="Known advisory matched using exact package/version OSV queries and original lockfile evidence. Code-path reachability is not analyzed." if verification == "verified_match" else "Advisory applicability requires review; source evidence is not fully consistent.",
            component_instance_ids=sorted({c.id for c, _, _, _ in candidates}), repository_commit=commit,
            advisory_ids=ids, aliases=aliases, verification_status=verification,
            advisory_category="malicious_package" if malicious else "vulnerability",
            classification="malicious_package_advisory" if malicious else "source_statement",
            version_applicability="affected" if verification == "verified_match" else "undetermined",
            evidence_ids=sorted({evidence for _, _, _, evidence_ids in candidates for evidence in evidence_ids}), created_at=timestamp(),
            source_metadata=[{key: record.get(key) for key in ["id", "aliases", "affected", "severity", "published", "modified", "withdrawn", "references", "database_specific"]}
                             for identifier in ids for _, record, _, _ in [next(candidate for candidate in candidates if candidate[1]["id"] == identifier)]])
        correlate_paths(finding, inventory, graph)
        store.validate([finding])
        result["findings"].append(finding.model_dump())
    result["verified_count"] = sum(f["verification_status"] == "verified_match" for f in result["findings"])
    verified_empty = phase1_dependency_status == "verified_empty" or bool(inventory.projects) and all(p.completeness_status == "verified_empty" for p in inventory.projects)
    if not keys and not packages and not verified_empty:
        result["warnings"].append("Insufficient dependency metadata: vulnerability coverage is unknown")
    if result["skipped_components"]:
        result["warnings"].append("Some components lack a supported, corroborated exact version; vulnerability coverage is reduced")
    if any(f["verification_status"] != "verified_match" for f in result["findings"]):
        result["warnings"].append("Some candidate advisory matches require verification review")
    if result["errors"] or result["warnings"]:
        result["status"] = "failed" if keys and result["completed_package_versions"] == 0 and result["errors"] else "partial"
    result["no_match_statement"] = "No matching advisories in the queried scope" if result["status"] == "completed" and not result["findings"] else None
    return result
