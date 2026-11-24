"""Read-only Git comparisons and narrowly scoped deterministic review signals."""
import json
import re
from pathlib import Path, PurePosixPath

import yaml
from yaml.events import AliasEvent, CollectionEndEvent, CollectionStartEvent

from .evidence import EvidenceStore, correlate_paths, timestamp
from .files import MAX_FILE, read_json, safe_file, walk_files
from .models import Finding, Inventory, stable_id
from .npm import declarations, pointer
from .process import ToolError, run_tool

SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


def workflow_data(raw: bytes):
    if len(raw) > 256 * 1024:
        raise ValueError("Workflow size limit exceeded")
    aliases = depth = events = 0
    for event in yaml.parse(raw):
        events += 1
        aliases += isinstance(event, AliasEvent)
        depth += isinstance(event, CollectionStartEvent) - isinstance(event, CollectionEndEvent)
        if aliases > 20 or depth > 30 or events > 20000:
            raise ValueError("Workflow YAML complexity limit exceeded")
    result = yaml.safe_load(raw) or {}
    if not isinstance(result, dict):
        raise ValueError("Workflow must be a YAML mapping")
    return result


def workflow_observations(document):
    permissions = {"/permissions": document["permissions"]} if "permissions" in document else {}
    actions = {}
    jobs = document.get("jobs", {})
    if not isinstance(jobs, dict):
        raise ValueError("Workflow jobs must be a mapping")
    for name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        prefix = "/jobs/" + pointer(str(name))
        if "permissions" in job:
            permissions[prefix + "/permissions"] = job["permissions"]
        if isinstance(job.get("uses"), str):
            actions[prefix + "/uses"] = job["uses"]
        steps = job.get("steps", [])
        if isinstance(steps, list):
            for index, step in enumerate(steps):
                if isinstance(step, dict) and isinstance(step.get("uses"), str):
                    actions[f"{prefix}/steps/{index}/uses"] = step["uses"]
    return permissions, actions


def docker_references(raw):
    stages, references = set(), []
    for index, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), 1):
        match = re.match(r"\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", line, re.I)
        if match:
            reference, alias = match.groups()
            if reference.casefold() not in stages:
                references.append({"line": index, "reference": reference, "digest_pinned": bool(re.search(r"@sha256:[0-9a-f]{64}\Z", reference)),
                                   "resolution": "unknown_build_argument" if "$" in reference else "literal_reference"})
            if alias:
                stages.add(alias.casefold())
    return references


def one_edit(left, right):
    if left == right or abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        return sum(a != b for a, b in zip(left, right)) == 1
    short, long = sorted([left, right], key=len)
    return any(long[:index] + long[index + 1:] == short for index in range(len(long)))


def detect_changes(repo: Path, inventory: Inventory, graph: dict, store: EvidenceStore,
                   scan_id: str, commit: str, baseline_commit: str | None = None) -> dict:
    report = {"status": "completed", "comparison_status": "comparison_unavailable", "baseline_commit": baseline_commit,
              "findings": [], "inspections": [], "errors": [], "warnings": [], "policy_version": "guardian-npm-comparison-v1"}
    sources, before_sources, changed = {}, {}, set()

    def git(*args, check=True):
        return run_tool(["git", "-c", "core.hooksPath=/dev/null", *args], repo, timeout=10, check=check)

    if baseline_commit:
        try:
            if not SHA.fullmatch(baseline_commit) or not SHA.fullmatch(commit):
                raise ValueError("Comparison commits must be full Git SHAs")
            git("cat-file", "-e", baseline_commit + "^{commit}")
            if git("rev-parse", "HEAD").stdout.strip() != commit:
                raise ValueError("Repository HEAD differs from the Phase 1 commit")
            git("merge-base", "--is-ancestor", baseline_commit, commit)
            git("diff", "--quiet", "--no-ext-diff", "--no-textconv", commit, "--")
            diff = git("diff", "--no-ext-diff", "--no-textconv", "--name-only", "-z", baseline_commit, commit, "--").stdout
            changed = set(diff.rstrip("\0").split("\0")) if diff else set()
            store.add("git_diff", f"git:{baseline_commit}..{commit}", {"before_commit": baseline_commit, "after_commit": commit, "changed_paths": sorted(changed)}, reliability="verified_observation")
            report["comparison_status"] = "available"
        except (ValueError, ToolError) as exc:
            report["warnings"].append(f"comparison_unavailable: {exc}")
    else:
        report["warnings"].append("comparison_unavailable: no trusted baseline supplied; change-dependent rules were skipped")

    def load_current(path):
        if path not in sources:
            raw = safe_file(repo, path).read_bytes()
            sources[path] = (raw, store.add("repository_source", path, None, raw=raw, reliability="verified_observation"))
        return sources[path]

    def load_before(path):
        if path not in before_sources:
            # A symlink blob is a link string, never a file to follow.
            tree = git("ls-tree", baseline_commit, "--", path).stdout
            if not tree or tree.split(" ", 1)[0] not in {"100644", "100755"}:
                before_sources[path] = (None, None)
            else:
                size = int(git("cat-file", "-s", f"{baseline_commit}:{path}").stdout)
                if size > MAX_FILE:
                    raise ValueError("Baseline source file exceeds size limit")
                raw = git("cat-file", "blob", f"{baseline_commit}:{path}").stdout.encode()
                before_sources[path] = (raw, store.add("git_blob", f"git:{baseline_commit}:{path}", None, raw=raw, reliability="verified_observation"))
        return before_sources[path]

    def emit(rule, path, location, before, after, title, classification="observed_change", component_ids=None, extra=None):
        raw, current_evidence = load_current(path)
        evidence_ids = [current_evidence]
        if classification == "observed_change" or report["comparison_status"] == "available":
            _, old_evidence = load_before(path)
            if old_evidence:
                evidence_ids.append(old_evidence)
        observation = {"rule_id": rule, "file": path, "pointer": location, "before": before, "after": after,
                       "repository_commit": commit, "baseline_commit": baseline_commit if report["comparison_status"] == "available" else None,
                       "additional_signals": extra or {}}
        evidence_ids.append(store.add("change_observation" if classification == "observed_change" else "heuristic_observation", path,
            observation, reliability="verified_observation" if classification == "observed_change" else "heuristic_suspicion"))
        finding = Finding(finding_id=stable_id("finding", inventory.repository_id or "repository", rule, path, location,
            json.dumps([before, after], sort_keys=True)), scan_id=scan_id, finding_type="suspicious_change", title=title,
            explanation="A literal before/after change was observed between the supplied commits." if classification == "observed_change" else "Deterministic review signal; this does not establish malware or an attack.",
            component_instance_ids=sorted(set(component_ids or [])), repository_commit=commit,
            baseline_commit=baseline_commit if report["comparison_status"] == "available" else None,
            rule_id=rule, verification_status="provisional" if classification != "observed_change" else "verified_match",
            classification=classification, version_applicability="not_applicable", evidence_ids=evidence_ids, created_at=timestamp(),
            source_metadata=[observation])
        correlate_paths(finding, inventory, graph)
        store.validate([finding])
        report["findings"].append(finding.model_dump())

    def component_ids(path, name=None, package_path=None):
        if package_path is not None:
            source_pointer = "/packages/" + pointer(package_path)
            return [c.id for c in inventory.components if any(e.file == path and e.pointer == source_pointer for e in c.evidence)]
        project_roots = {p.root_id for p in inventory.projects if p.manifest_path == path}
        return [edge.child for edge in inventory.edges if edge.parent in project_roots and edge.dependency == name and edge.child]

    files = [path.relative_to(repo).as_posix() for path in walk_files(repo) if path.name in {"package.json", "package-lock.json", "Dockerfile"}
             or path.relative_to(repo).as_posix().startswith(".github/workflows/") and path.suffix in {".yml", ".yaml"}]
    if len(files) > 150:
        report["warnings"].append("Source inspection limit reached (150 metadata files)")
        files = files[:150]
    for path in sorted(changed - set(files)):
        if PurePosixPath(path).name in {"package.json", "package-lock.json", "Dockerfile"} or path.startswith(".github/workflows/"):
            report["warnings"].append(f"Changed/deleted metadata was not inspected: {path}")
    policy = json.loads(Path(__file__).with_name("policies").joinpath("npm_names.json").read_text())
    policy_evidence = None
    for path in files:
        try:
            raw, source_evidence = load_current(path)
            comparing = report["comparison_status"] == "available" and path in changed
            old_raw, _ = load_before(path) if comparing else (None, None)
            name = PurePosixPath(path).name
            if name == "Dockerfile":
                references = docker_references(raw)
                report["inspections"].append({"file": path, "type": "container_image_references", "references": references, "evidence_id": source_evidence,
                    "scope": "Dockerfile declarations only; images are not pulled, built, or scanned"})
                previous = docker_references(old_raw or b"")
                if comparing and [x["reference"] for x in previous] != [x["reference"] for x in references]:
                    emit("RULE_BASE_IMAGE_CHANGE", path, "FROM", previous, references, "Container base-image references changed")
            elif path.startswith(".github/workflows/"):
                permissions, actions = workflow_observations(workflow_data(raw))
                report["inspections"].append({"file": path, "type": "github_actions", "actions": actions, "permissions": permissions, "evidence_id": source_evidence})
                for location, action in actions.items():
                    if action.startswith("./"):
                        continue
                    immutable = bool(re.search(r"@[0-9a-fA-F]{40}\Z", action) or re.search(r"@sha256:[0-9a-fA-F]{64}\Z", action))
                    if not immutable:
                        emit("RULE_UNPINNED_ACTION", path, location, None, action, "CI action uses a mutable or unverified reference", "requires_review")
                if comparing:
                    previous, _ = workflow_observations(workflow_data(old_raw or b""))
                    for location in sorted(set(previous) | set(permissions)):
                        if previous.get(location) != permissions.get(location):
                            emit("RULE_WORKFLOW_PERMISSION_CHANGE", path, location, previous.get(location), permissions.get(location), "GitHub Actions permissions changed")
            elif comparing and name == "package.json":
                current = json.loads(raw)
                previous = json.loads(old_raw or b"{}")
                old_declarations = {(field, package): constraint for field, _, package, constraint, _ in declarations(previous)}
                new_declarations = {(field, package): constraint for field, _, package, constraint, _ in declarations(current)}
                scripts, old_scripts = current.get("scripts", {}), previous.get("scripts", {})
                if not isinstance(scripts, dict) or not isinstance(old_scripts, dict):
                    raise ValueError("Manifest scripts must be an object")
                install_changed = False
                for script in ["preinstall", "install", "postinstall", "prepare"]:
                    if script in scripts and scripts.get(script) != old_scripts.get(script):
                        install_changed = True
                        emit("RULE_NEW_INSTALL_SCRIPT", path, "/scripts/" + script, old_scripts.get(script), scripts[script], "Installation lifecycle script added or changed")
                for (field, package), constraint in new_declarations.items():
                    before = old_declarations.get((field, package))
                    if before == constraint:
                        continue
                    ids = component_ids(path, package)
                    emit("RULE_NEW_DEPENDENCY" if before is None else "RULE_VERSION_CHANGE", path,
                        f"/{field}/{pointer(package)}", before, constraint, "Dependency declaration added" if before is None else "Declared dependency constraint changed", component_ids=ids)
                    similar = next((trusted for trusted in policy["packages"] if one_edit(package, trusted)), None)
                    # Name similarity alone is insufficient. Require a new declaration plus an install-script change.
                    if before is None and similar and package not in policy["packages"] and install_changed and "/" not in package:
                        if policy_evidence is None:
                            policy_evidence = store.add("trusted_comparison_policy", "guardian/policies/npm_names.json", policy, reliability="versioned_review_policy")
                        emit("RULE_SIMILAR_PACKAGE_NAME", path, f"/{field}/{pointer(package)}", None, package,
                            "Package name resembles a reviewed comparison name and install scripts changed", "requires_review", ids,
                            {"comparison_name": similar, "policy_version": policy["version"], "policy_evidence_id": policy_evidence, "new_dependency": True, "install_script_changed": True})
                        report["findings"][-1]["evidence_ids"].append(policy_evidence)
            elif comparing and name == "package-lock.json":
                current, previous = json.loads(raw), json.loads(old_raw or b"{}")
                if current.get("lockfileVersion") not in {2, 3} or (previous and previous.get("lockfileVersion") not in {2, 3}):
                    raise ValueError("Changed lockfile format is unsupported; npm v2/v3 is required")
                packages, old_packages = current.get("packages", {}), previous.get("packages", {})
                if not isinstance(packages, dict) or not isinstance(old_packages, dict):
                    raise ValueError("Invalid lockfile package records")
                for location in sorted(packages.keys() & old_packages.keys()):
                    after, before = packages[location], old_packages[location]
                    if not isinstance(after, dict) or not isinstance(before, dict):
                        raise ValueError("Invalid lockfile package record")
                    for field, rule in [("version", "RULE_VERSION_CHANGE"), ("resolved", "RULE_REGISTRY_CHANGE"), ("integrity", "RULE_INTEGRITY_CHANGE")]:
                        if after.get(field) != before.get(field):
                            emit(rule, path, f"/packages/{pointer(location)}/{field}", before.get(field), after.get(field),
                                 f"Lockfile {field} metadata changed", component_ids=component_ids(path, package_path=location))
        except (ValueError, TypeError, KeyError, yaml.YAMLError, ToolError, OSError) as exc:
            report["errors"].append(f"{path}: {str(exc)[:1000]}")
    if report["warnings"] or report["errors"]:
        report["status"] = "partial"
    report["limitations"] = ["No malware conclusion, risk score, remediation, or runtime execution is produced.",
        "Without a valid baseline, only current-state workflow/container inspections run.",
        "Deleted metadata files and non-npm dependency changes are not evaluated by initial rules.",
        "Docker inspection covers literal FROM declarations; images are not scanned.",
        "Workflow references are inspected statically; referenced workflows/actions are not downloaded."]
    return report
