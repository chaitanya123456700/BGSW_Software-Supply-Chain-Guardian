"""Selectable export drafts from scanned files; never execute or modify repository code."""
import copy
import difflib
import io
import json
import re
import time
import zipfile
from pathlib import Path

from semantic_version import Version

from .files import read_json, safe_file
from .models import Inventory
from .remediation import FIELDS, checkout_target, digest, fixed_versions, registry_reference, source, verify_plan
from .draft_validation import validate_export

MAX_DRAFT_BYTES = 20 * 1024 * 1024
MISSING = object()
DRAFT_NOTE = (
    "Review-only export. Advisory-listed versions are suggestions, not verified fixes. "
    "Manifest-only changes require lockfile regeneration. Combined changes have not been rebuilt or tested."
)


def merge_change(before, after, current):
    """Merge independent JSON edits, refusing incompatible changes to the same value."""
    if before == after:
        return current
    if isinstance(before, dict) and isinstance(after, dict) and isinstance(current, dict):
        result = copy.deepcopy(current)
        for key in dict.fromkeys([*before, *after]):
            value = merge_change(before.get(key, MISSING), after.get(key, MISSING), current.get(key, MISSING))
            if value is MISSING:
                result.pop(key, None)
            else:
                result[key] = value
        return result
    if current != before and current != after:
        raise ValueError("Selected remedies conflict on the same file value; select them separately")
    return after if after is MISSING else copy.deepcopy(after)


def draft_plan(scan):
    plan = verify_plan(scan)
    repo = source(scan)
    inventory = Inventory.model_validate(read_json(scan / "artifacts", "components.json")[0])
    analysis = read_json(scan / "artifacts", "analysis_report.json")[0]
    originals, documents, options, changes = {}, {}, [], {}

    def original(relative):
        if Path(relative).name not in {"package.json", "package-lock.json"}:
            raise ValueError("Only dependency manifests and lockfiles can be exported")
        if any(part.startswith(".env") or part in {".aws", ".ssh", ".git", "node_modules"} for part in Path(relative).parts):
            raise ValueError("Private configuration and installed package paths cannot be exported")
        if relative not in originals:
            raw = safe_file(repo, relative).read_bytes()
            if sum(len(value.encode()) for value in originals.values()) + len(raw) > MAX_DRAFT_BYTES:
                raise ValueError("Remediation draft exceeds the 20 MiB export limit")
            originals[relative] = raw.decode("utf-8")
            documents[relative] = json.loads(originals[relative])
        return documents[relative]

    covered = set()
    for proposal in plan["proposals"]:
        edits = {}
        for relative in proposal["before"]:
            original(relative)
            raw = safe_file(scan / "artifacts", f"remediation/proposals/{proposal['id']}/{Path(relative).name}").read_bytes()
            edits[relative] = json.loads(raw)
        identifier = proposal["id"]
        options.append({"id": identifier, "name": proposal["name"], "from_version": proposal["from_version"],
                        "to_version": proposal["to_version"], "files": sorted(edits), "kind": "prepared_patch",
                        "note": "Prepared exact patch. Exporting it does not approve or validate a combined rebuild."})
        changes[identifier] = edits
        covered.add((proposal["manifest_path"], proposal["name"]))

    findings = {}
    for finding in analysis["findings"]:
        if (finding["finding_type"] != "vulnerability" or finding["verification_status"] != "verified_match"
                or finding.get("advisory_category") == "malicious_package"):
            continue
        for identifier in finding["component_instance_ids"]:
            findings.setdefault(identifier, []).append(finding)
    projects = {project.path: project for project in inventory.projects}
    seen = set()
    for component in inventory.components:
        project = projects.get(component.project)
        if not project or not project.manifest_path or component.ecosystem != "npm" or not component.version:
            continue
        key = (project.manifest_path, component.name)
        if key in covered or key in seen or not findings.get(component.id):
            continue
        if not any(edge.parent == project.root_id and edge.child == component.id and edge.status == "resolved" for edge in inventory.edges):
            continue
        try:
            manifest = original(project.manifest_path)
            fields = [field for field in FIELDS if component.name in manifest.get(field, {})]
            if not fields:
                continue
            for field in fields:
                registry_reference(manifest[field][component.name])
            versions = fixed_versions([record for finding in findings[component.id] for record in finding["source_metadata"]], component.name)
            targets = [version for version in versions if version > Version(component.version)]
            if not targets:
                continue
        except (ValueError, TypeError):
            continue
        target = str(max(targets))
        updated = copy.deepcopy(manifest)
        for field in fields:
            updated[field][component.name] = target
        identifier = "draft-" + digest([*key, component.version, target])[:24]
        options.append({"id": identifier, "name": component.name, "from_version": component.version, "to_version": target,
                        "files": [project.manifest_path], "kind": "advisory_draft",
                        "note": "Advisory-listed fixed version; review compatibility and regenerate the lockfile. Not a verified fix."})
        changes[identifier] = {project.manifest_path: updated}
        seen.add(key)
        if len(options) >= 100:
            break
    public = {"options": options, "note": DRAFT_NOTE, "source_sha256": plan["source_sha256"], "checkout_path": str(checkout_target(scan)[1].resolve()),
              "plan_sha256": digest(plan), "version": 1}
    public["digest"] = digest(public)
    return public, originals, documents, changes


def apply_selection(scan, plan_digest, selected):
    started = time.perf_counter()
    plan, originals, documents, changes = draft_plan(scan)
    if plan_digest != plan["digest"]:
        raise ValueError("Remediation changed; reload the draft before applying selections")
    if len(selected) != len(set(selected)) or any(identifier not in changes for identifier in selected):
        raise ValueError("Select only current, unique remedy IDs")
    updated = copy.deepcopy(documents)
    touched = set()
    for option in plan["options"]:
        if option["id"] not in selected:
            continue
        for relative, after in changes[option["id"]].items():
            updated[relative] = merge_change(documents[relative], after, updated[relative])
            touched.add(relative)
    files, combined = [], ""
    for relative in sorted(touched):
        before = originals[relative]
        indent_match = re.search(r'\n([ \t]+)"', before)
        indent = indent_match.group(1) if indent_match else None
        after = json.dumps(updated[relative], indent=indent, ensure_ascii=False) + ("\n" if before.endswith("\n") else "")
        if "\r\n" in before:
            after = after.replace("\n", "\r\n")
        lines = difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile="a/" + relative, tofile="b/" + relative)
        diff = "".join(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n" for line in lines)
        files.append({"path": relative, "content": after, "sha256": digest(after.encode())})
        combined += diff
    if sum(len(item["content"].encode()) for item in files) > MAX_DRAFT_BYTES:
        raise ValueError("Selected files exceed the 20 MiB export limit")
    selection = {"digest": plan["digest"], "selected": selected, "files": files,
            "diff": combined[:200000], "diff_truncated": len(combined) > 200000,
            "note": plan["note"], "original_checkout_modified": False, "validated": False}
    selection["validation"] = validate_export(source(scan), plan, documents, changes, selection)
    selection["validation"]["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 1)
    if selection["validation"]["status"] == "failed":
        raise ValueError("Draft integrity validation failed; reload the plan before exporting")
    return selection, combined


def export_zip(selection, full_diff):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for item in selection["files"]:
            archive.writestr(item["path"], item["content"])
        archive.writestr("guardian-selected-changes.diff", full_diff)
        archive.writestr("GUARDIAN-REVIEW.txt", selection["note"] + "\nSelected remedies: " + ", ".join(selection["selected"]) + "\n")
        archive.writestr("guardian-draft-validation.json", json.dumps(selection["validation"], indent=2) + "\n")
    return output.getvalue()
