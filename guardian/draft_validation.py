"""Offline export validation: exact JSON edit sets and SHA-256 file identities."""
import json
from pathlib import Path

from .files import read_json
from .remediation import FIELDS, digest, snapshot

ABSENT = object()


def json_edits(before, after, path=()):
    """An edit is a JSON path plus hashes of its old and new values."""
    if isinstance(before, dict) and isinstance(after, dict):
        return set().union(*(json_edits(before.get(key, ABSENT), after.get(key, ABSENT), (*path, key))
                             for key in before.keys() | after.keys())) if before or after else set()
    old = "absent" if before is ABSENT else digest(before)
    new = "absent" if after is ABSENT else digest(after)
    return {(path, old, new)} if old != new else set()


def lock_consistency(repo, options, exported):
    issues = []
    for option in options:
        for name in option["files"]:
            if Path(name).name != "package.json":
                continue
            lock_path = (Path(name).parent / "package-lock.json").as_posix()
            try:
                lock = exported[lock_path] if lock_path in exported else read_json(repo, lock_path)[0]
                manifest = exported[name]
                entry = (lock.get("packages", {}).get("node_modules/" + option["name"], {})
                         if lock.get("lockfileVersion") in {2, 3} else lock.get("dependencies", {}).get(option["name"], {}))
                root = lock.get("packages", {}).get("", {})
                agrees = entry.get("version") == option["to_version"]
                for field in FIELDS:
                    if option["name"] in manifest.get(field, {}):
                        agrees &= manifest[field][option["name"]] == option["to_version"]
                        if lock.get("lockfileVersion") in {2, 3}:
                            agrees &= root.get(field, {}).get(option["name"]) == option["to_version"]
                if not agrees:
                    issues.append(f"{option['name']}: regenerate {lock_path} for the selected version")
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                issues.append(f"{option['name']}: a readable matching {lock_path} is required")
    return {"status": "needs_regeneration" if issues else "passed", "scope": "selected_direct_dependencies",
            "message": "Lockfile regeneration required" if issues else "Selected version pins agree with the lockfile",
            "issues": list(dict.fromkeys(issues))}


def validate_export(repo, plan, documents, changes, selection):
    options = [option for option in plan["options"] if option["id"] in selection["selected"]]
    if not options:
        return {"status": "not_run", "scope": "export_integrity", "checks": [], "passed_checks": 0,
                "reason": "Apply at least one remedy before validating a draft"}
    expected, actual, parsed = set(), set(), {}
    for option in options:
        for name, after in changes[option["id"]].items():
            expected.update((name, *edit) for edit in json_edits(documents[name], after))
    syntax_ok, hashes_ok = True, True
    for item in selection["files"]:
        hashes_ok &= digest(item["content"].encode()) == item["sha256"]
        try:
            parsed[item["path"]] = json.loads(item["content"])
            actual.update((item["path"], *edit) for edit in json_edits(documents.get(item["path"], ABSENT), parsed[item["path"]]))
        except (ValueError, TypeError):
            syntax_ok = False
    source_ok = digest(snapshot(repo)) == plan["source_sha256"]
    expected_files = {name for option in options for name in changes[option["id"]]}
    actual_files = [item["path"] for item in selection["files"]]
    exact = actual == expected and set(actual_files) == expected_files and len(actual_files) == len(set(actual_files))
    checks = [{"name": title, "status": "passed" if passed else "failed"} for title, passed in [
        ("Source unchanged", source_ok), ("Valid JSON", syntax_ok),
        ("Exact selected edits", exact), ("SHA-256 file hashes", hashes_ok)]]
    receipt = {"plan_sha256": plan["digest"], "source_sha256": plan["source_sha256"],
               "selected": sorted(selection["selected"]), "files": {item["path"]: item["sha256"] for item in selection["files"]}}
    return {"version": 1, "scope": "export_integrity", "status": "passed" if all(check["status"] == "passed" for check in checks) else "failed",
            "checks": checks, "passed_checks": sum(check["status"] == "passed" for check in checks),
            "proof": {"rule": "actual_edits = union(selected_edits)", "expected_edits": len(expected),
                      "actual_edits": len(actual), "unexpected_edits": len(actual - expected), "missing_edits": len(expected - actual)},
            "receipt_sha256": digest(receipt), **receipt,
            "lockfile": lock_consistency(repo, options, parsed),
            "build_tests": {"status": "not_run", "reason": "Offline export checks do not execute repository code"},
            "security_verification": "not_run",
            "limitations": "Proves selected file changes and integrity only. It does not prove compatibility, exploit removal, or build/test success."}
