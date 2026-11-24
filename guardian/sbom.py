import hashlib
import json
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

from jsonschema import Draft7Validator
from referencing import Registry, Resource

from .files import MAX_FILE, walk_files
from .models import Inventory
from .process import run_tool


def validate_sbom(document: dict):
    directory = Path(__file__).with_name("schemas")
    registry = Registry()
    for path in directory.glob("*.json"):
        schema = json.loads(path.read_text())
        resource = Resource.from_contents(schema)
        registry = registry.with_resource(schema["$id"], resource)
        registry = registry.with_resource("http://cyclonedx.org/schema/" + path.name, resource)
    schema = json.loads((directory / "bom-1.6.schema.json").read_text())
    try:
        Draft7Validator(schema, registry=registry).validate(document)
    except Exception as exc:
        raise ValueError(f"CycloneDX schema validation failed: {str(exc)[:500]}") from exc
    references = []

    def visit(item):
        if "bom-ref" in item:
            references.append(item["bom-ref"])
        for child in item.get("components", []) + item.get("services", []):
            visit(child)

    visit(document)
    if document.get("metadata", {}).get("component"):
        visit(document["metadata"]["component"])
    if len(references) != len(set(references)):
        raise ValueError("Duplicate CycloneDX reference")
    references = set(references)
    for dependency in document.get("dependencies", []):
        if dependency["ref"] not in references or any(ref not in references for ref in dependency.get("dependsOn", [])):
            raise ValueError("CycloneDX dependency reference does not exist")


def generate_sbom(repo_path: Path, artifacts: Path, commit: str, inventory: Inventory) -> dict:
    result = {"status": "failed", "tool": "syft", "tool_version": None, "commit": commit,
              "timestamp": datetime.now(timezone.utc).isoformat(), "error": None,
              "original_artifact": "sbom.json", "skipped_files": [], "reconciliation": None}
    try:
        result["tool_version"] = run_tool(["syft", "version", "-o", "json"], artifacts, timeout=10).stdout.strip()
        with tempfile.TemporaryDirectory(prefix="syft-source-", dir=artifacts) as temporary:
            snapshot = Path(temporary) / "source"
            snapshot.mkdir()
            for source in walk_files(repo_path):
                relative = source.relative_to(repo_path)
                if source.stat().st_size > MAX_FILE:
                    result["skipped_files"].append(relative.as_posix())
                    continue
                destination = snapshot / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            config = Path(temporary) / "syft.yaml"
            config.write_text("check-for-app-update: false\nparallelism: 2\n"
                              "javascript:\n  include-dev-dependencies: true\n  search-remote-licenses: false\n"
                              "python:\n  search-remote-licenses: false\n  guess-unpinned-requirements: false\n"
                              "golang:\n  use-packages-lib: false\n  search-remote-licenses: false\n"
                              "  search-local-mod-cache-licenses: false\n  search-local-vendor-licenses: false\n"
                              "java:\n  use-network: false\n  use-maven-local-repository: false\n"
                              "cpp:\n  vcpkg-allow-git-clone: false\n")
            completed = run_tool(["syft", "scan", f"dir:{snapshot}", "--config", str(config),
                                  "--parallelism", "2", "-o", "cyclonedx-json@1.6"],
                                 artifacts, timeout=120)
            (artifacts / "syft.stderr.log").write_text(completed.stderr)
            # Preserve exactly the original Syft JSON, including on validation failure.
            raw = completed.stdout.encode()
            (artifacts / "sbom.json").write_bytes(raw)
            result["sha256"] = hashlib.sha256(raw).hexdigest()
            document = json.loads(raw)
            validate_sbom(document)
        identities = {}
        for component in document.get("components", []):
            purl = component.get("purl", "")
            if purl.startswith("pkg:npm/"):
                value = unquote(purl[len("pkg:npm/"):].split("?", 1)[0].split("#", 1)[0])
                if "@" in value[1:]:
                    name, version = value.rsplit("@", 1)
                    identities.setdefault((name, version), []).append(component.get("bom-ref"))
        packages = [c for c in inventory.components if c.kind not in {"application", "repository"}
                    and c.resolution_status == "resolved" and c.version is not None]
        matches = {c.id: identities.get((c.name, c.version), []) for c in packages}
        result["reconciliation"] = {
            "matched_instances": sum(bool(refs) for refs in matches.values()),
            "unmatched_instances": [identifier for identifier, refs in matches.items() if not refs],
            "declared_only_instances": [c.id for c in inventory.components if c.resolution_status == "declared_only"],
            "inferred_instances": [c.id for c in inventory.components if c.inferred_version is not None],
            "declaration_policy": "Manifest constraints remain declared-only even if Syft independently reports a version. They are not proof of installation.",
            "instance_to_sbom_refs": matches,
            "syft_component_count": len(document.get("components", [])),
            "syft_dependency_records": len(document.get("dependencies", [])),
            "relationship_policy": "Original Syft relationships remain unchanged. Adapter edges are separate lockfile evidence.",
        }
        result["status"] = "completed"
    except Exception as exc:
        result["error"] = str(exc)[:3000]
        (artifacts / "syft.stderr.log").write_text(result["error"])
    return result
