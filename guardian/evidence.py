import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from .files import write_json
from .models import Finding, Inventory, stable_id


def timestamp():
    return datetime.now(timezone.utc).isoformat()


class EvidenceStore:
    """Content-addressed source records; advisory bodies remain unmodified."""
    def __init__(self, directory: Path, commit: str):
        self.directory = directory
        self.commit = commit
        directory.mkdir(parents=True, exist_ok=True)
        self.records = {}
        self.lock = threading.Lock()

    def add(self, source_type: str, source: str, data, *, raw: bytes | None = None,
            retrieved_at: str | None = None, modified: str | None = None, reliability="observation", context=None) -> str:
        raw = raw if raw is not None else json.dumps(data, sort_keys=True, ensure_ascii=True).encode()
        digest = hashlib.sha256(raw).hexdigest()
        identifier = stable_id("evidence", source_type, source, digest, json.dumps(context, sort_keys=True))
        filename = identifier.replace(":", "-") + ".json"
        record = {"id": identifier, "source_type": source_type, "source": source,
            "retrieved_at": retrieved_at or timestamp(), "repository_commit": self.commit,
            "advisory_modified": modified, "tool_version": "guardian-phase2/0.2.0",
            "raw_artifact": "evidence/" + filename, "sha256": digest, "reliability": reliability, "context": context}
        with self.lock:
            (self.directory / filename).write_bytes(raw)
            self.records[identifier] = record
        return identifier

    def validate(self, findings: list[Finding]):
        for finding in findings:
            for identifier in finding.evidence_ids:
                if identifier not in self.records:
                    raise ValueError("Finding references nonexistent evidence")
                record = self.records[identifier]
                path = self.directory / Path(record["raw_artifact"]).name
                if hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]:
                    raise ValueError("Finding evidence content hash mismatch")

    def save(self):
        write_json(self.directory / "index.json", self.records)


def correlate_paths(finding: Finding, inventory: Inventory, graph: dict):
    """Follow verified instance edges only; graph reachability is not code reachability."""
    import networkx as nx
    network = nx.DiGraph()
    network.add_nodes_from(node["id"] for node in graph["nodes"])
    network.add_edges_from((edge["parent"], edge["child"]) for edge in graph["edges"]
                          if edge.get("status") == "resolved" and edge.get("dependency_type") != "containment")
    for project in inventory.projects:
        for identifier in finding.component_instance_ids:
            try:
                path = nx.shortest_path(network, project.root_id, identifier)
            except (nx.NodeNotFound, nx.NetworkXNoPath):
                continue
            if len(path) > 100 or len(finding.dependency_paths) >= 500:
                finding.graph_coverage_warnings.append("Dependency path export limit reached")
                continue
            finding.affected_application_ids.append(project.id)
            finding.dependency_paths.append({"project_id": project.id, "component_instance_id": identifier, "nodes": path})
    finding.affected_application_ids = sorted(set(finding.affected_application_ids))
    linked = {path["component_instance_id"] for path in finding.dependency_paths}
    if set(finding.component_instance_ids) - linked:
        finding.graph_coverage_warnings.append("A component is known but has no verified application dependency path")
