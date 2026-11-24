"""Bounded deps.dev inference. This module never queries advisory endpoints."""
import json
import re
import time
from pathlib import Path
from urllib.parse import quote

import httpx
from packaging.requirements import Requirement
from packaging.version import Version as PythonVersion
from semantic_version import NpmSpec, Version as NpmVersion

from .evidence import EvidenceStore
from .models import Component, Edge, Evidence, Inventory, stable_id
from .npm import MAX_COMPONENTS, MAX_EDGES
from .process import SCAN_CANCEL_CHECK, SCAN_DEADLINE

MAX_NODES = 3000
MAX_GRAPH_EDGES = 10000
MAX_VERSIONS = 10000
NPM_NAME = re.compile(r"(?:@[a-zA-Z0-9._~-]+/)?[a-zA-Z0-9._~-]+\Z")
PYTHON_NAME = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\Z")


class DepsDevError(ValueError):
    pass


def valid_name(system, name):
    return (isinstance(name, str) and len(name) <= 214
            and bool((NPM_NAME if system == "NPM" else PYTHON_NAME).fullmatch(name))
            and name not in {".", ".."})


def version_parser(system):
    return NpmVersion if system == "NPM" else PythonVersion


def requirement_spec(component):
    raw = component.requested_constraint or ""
    if len(raw) > 1024:
        raise DepsDevError("Constraint exceeds inference limit")
    if component.ecosystem == "npm":
        try:
            return "NPM", NpmSpec(raw.strip() or "*")
        except ValueError as exc:
            raise DepsDevError("Unsupported npm reference or constraint; declaration retained without fetching") from exc
    requirement = Requirement(raw)
    if requirement.url or requirement.marker or requirement.extras:
        raise DepsDevError("URL, conditional, or extra requirements remain declaration-only")
    return "PYPI", requirement.specifier


def select_version(data, system, name, spec):
    key = data.get("packageKey", {})
    versions = data.get("versions")
    if not isinstance(key, dict) or key.get("system") != system or key.get("name") != name:
        raise DepsDevError("deps.dev package identity mismatch")
    if not isinstance(versions, list) or len(versions) > MAX_VERSIONS:
        raise DepsDevError("Invalid or oversized deps.dev version list")
    matches = []
    for entry in versions:
        key = entry.get("versionKey", {}) if isinstance(entry, dict) else {}
        if not isinstance(key, dict) or key.get("system") != system or key.get("name") != name:
            raise DepsDevError("deps.dev version identity mismatch")
        value = key.get("version")
        if not isinstance(value, str) or len(value) > 200:
            raise DepsDevError("Invalid deps.dev version")
        try:
            version = version_parser(system)(value)
        except ValueError:
            continue
        if system == "PYPI" or spec.match(version):
            matches.append((version, value))
    if system == "PYPI":
        allowed = set(spec.filter(version for version, _ in matches))
        matches = [pair for pair in matches if pair[0] in allowed]
    if not matches:
        raise DepsDevError("No indexed version satisfies the declared constraint")
    return max(matches, key=lambda pair: (pair[0], pair[1]))[1]


class DepsDevClient:
    def __init__(self, store: EvidenceStore, *, transport=None, max_requests=40, budget=30):
        self.store = store
        deadline = SCAN_DEADLINE.get()
        self.deadline = min(time.monotonic() + budget, deadline) if deadline else time.monotonic() + budget
        self.max_requests, self.requests, self.bytes_received = max_requests, 0, 0
        self.responses, self.reused_responses = {}, 0
        self.unavailable = False
        self.client = httpx.Client(base_url="https://api.deps.dev", trust_env=False, follow_redirects=False,
            timeout=httpx.Timeout(8, connect=3), transport=transport, headers={"User-Agent": "guardian-discovery/0.3.0"})

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.client.close()

    def get(self, system, name, version=None):
        SCAN_CANCEL_CHECK.get()()
        if system not in {"NPM", "PYPI"} or not valid_name(system, name):
            raise DepsDevError("Unsupported inference package identity")
        path = f"/v3/systems/{system.lower()}/packages/{quote(name, safe='')}"
        if version is not None:
            if not isinstance(version, str) or len(version) > 200:
                raise DepsDevError("Invalid inference version")
            version_parser(system)(version)
            path += f"/versions/{quote(version, safe='')}:dependencies"
        if path in self.responses:
            self.reused_responses += 1
            return self.responses[path]
        remaining = self.deadline - time.monotonic()
        if self.unavailable or remaining <= 0 or self.requests >= self.max_requests:
            raise DepsDevError("deps.dev request/time budget exhausted or service unavailable")
        self.requests += 1
        try:
            with self.client.stream("GET", path, timeout=min(8, remaining)) as response:
                chunks, size = [], 0
                for chunk in response.iter_bytes():
                    SCAN_CANCEL_CHECK.get()()
                    size += len(chunk)
                    self.bytes_received += len(chunk)
                    if size > 4 * 1024 * 1024 or self.bytes_received > 16 * 1024 * 1024 or time.monotonic() > self.deadline:
                        self.unavailable = True
                        self.store.add("depsdev_response_limit", str(response.url), {"received_bytes": size},
                                       reliability="source_error")
                        raise DepsDevError("deps.dev response size/time budget exceeded")
                    chunks.append(chunk)
                raw = b"".join(chunks)
                evidence_id = self.store.add("depsdev_graph" if version else "depsdev_versions", str(response.url),
                    None, raw=raw, reliability="external_inference" if response.status_code == 200 else "source_error",
                    context={"http_status": response.status_code})
                if response.status_code != 200:
                    if response.status_code == 429 or response.status_code >= 500:
                        self.unavailable = True
                    raise DepsDevError(f"deps.dev HTTP {response.status_code}; no retry was attempted")
        except httpx.TransportError as exc:
            self.unavailable = True
            self.store.add("depsdev_transport_error", "https://api.deps.dev" + path,
                           {"error": type(exc).__name__}, reliability="source_error")
            raise DepsDevError("deps.dev transport unavailable") from exc
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise DepsDevError("deps.dev returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise DepsDevError("deps.dev response must be an object")
        record = self.store.records[evidence_id]
        evidence = Evidence(file="discovery/" + record["raw_artifact"], pointer="", sha256=record["sha256"])
        self.responses[path] = data, evidence
        return data, evidence


def import_graph(inventory, component, data, evidence, system, selected):
    nodes, edges = data.get("nodes"), data.get("edges", [])
    if (not isinstance(nodes, list) or not nodes or len(nodes) > MAX_NODES
            or not isinstance(edges, list) or len(edges) > MAX_GRAPH_EDGES):
        raise DepsDevError("Invalid or oversized deps.dev graph")
    if data.get("error"):
        raise DepsDevError("deps.dev reports an incomplete dependency graph")
    if len(inventory.components) + len(nodes) - 1 > MAX_COMPONENTS or len(inventory.edges) + len(edges) > MAX_EDGES:
        raise DepsDevError("Combined inventory limit prevents graph inference")
    parsed = []
    for index, node in enumerate(nodes):
        key = node.get("versionKey", {}) if isinstance(node, dict) else {}
        if (not isinstance(key, dict) or key.get("system") != system or not valid_name(system, key.get("name"))
                or node.get("bundled") or node.get("errors")):
            raise DepsDevError("Unsupported, bundled, or incomplete deps.dev node")
        version = key.get("version")
        if not isinstance(version, str) or len(version) > 200:
            raise DepsDevError("Invalid deps.dev graph version")
        version_parser(system)(version)
        if index == 0 and (key["name"] != component.name or version != selected):
            raise DepsDevError("deps.dev graph root identity mismatch")
        parsed.append(key)
    for edge in edges:
        if not isinstance(edge, dict):
            raise DepsDevError("Invalid deps.dev graph edge")
        source, target = edge.get("fromNode", 0), edge.get("toNode", 0)
        if (type(source) is not int or type(target) is not int or not 0 <= source < len(nodes)
                or not 0 <= target < len(nodes) or not isinstance(edge.get("requirement", ""), str)
                or len(edge.get("requirement", "")) > 1024):
            raise DepsDevError("deps.dev edge references an invalid node or requirement")
    # Validate the whole response before adding any externally inferred topology.
    identifiers = [component.id] + [stable_id("inferred", component.id, str(index), key["name"], key["version"])
                                   for index, key in enumerate(parsed[1:], 1)]
    for index, key in enumerate(parsed[1:], 1):
        proof = evidence.model_copy(update={"pointer": f"/nodes/{index}"})
        inventory.components.append(Component(id=identifiers[index], name=key["name"], ecosystem=component.ecosystem,
            identity=f"pkg:{'npm' if system == 'NPM' else 'pypi'}/{quote(key['name'], safe='/')}",
            path=component.path, project=component.project, version=None, inferred_version=key["version"],
            dev=component.dev, optional=component.optional,
            resolution_status="inferred", version_source="deps.dev", evidence=[], inference_evidence=[proof]))
    for index, edge in enumerate(edges):
        source, target = edge.get("fromNode", 0), edge.get("toNode", 0)
        inventory.edges.append(Edge(parent=identifiers[source], child=identifiers[target], dependency=parsed[target]["name"],
            dependency_type="production", constraint=edge.get("requirement", ""), status="inferred",
            evidence=evidence.model_copy(update={"pointer": f"/edges/{index}"}),
            reason="deps.dev generic-platform resolution; repository installation is unverified",
            version_satisfaction="externally_inferred"))
    component.inferred_version = selected
    component.inference_evidence.append(evidence.model_copy(update={"pointer": "/nodes/0"}))


def infer_dependencies(inventory: Inventory, root_ids: set[str], artifacts: Path, commit: str, *, transport=None):
    report = {"provider": "deps.dev", "status": "not_needed", "requests": 0, "reused_responses": 0,
              "outcomes": [], "warnings": [], "selection_policy": "Highest indexed version satisfying each supported declaration; not an installed or joint project resolution"}
    eligible = {e.child for e in inventory.edges if e.parent in root_ids and e.status == "declared_only"}
    roots = [c for c in inventory.components if c.id in eligible]
    if not roots:
        return report
    store = EvidenceStore(artifacts / "discovery/evidence", commit)
    report["status"] = "partial"
    with DepsDevClient(store, transport=transport) as client:
        try:
            for index, component in enumerate(roots):
                SCAN_CANCEL_CHECK.get()()
                if index >= 20:
                    report["warnings"].append("Inference limited to 20 direct declarations; remaining declarations were retained")
                    break
                outcome = {"component_id": component.id, "status": "unavailable"}
                try:
                    system, spec = requirement_spec(component)
                    if not valid_name(system, component.name):
                        raise DepsDevError("Unsupported package name for inference")
                    data, versions_evidence = client.get(system, component.name)
                    selected = select_version(data, system, component.name, spec)
                    data, graph_evidence = client.get(system, component.name, selected)
                    import_graph(inventory, component, data, graph_evidence, system, selected)
                    component.inference_evidence.append(versions_evidence)
                    outcome.update(status="inferred", inferred_version=selected)
                except ValueError as exc:
                    outcome["reason"] = str(exc)[:300]
                report["outcomes"].append(outcome)
        finally:
            store.save()
            report.update(requests=client.requests, reused_responses=client.reused_responses)
    report["warnings"].append("deps.dev graphs are external inference for a generic platform; constraints, peers, extras, and environments are not jointly resolved for this repository")
    return report
