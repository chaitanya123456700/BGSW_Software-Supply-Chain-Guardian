from collections import deque

import networkx as nx

from .models import Inventory


def build_graph(inventory: Inventory, project_id: str | None = None) -> dict:
    graph = nx.MultiDiGraph()
    components = {component.id: component for component in inventory.components}
    if len(components) != len(inventory.components) or any(root not in components for root in inventory.roots):
        raise ValueError("Duplicate component IDs or missing application root")
    roots = list(inventory.roots)
    project_reachability = {}
    project_observations = {}
    verified = nx.DiGraph()
    verified.add_nodes_from(components)
    observed = nx.DiGraph()
    observed.add_nodes_from(components)
    for edge in inventory.edges:
        if edge.status == "resolved" and edge.dependency_type != "containment" and edge.child in components:
            verified.add_edge(edge.parent, edge.child)
        if edge.status in {"resolved", "declared_only", "inferred"} and edge.dependency_type != "containment" and edge.child in components:
            observed.add_edge(edge.parent, edge.child)
    for project in inventory.projects:
        reachable = {project.root_id} | nx.descendants(verified, project.root_id)
        project_reachability[project.id] = reachable
        project_observations[project.id] = {project.root_id} | nx.descendants(observed, project.root_id)
    if project_id is not None:
        project = next((project for project in inventory.projects if project.id == project_id), None)
        if project is None:
            raise ValueError("Project not found")
        included = project_observations[project_id]
        components = {identifier: component.model_copy(deep=True) for identifier, component in components.items() if identifier in included}
        roots = [project.root_id]
    graph.add_nodes_from(components)
    resolved, unresolved, declared, inferred, containment = [], [], [], [], []
    for edge in inventory.edges:
        if edge.parent not in components:
            if project_id is not None:
                continue
            raise ValueError("Edge parent is missing")
        if edge.dependency_type == "containment":
            if edge.child not in components:
                if project_id is not None:
                    continue
                raise ValueError("Containment child is missing")
            containment.append(edge.model_dump())
            continue
        if edge.status == "resolved":
            if edge.child not in components:
                raise ValueError("Resolved edge child is missing")
            graph.add_edge(edge.parent, edge.child)
            resolved.append(edge.model_dump())
        elif edge.status == "declared_only":
            if edge.child not in components:
                raise ValueError("Declared edge child is missing")
            graph.add_edge(edge.parent, edge.child)
            declared.append(edge.model_dump())
        elif edge.status == "inferred":
            if edge.child not in components:
                raise ValueError("Inferred edge child is missing")
            graph.add_edge(edge.parent, edge.child)
            inferred.append(edge.model_dump())
        else:
            unresolved.append(edge.model_dump())
    # One multi-source BFS stores a shortest witness, not exponentially many paths.
    predecessors = dict.fromkeys(roots)
    depths = dict.fromkeys(roots, 0)
    queue = deque(roots)
    while queue:
        parent = queue.popleft()
        for child in graph.successors(parent):
            if child not in depths:
                depths[child] = depths[parent] + 1
                predecessors[child] = parent
                queue.append(child)
    paths = {}
    for identifier, component in components.items():
        depth = depths.get(identifier)
        component.classification = ("root" if identifier in roots or component.kind == "repository" else "direct" if depth == 1
                                    else "transitive" if depth is not None else "unreachable")
        # Bound path materialization while retaining complete predecessor data.
        if depth is not None and depth <= 100:
            path, current = [], identifier
            while current is not None:
                path.append(current)
                current = predecessors[current]
            paths[identifier] = list(reversed(path))
    packages = [c for c in components.values() if c.id not in roots and c.kind not in {"application", "repository"}]
    nodes = []
    for component in components.values():
        node = component.model_dump()
        node["project_ids"] = [identifier for identifier, reachable in project_observations.items() if component.id in reachable]
        node["shared_by_projects"] = len(node["project_ids"])
        nodes.append(node)
    return {
        "roots": roots,
        "repository_id": inventory.repository_id, "project_id": project_id,
        "projects": [project.model_dump() for project in inventory.projects],
        "nodes": nodes,
        "edges": resolved, "unresolved": unresolved, "declared": declared, "inferred": inferred, "containment": containment,
        "coverage_statistics": {"declared_only_edges": len(declared), "containment_edges": len(containment),
            "inferred_edges": len(inferred),
            "trust_tiers": {tier: sum(c.trust_tier == tier for c in packages) for tier in
                           ("verified_lockfile", "declared_exact", "externally_inferred", "constraint_only", "unknown")},
            "resolved_components": sum(c.resolution_status == "resolved" for c in packages),
            "declared_only_components": sum(c.resolution_status == "declared_only" for c in packages)},
        "project_statistics": {project.id: {
            "reachable_instances": len(project_reachability[project.id]) - 1,
            "observed_instances": len(project_observations[project.id]) - 1,
            "resolved_edges": sum(edge.status == "resolved" and edge.dependency_type != "containment" and edge.parent in project_reachability[project.id] for edge in inventory.edges),
            "completeness_status": project.completeness_status,
        } for project in inventory.projects},
        "paths": paths, "predecessors": predecessors,
        "path_policy": "One shortest observed path per instance, including declared/inferred relationships; not proof of installation. Full paths capped at depth 100. Use predecessors for deeper paths.",
        "statistics": {
            "component_count": len(packages),
            "distinct_package_versions": len({(c.ecosystem, c.name, c.version or c.declared_version or c.inferred_version) for c in packages}),
            "direct_dependencies": sum(c.classification == "direct" for c in packages),
            "transitive_dependencies": sum(c.classification == "transitive" for c in packages),
            "unreachable_components": sum(c.classification == "unreachable" for c in packages),
            "edge_count": len(resolved), "unresolved_edges": len(unresolved), "root_count": len(roots),
        },
    }
