from guardian.graph import build_graph
from test_npm import extract


def test_graph_uses_reachability_not_installation_depth_and_handles_cycles(tmp_path):
    inventory = extract(tmp_path, {
        "": {"name": "app", "dependencies": {"a": "1"}},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "1", "missing": "1"}},
        "node_modules/b": {"version": "1.0.0", "dependencies": {"a": "1"}},
        "node_modules/orphan": {"version": "1.0.0"},
    })
    graph = build_graph(inventory)
    classes = {n["name"]: n["classification"] for n in graph["nodes"]}
    assert classes == {"app": "root", "a": "direct", "b": "transitive", "orphan": "unreachable"}
    assert graph["statistics"] == {"component_count": 3, "distinct_package_versions": 3,
        "direct_dependencies": 1, "transitive_dependencies": 1, "unreachable_components": 1,
        "edge_count": 3, "unresolved_edges": 1, "root_count": 1}
    ids = {n["id"] for n in graph["nodes"]}
    assert all(e["parent"] in ids and e["child"] in ids for e in graph["edges"])
    b = next(n for n in graph["nodes"] if n["name"] == "b")
    assert graph["paths"][b["id"]] == [inventory.roots[0], inventory.components[1].id, b["id"]]
