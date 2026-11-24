import json

import pytest

from guardian.npm import extract_npm


def test_direct_dependency_keeps_exact_version_and_evidence(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"": {"name": "app", "dependencies": {"a": "^1.0.0"}},
                     "node_modules/a": {"version": "1.2.3"}},
    }))
    result = extract_npm(tmp_path, "package-lock.json")
    assert [(c.name, c.version) for c in result.components] == [("app", None), ("a", "1.2.3")]
    assert result.edges[0].parent == result.roots[0]
    assert result.edges[0].child == result.components[1].id
    assert result.edges[0].evidence.pointer == "/packages//dependencies/a"
    assert len(result.edges[0].evidence.sha256) == 64


def extract(tmp_path, records, version=3):
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": version, "packages": records}))
    return extract_npm(tmp_path, "package-lock.json")


@pytest.mark.parametrize("version", [2, 3])
def test_hoisting_nested_versions_scopes_and_repeated_references(tmp_path, version):
    result = extract(tmp_path, {
        "": {"name": "app", "dependencies": {"a": "1", "b": "1", "@scope/c": "2"}},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"shared": "1", "b": "1"}},
        "node_modules/b": {"version": "1.0.0", "dependencies": {"shared": "2"}},
        "node_modules/@scope/c": {"version": "2.0.0", "dependencies": {"shared": "1"}},
        "node_modules/shared": {"version": "1.0.0"},
        "node_modules/b/node_modules/shared": {"version": "2.0.0"},
    }, version)
    by_id = {c.id: c for c in result.components}
    edges = [(by_id[e.parent].path, by_id[e.child].path) for e in result.edges]
    assert ("node_modules/a", "node_modules/shared") in edges
    assert ("node_modules/b", "node_modules/b/node_modules/shared") in edges
    assert ("node_modules/@scope/c", "node_modules/shared") in edges
    assert len(edges) == 7
    assert {c.version for c in result.components if c.name == "shared"} == {"1.0.0", "2.0.0"}


def test_peer_resolves_in_parent_context_and_optional_overrides_production(tmp_path):
    result = extract(tmp_path, {
        "": {"dependencies": {"a": "1", "absent": "1"}, "optionalDependencies": {"absent": "2"},
             "devDependencies": {"test": "3"}},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"peer": "2"},
                           "peerDependencies": {"peer": "1", "missing-peer": "*"},
                           "peerDependenciesMeta": {"missing-peer": {"optional": True}}},
        "node_modules/peer": {"version": "1.0.0"},
        "node_modules/a/node_modules/peer": {"version": "2.0.0"},
        "node_modules/test": {"version": "3.0.0", "dev": True},
    })
    peers = [e for e in result.edges if e.dependency_type == "peer"]
    by_id = {c.id: c for c in result.components}
    assert by_id[peers[0].child].version == "1.0.0"
    assert peers[1].child is None and peers[1].optional
    absent = [e for e in result.edges if e.dependency == "absent"]
    assert len(absent) == 1 and absent[0].dependency_type == "optional"
    assert absent[0].constraint == "2" and absent[0].status == "unresolved"
    assert any(e.dependency_type == "development" for e in result.edges)


def test_local_link_keeps_instance_and_resolves_from_real_target(tmp_path):
    result = extract(tmp_path, {
        "": {"dependencies": {"local": "file:packages/local"}},
        "packages/local": {"name": "local", "version": "1.0.0", "dependencies": {"a": "1"}},
        "node_modules/local": {"link": True, "resolved": "packages/local"},
        "packages/local/node_modules/a": {"version": "1.0.0"},
    })
    by_id = {c.id: c for c in result.components}
    link = next(c for c in result.components if c.link_target)
    assert link.version == "1.0.0"
    assert any(e.parent == link.id and by_id[e.child].path == "packages/local/node_modules/a" for e in result.edges)


@pytest.mark.parametrize("payload", ["{", "[]", '{"lockfileVersion":1}',
    '{"lockfileVersion":3,"packages":{}}',
    '{"lockfileVersion":3,"packages":{"":{},"../escape":{}}}'])
def test_invalid_lockfile_is_rejected(tmp_path, payload):
    (tmp_path / "package-lock.json").write_text(payload)
    with pytest.raises(ValueError):
        extract_npm(tmp_path, "package-lock.json")


def test_missing_version_stays_unknown_and_broken_link_is_unresolved(tmp_path):
    result = extract(tmp_path, {"": {"dependencies": {"a": "*", "b": "*"}},
                                "node_modules/a": {}, "node_modules/b": {"link": True, "resolved": "../outside"}})
    assert result.components[1].version is None
    assert result.components[1].identity is None
    assert result.edges[1].status == "unresolved"
    assert result.warnings


def test_workspaces_are_connected_without_inventing_dependency_declarations(tmp_path):
    from guardian.graph import build_graph
    result = extract(tmp_path, {
        "": {"name": "monorepo", "workspaces": ["packages/*"]},
        "packages/web": {"name": "web", "version": "1.0.0", "dependencies": {"a": "1"}},
        "node_modules/web": {"resolved": "packages/web", "link": True},
        "node_modules/a": {"version": "1.0.0"},
    })
    graph = build_graph(result)
    workspace = next(n for n in graph["nodes"] if n["path"] == "packages/web")
    assert workspace["kind"] == "workspace" and workspace["classification"] == "direct"
    assert any(e["dependency_type"] == "workspace" and e["child"] == workspace["id"] for e in graph["edges"])
    assert next(n for n in graph["nodes"] if n["name"] == "a")["classification"] == "transitive"


def test_peer_does_not_resolve_from_own_nested_installation(tmp_path):
    result = extract(tmp_path, {
        "": {"dependencies": {"a": "1"}},
        "node_modules/a": {"version": "1.0.0", "peerDependencies": {"peer": "1"}},
        "node_modules/a/node_modules/peer": {"version": "1.0.0"},
    })
    assert result.edges[-1].status == "unresolved"


def test_alias_uses_record_identity_and_installation_name_for_resolution(tmp_path):
    result = extract(tmp_path, {"": {"dependencies": {"alias": "npm:real@1.0.0"}},
        "node_modules/alias": {"name": "real", "version": "1.0.0"}})
    assert result.components[1].name == "real"
    assert result.edges[0].dependency == "alias" and result.edges[0].child == result.components[1].id
