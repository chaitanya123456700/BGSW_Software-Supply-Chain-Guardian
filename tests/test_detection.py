import json

from guardian.detection import detect_ecosystems


def test_unsupported_ecosystems_and_nested_projects_are_detected(tmp_path):
    (tmp_path / "requirements.txt").write_text("fastapi==1.0")
    nested = tmp_path / "apps" / "web"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text('{"name":"web","packageManager":"pnpm@9"}')
    (nested / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'")
    result = detect_ecosystems(tmp_path)
    assert {(p.ecosystem, p.package_manager, p.supported) for p in result} == {
        ("python", "pip", True), ("npm", "pnpm", False)}
    assert next(p for p in result if p.package_manager == "pnpm").project_root == "apps/web"


def test_stale_npm_lock_is_not_used_for_yarn_project(tmp_path):
    (tmp_path / "package.json").write_text('{"packageManager":"yarn@4"}')
    (tmp_path / "yarn.lock").write_text("")
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3}))
    assert all(not p.supported for p in detect_ecosystems(tmp_path))


def test_npm_v1_is_explicitly_unsupported(tmp_path):
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion":1}')
    result = detect_ecosystems(tmp_path)
    assert len(result) == 1 and not result[0].supported
    assert "v2/v3" in result[0].reason


def test_nested_pnpm_manifest_inherits_package_manager(tmp_path):
    (tmp_path / "pnpm-lock.yaml").write_text("")
    package = tmp_path / "packages/web"
    package.mkdir(parents=True)
    (package / "package.json").write_text('{"name":"web"}')
    assert {p.package_manager for p in detect_ecosystems(tmp_path)} == {"pnpm"}


def test_npm_workspace_manifest_is_covered_once_by_root_lock(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"workspaces": ["packages/*"]}, "packages/web": {"name": "web"}}}))
    package = tmp_path / "packages/web"
    package.mkdir(parents=True)
    (package / "package.json").write_text('{"name":"web"}')
    projects = detect_ecosystems(tmp_path)
    assert all(project.supported for project in projects)
    assert projects[1].covered_by == "package-lock.json"
