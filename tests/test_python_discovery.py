import hashlib

import pytest

from guardian.detection import detect_ecosystems
from guardian.graph import build_graph
from guardian.python import extract_python


def test_requirements_preserve_exact_constraints_markers_extras_and_sources(tmp_path):
    source = ('Requests==2.31.0\nDjango>=4,<5\nhttpx[http2]==0.27.0; python_version >= "3.10"\n'
              'local @ https://example.invalid/package.whl\n-r private.txt\n--index-url https://secret.invalid\n')
    (tmp_path / "requirements.txt").write_text(source)
    inventory = extract_python(tmp_path, ["requirements.txt"], "repo")
    packages = {c.name: c for c in inventory.components if c.kind == "package"}
    assert set(packages) == {"requests", "django", "httpx", "local"}
    assert packages["requests"].declared_version == "2.31.0"
    assert packages["requests"].trust_tier == "declared_exact"
    assert packages["django"].trust_tier == "constraint_only"
    assert packages["httpx"].extras == ["http2"]
    assert packages["httpx"].environment_marker == 'python_version >= "3.10"'
    assert all(c.version is None and c.resolved_version is None for c in packages.values())
    proof = packages["requests"].evidence[0]
    assert proof.pointer == "line:1"
    assert proof.sha256 == hashlib.sha256(source.encode()).hexdigest()
    assert not any("secret.invalid" in warning for warning in inventory.warnings)
    graph = build_graph(inventory)
    assert graph["edges"] == [] and len(graph["declared"]) == 4
    assert inventory.projects[0].completeness_status == "partial"


def test_standard_pyproject_and_requirements_share_one_application(tmp_path):
    (tmp_path / "pyproject.toml").write_text('''[project]
name = "python-app"
dependencies = ["Requests==2.31.0", "django>=4"]
[project.optional-dependencies]
test = ["pytest>=8"]
''')
    (tmp_path / "requirements.txt").write_text("numpy==1.26.*\n")
    detected = detect_ecosystems(tmp_path)
    assert len(detected) == 1 and detected[0].supported
    assert detected[0].manifest_paths == ["pyproject.toml", "requirements.txt"]
    inventory = extract_python(tmp_path, detected[0].manifest_paths, "repo")
    assert len(inventory.projects) == 1
    assert inventory.projects[0].name == "python-app"
    assert len(inventory.components) == 5
    optional = next(c for c in inventory.components if c.name == "pytest")
    assert optional.optional and optional.declaration_group == "test"
    assert optional.evidence[0].pointer == "/project/optional-dependencies/test/0"
    assert next(c for c in inventory.components if c.name == "numpy").declared_version is None


@pytest.mark.parametrize("lock", ["poetry.lock", "uv.lock"])
def test_unsupported_python_locks_never_route_as_manifest_only(tmp_path, lock):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="app"\ndependencies=["requests==2.31.0"]')
    (tmp_path / lock).write_text("")
    project = detect_ecosystems(tmp_path)[0]
    assert not project.supported and project.lockfile_path == lock


@pytest.mark.parametrize("source", ['[tool.poetry]\nname="legacy"', '[project]\ndynamic=["dependencies"]'])
def test_dynamic_and_legacy_metadata_never_claim_empty_inventory(tmp_path, source):
    (tmp_path / "pyproject.toml").write_text(source)
    inventory = extract_python(tmp_path, ["pyproject.toml"], "repo")
    assert inventory.projects[0].dependency_status == "unknown"
    assert inventory.projects[0].completeness_status == "partial"


def test_requirement_hash_continuations_comments_and_invalid_lines(tmp_path):
    source = "# comment\nrequests==2.31.0 " + chr(92) + "\n    --hash=sha256:" + "a" * 64
    (tmp_path / "requirements.txt").write_text(source + "\ndjango>=4 # explanation\nnot a requirement\n")
    inventory = extract_python(tmp_path, ["requirements.txt"], "repo")
    assert {c.name for c in inventory.components if c.kind == "package"} == {"requests", "django"}
    assert any("syntax" in warning for warning in inventory.warnings)


def test_malformed_python_metadata_and_symlinks_are_rejected(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project")
    with pytest.raises(ValueError, match="Invalid TOML"):
        extract_python(tmp_path, ["pyproject.toml"], "repo")
    (tmp_path / "requirements.txt").symlink_to("/etc/passwd")
    with pytest.raises(ValueError, match="Symlink"):
        extract_python(tmp_path, ["requirements.txt"], "repo")


def test_empty_python_manifest_is_declared_empty_only(tmp_path):
    (tmp_path / "requirements.txt").write_text("# no declared dependencies\n")
    project = extract_python(tmp_path, ["requirements.txt"], "repo").projects[0]
    assert project.dependency_status == "declared_empty"
    assert project.completeness_status == "declared_empty"
    assert project.coverage_status == "partial"
