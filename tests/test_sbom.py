import json
import shutil

import pytest

from guardian.sbom import generate_sbom, validate_sbom
from guardian.process import WORKSPACE
from test_npm import extract


def test_cyclonedx_structure_and_references_are_validated():
    validate_sbom({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                   "components": [{"type": "library", "name": "a", "bom-ref": "a"}],
                   "dependencies": [{"ref": "a", "dependsOn": []}]})
    with pytest.raises(ValueError):
        validate_sbom({"bomFormat": "not-cyclonedx"})
    with pytest.raises(ValueError, match="reference"):
        validate_sbom({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                       "components": [], "dependencies": [{"ref": "missing"}]})


@pytest.mark.skipif(not (WORKSPACE / ".tools/bin/syft").exists() and not shutil.which("syft"), reason="Syft unavailable")
def test_real_syft_on_synthetic_fixture_preserves_original(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text('{"name":"test-app","version":"1.0.0","dependencies":{"a":"1.2.3"}}')
    inventory = extract(repo, {"": {"name": "test-app", "version": "1.0.0", "dependencies": {"a": "1.2.3"},
                                    "devDependencies": {"dev-tool": "2.0.0"}},
                               "node_modules/a": {"version": "1.2.3", "resolved": "https://registry.npmjs.org/a/-/a-1.2.3.tgz"},
                               "node_modules/dev-tool": {"version": "2.0.0", "dev": True}})
    out = tmp_path / "artifacts"
    out.mkdir()
    result = generate_sbom(repo, out, "f" * 40, inventory)
    assert result["status"] == "completed", result
    assert result["tool_version"]
    assert result["commit"] == "f" * 40
    assert result["reconciliation"]["matched_instances"] == 2
    document = json.loads((out / "sbom.json").read_bytes())
    assert document["bomFormat"] == "CycloneDX"
    assert any(c["name"] == "a" and c["version"] == "1.2.3" for c in document["components"])
