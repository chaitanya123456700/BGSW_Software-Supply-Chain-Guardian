import os

import pytest

from guardian.pipeline import scan_repository


@pytest.mark.integration
@pytest.mark.skipif(os.getenv("GUARDIAN_INTEGRATION") != "1", reason="Opt-in real GitHub scan")
def test_public_axios_repository_end_to_end(tmp_path):
    report = scan_repository("https://github.com/axios/axios", tmp_path / "scan")
    assert report["status"] in {"completed", "incomplete"}
    assert len(report["repository"]["commit"]) == 40
    assert report["statistics"]["component_count"] > 0
    assert report["statistics"]["edge_count"] > 0
    assert report["sbom"]["status"] == "completed", report["sbom"]
    assert not report["errors"]
    assert all(check["status"] == "completed" for check in report["native_checks"])
    assert all(not check["adapter_only"] and not check["native_only"] for check in report["native_checks"])
