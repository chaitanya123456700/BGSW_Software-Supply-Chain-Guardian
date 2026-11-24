import json
from pathlib import Path

import pytest
from guardian.branch_validation import compatibility, export_branches
from guardian.remediation import digest
from guardian.process import run_tool


def test_compatibility_requires_both_build_and_test_on_both_versions():
    passed = {'status': 'passed', 'commands': ['build', 'test']}
    assert compatibility(passed, passed)['status'] == 'passed'
    assert compatibility({'status': 'failed'}, passed)['status'] == 'baseline_failed'
    assert compatibility(passed, {'status': 'failed'})['status'] == 'failed'
    assert compatibility(passed, {'status': 'not_run'})['status'] == 'not_verified'
    assert compatibility({'status': 'passed', 'commands': ['test']}, passed)['status'] == 'not_verified'


def test_bundle_contains_two_related_branches_and_only_approved_change(tmp_path):
    repo = tmp_path / 'source'; repo.mkdir()
    old = b'{"dependencies":{"lodash":"4.17.20"}}'
    new = b'{"dependencies":{"lodash":"4.17.21"}}'
    (repo / 'package.json').write_bytes(old)
    (repo / 'app.js').write_text('unchanged business logic')
    (repo / '.env').write_text('SECRET=never-export')
    artifacts = tmp_path / 'artifacts'
    patch = artifacts / 'remediation/proposals/test'; patch.mkdir(parents=True)
    (patch / 'package.json').write_bytes(new)
    saved = tmp_path / 'saved'; saved.mkdir()
    proposal = {'id':'test','name':'lodash','before':{'package.json':digest(old)},'after':{'package.json':digest(new)}}
    result = export_branches(repo, proposal, artifacts, saved)
    cloned = tmp_path / 'clone'
    run_tool(['git','clone','--branch','guardian-fixed',str(saved/'branches.bundle'),str(cloned)],tmp_path, extra_env={'GIT_ALLOW_PROTOCOL':'file'})
    assert (cloned/'package.json').read_bytes() == new
    assert not (cloned/'.env').exists()
    assert run_tool(['git','diff','--name-only','origin/vulnerable','HEAD'],cloned).stdout.strip() == 'package.json'
    assert run_tool(['git','rev-parse','HEAD^'],cloned).stdout.strip() == result['before_commit']
    assert (repo/'package.json').read_bytes() == old
    (patch/'package.json').write_text('tampered')
    with pytest.raises(ValueError, match='Patch differs'):
        export_branches(repo, proposal, artifacts, saved)


def test_downloads_use_correct_content_types_and_reject_unknown_artifacts(tmp_path):
    from fastapi.testclient import TestClient
    from guardian.app import create_app
    scan = tmp_path / ('a' * 32)
    saved = scan / 'artifacts/validation' / ('b' * 32)
    saved.mkdir(parents=True)
    (scan/'status.json').write_text('{"status":"completed"}')
    (saved/'branches.bundle').write_bytes(b'git bundle fixture')
    (saved/'branch-diff.patch').write_text('diff fixture')
    with TestClient(create_app(tmp_path)) as client:
        base = f'/api/scans/{scan.name}/validation/{saved.name}/'
        response = client.get(base+'branches')
        assert response.content == b'git bundle fixture'
        assert response.headers['content-type'] == 'application/octet-stream'
        assert client.get(base+'branch-diff').headers['content-type'].startswith('text/plain')
        assert client.get(base+'secret').status_code == 404
