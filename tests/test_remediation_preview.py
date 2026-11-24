import copy
import io
import json
import zipfile

import httpx
import pytest
from fastapi.testclient import TestClient

from guardian.ai import AIConfig
from guardian.analysis import run_analysis
from guardian.app import create_app
from guardian.files import write_json
from guardian.graph import build_graph
from guardian.npm import reconcile_npm_projects
from guardian.phase2 import run_detection
from guardian.remediation import snapshot, run_remediation
from guardian.remediation_preview import apply_selection, draft_plan, export_zip, merge_change
from test_remediation import metadata_response, osv_response, prepared


def blocked_plan(tmp_path, monkeypatch):
    scan, repo, store, _ = prepared(tmp_path, monkeypatch)
    manifest = json.loads((repo / 'package.json').read_text())
    manifest['dependencies']['local-plugin'] = 'file:../plugin'
    write_json(repo / 'package.json', manifest)
    inventory = reconcile_npm_projects(repo, 'package-lock.json', ['package.json'], 'repository:test')
    write_json(scan / 'artifacts/components.json', inventory.model_dump())
    write_json(scan / 'artifacts/dependency_graph.json', build_graph(inventory))
    transport, metadata = httpx.MockTransport(osv_response), httpx.MockTransport(metadata_response)
    run_detection(scan, transport=transport, metadata_transport=metadata)
    run_analysis(scan, store, config=AIConfig(enabled=False))
    report = run_remediation(scan, store, osv_transport=transport, metadata_transport=metadata, config=AIConfig(enabled=False))
    assert not report['proposals']
    return scan, repo


def test_unsupported_project_still_has_real_selectable_manifest_draft(tmp_path, monkeypatch):
    scan, repo = blocked_plan(tmp_path, monkeypatch)
    before = snapshot(repo)
    plan, *_ = draft_plan(scan)
    assert len(plan['options']) == 1
    option = plan['options'][0]
    assert option['name'] == 'lodash' and option['kind'] == 'advisory_draft'
    result, diff = apply_selection(scan, plan['digest'], [option['id']])
    assert result['validated'] is False and result['original_checkout_modified'] is False
    assert [item['path'] for item in result['files']] == ['package.json']
    updated = json.loads(result['files'][0]['content'])
    assert updated['dependencies']['lodash'] == '4.17.21'
    assert updated['dependencies']['local-plugin'] == 'file:../plugin'
    assert '-    "lodash": "4.17.20"' in diff and '+    "lodash": "4.17.21"' in diff
    assert 'lockfile regeneration' in result['note']
    assert snapshot(repo) == before
    empty, diff = apply_selection(scan, plan['digest'], [])
    assert empty['files'] == [] and diff == ''


def test_prepared_patch_exports_changed_manifest_and_lockfile_not_originals(tmp_path, monkeypatch):
    scan, repo, _, _ = prepared(tmp_path, monkeypatch)
    before = snapshot(repo)
    plan, *_ = draft_plan(scan)
    result, diff = apply_selection(scan, plan['digest'], [plan['options'][0]['id']])
    files = {item['path']: item['content'] for item in result['files']}
    assert json.loads(files['package-lock.json'])['packages']['node_modules/lodash']['version'] == '4.17.21'
    assert json.loads(files['package.json'])['dependencies']['lodash'] == '4.17.21'
    with zipfile.ZipFile(io.BytesIO(export_zip(result, diff))) as archive:
        assert set(archive.namelist()) == {'package.json', 'package-lock.json', 'guardian-selected-changes.diff', 'GUARDIAN-REVIEW.txt', 'guardian-draft-validation.json'}
        assert archive.read('package.json').decode() == files['package.json']
        assert archive.read('guardian-selected-changes.diff').decode() == diff
    assert snapshot(repo) == before


def test_independent_edits_merge_without_overwriting_unselected_values():
    original = {'dependencies': {'a': '1', 'b': '1', 'c': '1'}, 'scripts': {'test': 'original'}}
    first = copy.deepcopy(original); first['dependencies']['a'] = '2'
    second = copy.deepcopy(original); second['dependencies']['b'] = '3'
    result = merge_change(original, first, original)
    assert result['dependencies'] == {'a': '2', 'b': '1', 'c': '1'}
    result = merge_change(original, second, result)
    assert result['dependencies'] == {'a': '2', 'b': '3', 'c': '1'}
    assert result['scripts'] == original['scripts']
    conflict = copy.deepcopy(original); conflict['dependencies']['a'] = '4'
    with pytest.raises(ValueError, match='conflict'):
        merge_change(original, conflict, result)


def test_selection_refuses_unknown_duplicate_and_stale_ids(tmp_path, monkeypatch):
    scan, repo, _, _ = prepared(tmp_path, monkeypatch)
    plan, *_ = draft_plan(scan)
    identifier = plan['options'][0]['id']
    for selected in [['unknown'], [identifier, identifier]]:
        with pytest.raises(ValueError, match='unique remedy IDs'):
            apply_selection(scan, plan['digest'], selected)
    with pytest.raises(ValueError, match='reload'):
        apply_selection(scan, '0' * 64, [identifier])
    (repo / 'index.js').write_text('source changed')
    with pytest.raises(ValueError, match='Source changed'):
        apply_selection(scan, plan['digest'], [identifier])


def test_api_download_bytes_match_preview_and_only_selected_files(tmp_path, monkeypatch):
    scan, _ = blocked_plan(tmp_path, monkeypatch)
    with TestClient(create_app(tmp_path)) as client:
        base = f'/api/scans/{scan.name}/remediation-preview'
        plan = client.get(base).json()
        ids = [plan['options'][0]['id']]
        preview = client.post(base, json={'digest': plan['digest'], 'selected': ids})
        assert preview.status_code == 200
        query = {'digest': plan['digest'], 'selected': ','.join(ids)}
        response = client.get(base + '/download', params={**query, 'file': 'package.json'})
        assert response.status_code == 200
        assert response.content == preview.json()['files'][0]['content'].encode()
        assert 'attachment' in response.headers['content-disposition']
        assert client.get(base + '/download', params={**query, 'file': '../.env'}).status_code == 409
        assert client.get(base + '/download', params={**query, 'selected': ''}).status_code == 409
        assert client.get(base + '/download', params={**query, 'digest': '0' * 64}).status_code == 409
        archive = client.get(base + '/download', params=query)
        assert archive.status_code == 200
        with zipfile.ZipFile(io.BytesIO(archive.content)) as contents:
            assert 'package.json' in contents.namelist() and 'package-lock.json' not in contents.namelist()
        assert client.post(base, json={'digest': plan['digest'], 'selected': ids}, headers={'origin': 'https://evil.invalid'}).status_code == 403


def test_start_pipeline_reaches_export_without_demo_or_automatic_patches(tmp_path, monkeypatch):
    from test_vulnerabilities import inventory_fixture
    from test_workspace import wait_pipeline

    def discovery(url, scan, update):
        repo = scan / 'workspaces/repo-public/source'
        repo.mkdir(parents=True)
        inventory_fixture(repo)
        manifest = json.loads((repo / 'package.json').read_text())
        manifest['dependencies']['local-plugin'] = 'file:../plugin'
        write_json(repo / 'package.json', manifest)
        inventory = reconcile_npm_projects(repo, 'package-lock.json', ['package.json'], 'repository:test')
        graph = build_graph(inventory)
        write_json(scan / 'artifacts/components.json', inventory.model_dump())
        write_json(scan / 'artifacts/dependency_graph.json', graph)
        report = {'status': 'completed', 'repository': {'url': url, 'commit': 'b' * 40},
                  'coverage_status': 'verified', 'dependency_status': 'has_dependencies', 'statistics': graph['statistics']}
        write_json(scan / 'artifacts/discovery_report.json', report)
        return report

    monkeypatch.setattr('guardian.orchestrator.scan_repository', discovery)
    with TestClient(create_app(tmp_path, osv_transport=httpx.MockTransport(osv_response),
                               metadata_transport=httpx.MockTransport(metadata_response), ai_config=AIConfig(enabled=False))) as client:
        response = client.post('/api/pipelines', json={'repo_url': 'https://github.com/test/ordinary-repository'})
        assert response.status_code == 202
        scan_id = response.json()['scan_id']
        state = wait_pipeline(client, scan_id)
        assert state['status'] == 'completed', state
        for stage in ['discover', 'detect', 'analyze', 'remediate']:
            assert state['modules'][stage]['attempts'] == 1
        summary = client.get(f'/api/scans/{scan_id}/summary').json()
        assert not summary['controlled_fixture']
        assert summary['remediation']['proposals_count'] == 0
        preview = client.get(f'/api/scans/{scan_id}/remediation-preview').json()
        assert len(preview['options']) == 1 and preview['options'][0]['name'] == 'lodash'
        selected = client.post(f'/api/scans/{scan_id}/remediation-preview', json={'digest': preview['digest'], 'selected': [preview['options'][0]['id']]}).json()
        assert json.loads(selected['files'][0]['content'])['dependencies']['lodash'] == '4.17.21'


def test_export_proof_distinguishes_integrity_from_build_and_lock_readiness(tmp_path, monkeypatch):
    scan, _ = blocked_plan(tmp_path, monkeypatch)
    plan, *_ = draft_plan(scan)
    selection, diff = apply_selection(scan, plan['digest'], [plan['options'][0]['id']])
    proof = selection['validation']
    assert proof['status'] == 'passed' and proof['passed_checks'] == 4
    assert proof['scope'] == 'export_integrity'
    assert proof['proof'] == {'rule': 'actual_edits = union(selected_edits)', 'expected_edits': 1,
                              'actual_edits': 1, 'unexpected_edits': 0, 'missing_edits': 0}
    assert proof['lockfile']['status'] == 'needs_regeneration'
    assert proof['build_tests']['status'] == 'not_run' and proof['security_verification'] == 'not_run'
    assert len(proof['receipt_sha256']) == 64 and proof['elapsed_ms'] >= 0
    with zipfile.ZipFile(io.BytesIO(export_zip(selection, diff))) as archive:
        saved = json.loads(archive.read('guardian-draft-validation.json'))
        assert saved['receipt_sha256'] == proof['receipt_sha256']
        from guardian.remediation import digest
        assert digest(archive.read('package.json')) == saved['files']['package.json']
    with TestClient(create_app(tmp_path)) as client:
        response = client.get(f'/api/scans/{scan.name}/remediation-preview/download', params={
            'digest': plan['digest'], 'selected': ','.join(selection['selected']), 'file': 'guardian-draft-validation.json'})
        assert response.status_code == 200
        assert response.json()['receipt_sha256'] == proof['receipt_sha256']


@pytest.mark.parametrize('tamper', ['unexpected', 'missing', 'wrong_hash', 'syntax'])
def test_mathematical_validation_detects_tampered_exports(tmp_path, monkeypatch, tamper):
    from guardian.draft_validation import validate_export
    from guardian.remediation import digest
    scan, repo, _, _ = prepared(tmp_path, monkeypatch)
    plan, _, documents, changes = draft_plan(scan)
    selection, _ = apply_selection(scan, plan['digest'], [plan['options'][0]['id']])
    item = next(item for item in selection['files'] if item['path'] == 'package.json')
    value = json.loads(item['content'])
    if tamper == 'unexpected':
        value['scripts'] = {'postinstall': 'unselected modification'}
    if tamper == 'missing':
        value['dependencies']['lodash'] = '4.17.20'
    item['content'] = 'invalid JSON' if tamper == 'syntax' else json.dumps(value)
    item['sha256'] = '0' * 64 if tamper == 'wrong_hash' else digest(item['content'].encode())
    proof = validate_export(repo, plan, documents, changes, selection)
    assert proof['status'] == 'failed'
    if tamper == 'unexpected': assert proof['proof']['unexpected_edits'] > 0
    if tamper == 'missing': assert proof['proof']['missing_edits'] > 0


def test_prepared_export_has_matching_selected_lock_pins_and_empty_selection_is_not_passed(tmp_path, monkeypatch):
    scan, _, _, _ = prepared(tmp_path, monkeypatch)
    plan, *_ = draft_plan(scan)
    selection, _ = apply_selection(scan, plan['digest'], [plan['options'][0]['id']])
    assert selection['validation']['lockfile']['status'] == 'passed'
    empty, _ = apply_selection(scan, plan['digest'], [])
    assert empty['validation']['status'] == 'not_run'
