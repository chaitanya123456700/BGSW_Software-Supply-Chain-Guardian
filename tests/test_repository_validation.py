import json
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from guardian.app import create_app
from guardian.remediation import snapshot
from guardian.remediation_preview import apply_selection, draft_plan
from guardian.repository_validation import resolved_coverage, run_repository_validation
from test_remediation import fake_discovery, metadata_response, osv_response, prepared
from test_vulnerabilities import advisory


def reviewed(tmp_path, monkeypatch):
    scan, repo, store, _ = prepared(tmp_path, monkeypatch)
    plan, *_ = draft_plan(scan)
    ids = [plan['options'][0]['id']]
    selection, _ = apply_selection(scan, plan['digest'], ids)
    monkeypatch.setattr('guardian.repository_validation.analyze_repository', fake_discovery)
    return scan, repo, plan['digest'], ids, selection['validation']['receipt_sha256']


def test_applies_real_checkout_and_rescans_all_dependencies(tmp_path, monkeypatch):
    scan, repo, digest, ids, receipt = reviewed(tmp_path, monkeypatch)
    original = snapshot(repo)
    report = run_repository_validation(scan, digest, ids, receipt,
        osv_transport=httpx.MockTransport(osv_response), metadata_transport=httpx.MockTransport(metadata_response))
    assert report['status'] == 'passed', report
    assert report['applied'] and report['remaining_vulnerabilities'] == 0
    assert report['before_vulnerabilities'] == 1 and report['checks']['advisory_coverage'] == 'passed'
    assert json.loads((repo / 'package.json').read_text())['dependencies']['lodash'] == '4.17.21'
    assert json.loads((repo / 'package-lock.json').read_text())['packages']['node_modules/lodash']['version'] == '4.17.21'
    assert snapshot(repo) != original
    backup = Path(report['backup_directory'])
    assert json.loads((backup / 'package.json').read_text())['dependencies']['lodash'] == '4.17.20'
    assert (repo / '.env').read_text() == 'SECRET=hidden'
    assert not (repo / 'node_modules').exists()
    assert not report['fully_verified'], 'Missing build/tests must not be claimed as executed'
    child = scan.parent / report['after_scan_id']
    assert json.loads((child / 'artifacts/detection_report.json').read_text())['verified_vulnerabilities'] == 0
    assert snapshot(child / 'workspaces/repo-remediated/source') == snapshot(repo)


def test_remaining_vulnerability_prevents_pass_even_when_source_is_updated(tmp_path, monkeypatch):
    scan, repo, digest, ids, receipt = reviewed(tmp_path, monkeypatch)
    def still_vulnerable(request):
        if request.url.path.endswith('querybatch'):
            queries = json.loads(request.content)['queries']
            return httpx.Response(200, json={'results': [{'vulns': [{'id': 'GHSA-newx-1234-5678'}]} if query['package']['name'] == 'lodash' else {} for query in queries]})
        record = advisory('GHSA-newx-1234-5678')
        record['aliases'] = ['CVE-2099-0002']
        record['affected'][0]['versions'] = ['4.17.21']
        return httpx.Response(200, json=record)
    report = run_repository_validation(scan, digest, ids, receipt,
        osv_transport=httpx.MockTransport(still_vulnerable), metadata_transport=httpx.MockTransport(metadata_response))
    assert report['applied'] and report['status'] == 'failed', report
    assert report['remaining_vulnerabilities'] > 0
    assert report['checks']['zero_vulnerabilities'] == 'failed'
    assert json.loads((repo / 'package.json').read_text())['dependencies']['lodash'] == '4.17.21'


def test_failed_lock_resolution_never_writes_the_actual_checkout(tmp_path, monkeypatch):
    scan, repo, digest, ids, receipt = reviewed(tmp_path, monkeypatch)
    before = snapshot(repo)
    def blocked(*args): raise ValueError('Dependency topology requires manual lockfile resolution')
    monkeypatch.setattr('guardian.repository_validation.npm_operation', blocked)
    report = run_repository_validation(scan, digest, ids, receipt)
    assert report['status'] == 'failed' and not report['applied']
    assert snapshot(repo) == before
    assert 'manual lockfile' in report['errors'][0]


def test_incomplete_advisory_coverage_never_becomes_a_zero_vulnerability_pass():
    discovery = {'status': 'completed'}
    inventory = {'projects': [{'ecosystem': 'npm', 'completeness_status': 'verified'}],
                 'components': [{'kind': 'package', 'version': '1.0.0', 'resolution_status': 'resolved'}]}
    graph = {'statistics': {'unresolved_edges': 0}}
    detection = {'vulnerabilities': {'status': 'completed', 'errors': [], 'skipped_components': [],
                                     'queried_package_versions': 1, 'completed_package_versions': 1}}
    assert resolved_coverage(discovery, detection, inventory, graph)
    detection['vulnerabilities']['completed_package_versions'] = 0
    assert not resolved_coverage(discovery, detection, inventory, graph)
    detection['vulnerabilities']['completed_package_versions'] = 1
    graph['statistics']['unresolved_edges'] = 1
    assert not resolved_coverage(discovery, detection, inventory, graph)


def test_api_requires_exact_review_and_reports_updated_scan_and_stale_checkout(tmp_path, monkeypatch):
    scan, repo, digest, ids, receipt = reviewed(tmp_path, monkeypatch)
    with TestClient(create_app(tmp_path, osv_transport=httpx.MockTransport(osv_response), metadata_transport=httpx.MockTransport(metadata_response))) as client:
        base = f'/api/scans/{scan.name}/repository-validation'
        body = {'digest': digest, 'selected': ids, 'receipt': receipt}
        assert client.post(base, json=body).status_code == 409
        body['reviewed_changes'] = True
        assert client.post(base, json={**body, 'receipt': '0' * 64}).status_code == 409
        assert client.post(base, json=body).status_code == 202
        for _ in range(200):
            state = client.get(base).json()
            if state['status'] not in {'queued', 'running'}: break
            time.sleep(.01)
        assert state['status'] == 'passed', state
        child = state['report']['after_scan_id']
        assert client.get(f'/api/scans/{child}/detection').json()['report']['verified_vulnerabilities'] == 0
        assert client.get(base + '/report').status_code == 200
        (repo / 'index.js').write_text('later local edit')
        assert client.get(base).json()['status'] == 'stale'


def test_partial_write_failure_restores_files_and_removes_temporary_writes(tmp_path, monkeypatch):
    scan, repo, digest, ids, receipt = reviewed(tmp_path, monkeypatch)
    original = snapshot(repo)
    replace = Path.replace
    def fail_second_write(path, target):
        if path.name == 'package.json.guardian-tmp':
            raise OSError('Synthetic second-file write failure')
        return replace(path, target)
    monkeypatch.setattr(Path, 'replace', fail_second_write)
    report = run_repository_validation(scan, digest, ids, receipt,
        osv_transport=httpx.MockTransport(osv_response), metadata_transport=httpx.MockTransport(metadata_response))
    assert not report['applied'] and report['status'] == 'failed'
    assert snapshot(repo) == original
    assert not list(repo.glob('*.guardian-tmp'))


def test_updated_scan_keeps_the_real_clone_as_the_future_apply_target(tmp_path, monkeypatch):
    from guardian.remediation import checkout_target
    scan, repo, digest, ids, receipt = reviewed(tmp_path, monkeypatch)
    report = run_repository_validation(scan, digest, ids, receipt,
        osv_transport=httpx.MockTransport(osv_response), metadata_transport=httpx.MockTransport(metadata_response))
    child = scan.parent / report['after_scan_id']
    origin, target = checkout_target(child)
    assert origin == scan and target == repo
    with TestClient(create_app(tmp_path)) as client:
        (repo / 'index.js').write_text('Later real checkout edit')
        assert client.get(f'/api/scans/{child.name}/repository-validation').json()['status'] == 'stale'
