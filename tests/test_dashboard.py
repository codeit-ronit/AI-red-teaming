import hashlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import dashboard

pytestmark = [pytest.mark.integration, pytest.mark.security]
ROOT = Path(__file__).resolve().parents[1]


def test_dashboard_local_mode_and_security_headers():
    response = TestClient(dashboard.create_dashboard()).get('/')
    assert response.status_code == 200
    assert 'name="runtime" content="local"' in response.text
    assert response.headers['x-content-type-options'] == 'nosniff'
    assert "script-src 'self'" in response.headers['content-security-policy']


def test_snapshot_agrees_with_original_evidence_and_omits_private_trace_fields():
    data = TestClient(dashboard.create_dashboard()).get('/data/experiment.json').json()
    source = ROOT / data['source_report']
    original = json.loads(source.read_text())
    assert data['source_sha256'] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert data['execution_count'] == len(original['runs']) == 102
    assert len(data['cases']) == data['case_count'] == 34
    assert data['metrics'] == original['metrics']
    forbidden = {'messages', 'raw_response', 'raw_excerpt', 'provider_generations', 'protected_value'}
    def check(value):
        if isinstance(value, dict):
            assert not forbidden.intersection(value)
            for v in value.values(): check(v)
        elif isinstance(value, list):
            for v in value: check(v)
    check(data)


def test_live_boundary_check_uses_actual_fixture_runner():
    response = TestClient(dashboard.create_dashboard()).post('/api/checks', headers={'X-AgentSec-Action':'run-boundaries'})
    assert response.status_code == 200
    assert response.json()['summary'] == {'checks':142,'passed':142,'failed':0}
    assert response.json()['real_model'] is False
    assert 'approval-concurrency' in response.json()['families']


@pytest.mark.parametrize('headers', [{}, {'X-AgentSec-Action':'run-boundaries','Origin':'https://attacker.example'}, {'X-AgentSec-Action':'run-boundaries','Origin':'null'}])
def test_check_endpoint_requires_explicit_same_origin_action(headers):
    assert TestClient(dashboard.create_dashboard()).post('/api/checks',headers=headers).status_code == 403


def test_untrusted_host_and_path_traversal_are_rejected():
    client = TestClient(dashboard.create_dashboard())
    assert client.get('/',headers={'host':'attacker.example'}).status_code == 400
    assert client.get('/assets/%2e%2e/%2e%2e/pyproject.toml').status_code == 404
    assert client.get('/data/../../../.env').status_code == 404


def test_failed_boundaries_are_reported_as_failures(monkeypatch):
    def fail(folder):
        Path(folder,'report.json').write_text(json.dumps({'method':'fixture','summary':{'checks':1,'passed':0,'failed':1},'cases':[{'family':'injected-failure'}]}))
        raise SystemExit(1)
    monkeypatch.setattr(dashboard,'run',fail)
    response = TestClient(dashboard.create_dashboard()).post('/api/checks',headers={'X-AgentSec-Action':'run-boundaries'})
    assert response.status_code == 200
    assert response.json()['summary']['failed'] == 1
    assert response.json()['summary']['passed'] == 0


def test_static_snapshot_runtime_does_not_claim_live_execution():
    html = (ROOT/'dashboard/dist/index.html').read_text()
    assert 'name="runtime" content="snapshot"' in html
    assert 'No new inference is run here' in html
