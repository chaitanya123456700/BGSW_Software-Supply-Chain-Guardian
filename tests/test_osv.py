import httpx
import pytest

from guardian.evidence import EvidenceStore
from guardian.osv import OSVClient, OSVError


def test_batch_fetches_full_advisory_and_preserves_raw_response(tmp_path):
    def respond(request):
        if request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-test-1234-5678", "modified": "2026-01-01T00:00:00Z"}]}]})
        return httpx.Response(200, json={"id": "GHSA-test-1234-5678", "modified": "2026-01-01T00:00:00Z", "affected": []})
    store = EvidenceStore(tmp_path / "evidence", "a" * 40)
    with OSVClient(tmp_path / "cache", store, transport=httpx.MockTransport(respond)) as client:
        result = client.query_batch([{"package": {"ecosystem": "npm", "name": "lodash"}, "version": "4.17.20"}])
        assert result[0]["advisories"] == ["GHSA-test-1234-5678"]
        record, evidence = client.advisory("GHSA-test-1234-5678")
        assert record["id"] == "GHSA-test-1234-5678"
        assert store.records[evidence]["sha256"]
        assert len(store.records) == 2


@pytest.mark.parametrize("failure", ["timeout", "rate", "server"])
def test_api_failures_never_become_no_matches(tmp_path, failure):
    calls = []
    def respond(request):
        calls.append(request)
        if failure == "timeout":
            raise httpx.ReadTimeout("fixture timeout")
        return httpx.Response(429 if failure == "rate" else 503, json={"error": "fixture"})
    store = EvidenceStore(tmp_path / "evidence", "a" * 40)
    with OSVClient(tmp_path / "cache", store, transport=httpx.MockTransport(respond), sleep=lambda _: None) as client:
        item = client.query_batch([{"package": {"ecosystem": "npm", "name": "a"}, "version": "1.0.0"}])[0]
    assert len(calls) == 3
    assert item["complete"] is False and item["error"]
    assert store.records


def test_pagination_partial_failure_and_cache_preserve_each_query_status(tmp_path):
    calls = []
    def respond(request):
        calls.append(request)
        payload = __import__("json").loads(request.content)
        if payload["queries"][0].get("page_token"):
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-next-1234-5678"}]}]})
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-first-1234-5678"}], "next_page_token": "next"}, {"error": "bad query"}]})
    store = EvidenceStore(tmp_path / "evidence", "a" * 40)
    queries = [{"package": {"ecosystem": "npm", "name": "a"}, "version": "1.0.0"}] * 2
    with OSVClient(tmp_path / "cache", store, transport=httpx.MockTransport(respond)) as client:
        results = client.query_batch(queries)
        assert results[0]["advisories"] == ["GHSA-first-1234-5678", "GHSA-next-1234-5678"]
        assert results[0]["complete"] and not results[1]["complete"]
        client.query_batch(queries)
        assert client.cache_hits == 2 and len(calls) == 2
