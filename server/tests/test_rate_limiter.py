import pytest
from unittest.mock import patch


@pytest.mark.asyncio
class TestRateLimiterDisabled:
    async def test_passes_when_disabled(self, client):
        r = await client.get("/health")
        assert r.status_code == 200

    async def test_no_headers_when_disabled(self, client):
        r = await client.get("/health")
        assert "X-RateLimit-Limit" not in r.headers


@pytest.mark.asyncio
class TestRateLimiterEnabled:
    async def test_headers_present(self, client):
        with patch.dict("os.environ", {"SOVEREIGN_RATE_LIMIT": "1000"}):
            r = await client.get("/api/v1/compliance/summary")
            assert r.status_code == 200
            assert "X-RateLimit-Limit" in r.headers
            assert r.headers["X-RateLimit-Limit"] == "1000"
            assert "X-RateLimit-Remaining" in r.headers

    async def test_exempt_paths_not_limited(self, client):
        with patch.dict("os.environ", {"SOVEREIGN_RATE_LIMIT": "1"}):
            r1 = await client.get("/health")
            r2 = await client.get("/health")
            assert r1.status_code == 200
            assert r2.status_code == 200
