import pytest


@pytest.mark.asyncio
class TestMetrics:
    async def test_endpoint(self, client):
        r = await client.get("/metrics")
        assert r.status_code == 200

    async def test_has_version(self, client):
        r = await client.get("/metrics")
        d = r.json()
        assert "version" in d
        assert d["version"] == "1.0.0"

    async def test_has_platform_info(self, client):
        r = await client.get("/metrics")
        d = r.json()
        assert "platform" in d

    async def test_has_config(self, client):
        r = await client.get("/metrics")
        d = r.json()
        assert "config" in d

    async def test_has_vault(self, client):
        r = await client.get("/metrics")
        d = r.json()
        assert "vault" in d

    async def test_has_policies(self, client):
        r = await client.get("/metrics")
        d = r.json()
        assert "policies_loaded" in d

    async def test_has_uptime(self, client):
        r = await client.get("/metrics")
        d = r.json()
        assert "uptime_seconds" in d
        assert d["uptime_seconds"] >= 0
