import pytest


@pytest.mark.asyncio
class TestWatermark:
    async def test_generate(self, client):
        r = await client.post("/api/v1/forensics/watermark?user_id=user-alpha&document_id=DOC-001")
        assert r.status_code == 200
        d = r.json()
        assert "watermark_id" in d or "watermark_hash" in d or "token" in d

    async def test_verify(self, client):
        r1 = await client.post("/api/v1/forensics/watermark?user_id=user-beta&document_id=DOC-002")
        assert r1.status_code == 200
        d = r1.json()
        token = d.get("token") or d.get("watermark_id") or d.get("watermark_hash")
        if token:
            r2 = await client.get(f"/api/v1/forensics/watermark/verify?token={token}")
            assert r2.status_code == 200


@pytest.mark.asyncio
class TestTimeline:
    async def test_basic(self, client):
        r = await client.get("/api/v1/forensics/timeline")
        assert r.status_code == 200
        d = r.json()
        assert "entries" in d

    async def test_with_params(self, client):
        r = await client.get("/api/v1/forensics/timeline?hours=24&limit=50")
        assert r.status_code == 200


@pytest.mark.asyncio
class TestTaint:
    async def test_basic(self, client):
        r = await client.get("/api/v1/forensics/taint")
        assert r.status_code == 200
        d = r.json()
        assert "exfiltration_paths" in d


@pytest.mark.asyncio
class TestSIEM:
    async def test_formats(self, client):
        r = await client.get("/api/v1/forensics/siem/formats")
        assert r.status_code == 200
        d = r.json()
        assert "formats" in d

    async def test_export_json(self, client):
        r = await client.get("/api/v1/forensics/siem/export?format=json")
        assert r.status_code == 200


@pytest.mark.asyncio
class TestPackaging:
    async def test_package_event(self, client):
        r = await client.get("/api/v1/forensics/package/test-event-id")
        assert r.status_code in [200, 404]
