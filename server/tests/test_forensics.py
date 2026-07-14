import pytest
import hashlib
import hmac


@pytest.mark.asyncio
class TestWatermark:
    async def test_generate(self, client):
        r = await client.post("/api/v1/forensics/watermark", json={
            "document_id": "DOC-001",
            "recipient_id": "user-alpha",
            "classification": "CONFIDENTIAL"
        })
        assert r.status_code == 200
        d = r.json()
        assert "watermark_id" in d
        assert "watermark_hash" in d

    async def test_verify(self, client):
        r1 = await client.post("/api/v1/forensics/watermark", json={
            "document_id": "DOC-002",
            "recipient_id": "user-beta",
            "classification": "SECRET"
        })
        assert r1.status_code == 200
        d = r1.json()
        r2 = await client.get(f"/api/v1/forensics/watermark/verify?watermark_id={d['watermark_id']}&document_id=DOC-002&recipient_id=user-beta")
        assert r2.status_code == 200
        assert r2.json()["valid"] is True


@pytest.mark.asyncio
class TestTimeline:
    async def test_basic(self, client):
        r = await client.get("/api/v1/forensics/timeline")
        assert r.status_code == 200
        d = r.json()
        assert "events" in d

    async def test_with_params(self, client):
        r = await client.get("/api/v1/forensics/timeline?hours=24&limit=50")
        assert r.status_code == 200


@pytest.mark.asyncio
class TestTaint:
    async def test_basic(self, client):
        r = await client.get("/api/v1/forensics/taint")
        assert r.status_code == 200
        d = r.json()
        assert "tainted_paths" in d


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
