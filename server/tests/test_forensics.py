import pytest
from fastapi.testclient import TestClient
from app.main import app
client = TestClient(app)

class TestWatermark:
    def test_generate(self):
        r = client.post("/api/v1/forensics/watermark", params={"user_id": "u001", "document_id": "d001"})
        assert r.status_code == 200
        d = r.json()
        assert "watermark_id" in d
        assert "watermark_token" in d
        assert "signature" in d
        assert d["user_id"] == "u001"
    def test_verify(self):
        r = client.post("/api/v1/forensics/watermark", params={"user_id": "u002", "document_id": "d002"})
        token = r.json()["watermark_token"]
        r2 = client.get("/api/v1/forensics/watermark/verify", params={"token": token})
        assert r2.status_code == 200
        d = r2.json()
        assert d.get("valid") is True or d.get("verified") is True
    def test_verify_tampered(self):
        r = client.get("/api/v1/forensics/watermark/verify", params={"token": "bad-token"})
        assert r.status_code in (200, 400)
        if r.status_code == 200:
            d = r.json()
            assert d.get("valid") is False or d.get("verified") is False

class TestTimeline:
    def test_endpoint(self):
        r = client.get("/api/v1/forensics/timeline")
        assert r.status_code == 200
    def test_returns_data(self):
        r = client.get("/api/v1/forensics/timeline")
        assert isinstance(r.json(), (dict, list))

class TestTaint:
    def test_endpoint(self):
        r = client.get("/api/v1/forensics/taint")
        assert r.status_code == 200

class TestSIEM:
    def test_formats(self):
        r = client.get("/api/v1/forensics/siem/formats")
        assert r.status_code == 200
        names = [f["name"] for f in r.json()["formats"]]
        assert "json" in names
        assert "cef" in names
        assert "syslog" in names
    def test_format_structure(self):
        r = client.get("/api/v1/forensics/siem/formats")
        for f in r.json()["formats"]:
            assert "name" in f
            assert "description" in f
            assert "mime" in f

class TestPackage:
    def test_package_get(self):
        r = client.get("/api/v1/forensics/package/test-case-001")
        assert r.status_code in (200, 404)
