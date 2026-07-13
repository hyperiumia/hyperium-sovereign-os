import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from app.main import app
client = TestClient(app)

class TestAuthDisabled:
    def test_passes_without_key(self):
        r = client.get("/api/v1/compliance/summary")
        assert r.status_code == 200
    def test_health_accessible(self):
        r = client.get("/health")
        assert r.status_code == 200

class TestAuthEndpoints:
    def test_status(self):
        r = client.get("/api/v1/auth/status")
        assert r.status_code == 200
        assert "enabled" in r.json()
    def test_list_keys(self):
        r = client.get("/api/v1/auth/keys")
        assert r.status_code == 200
        assert isinstance(r.json(), list)
    def test_create_and_revoke(self):
        r = client.post("/api/v1/auth/keys", json={"name": "test"})
        assert r.status_code == 200
        d = r.json()
        assert d["key"].startswith("sk_sov_")
        kid = d["id"]
        r2 = client.delete(f"/api/v1/auth/keys/{kid}")
        assert r2.status_code == 200
        assert r2.json()["revoked"] is True
    def test_revoke_nonexistent(self):
        r = client.delete("/api/v1/auth/keys/key_noexist")
        assert r.status_code == 404

class TestMiddleware:
    def test_rejects_missing_key(self):
        with patch("app.auth.middleware.is_auth_enabled", return_value=True):
            r = client.get("/api/v1/compliance/summary")
            assert r.status_code == 401
    def test_rejects_invalid_key(self):
        with patch("app.auth.middleware.is_auth_enabled", return_value=True):
            r = client.get("/api/v1/compliance/summary", headers={"X-API-Key": "bad"})
            assert r.status_code == 403
    def test_accepts_valid_key(self):
        cr = client.post("/api/v1/auth/keys", json={"name": "mw-test"})
        key = cr.json()["key"]
        with patch("app.auth.middleware.is_auth_enabled", return_value=True),              patch("app.auth.middleware.get_api_keys", return_value=[{"key": key, "active": True}]):
            r = client.get("/api/v1/compliance/summary", headers={"X-API-Key": key})
            assert r.status_code == 200
    def test_exempt_paths(self):
        with patch("app.auth.middleware.is_auth_enabled", return_value=True):
            assert client.get("/health").status_code == 200
            assert client.get("/").status_code == 200
    def test_bearer_token(self):
        cr = client.post("/api/v1/auth/keys", json={"name": "bearer"})
        key = cr.json()["key"]
        with patch("app.auth.middleware.is_auth_enabled", return_value=True),              patch("app.auth.middleware.get_api_keys", return_value=[{"key": key, "active": True}]):
            r = client.get("/api/v1/compliance/summary", headers={"Authorization": f"Bearer {key}"})
            assert r.status_code == 200
