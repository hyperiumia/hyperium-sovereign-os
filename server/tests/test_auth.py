import pytest
from unittest.mock import patch


@pytest.mark.asyncio
class TestAuthDisabled:
    async def test_passes_without_key(self, client):
        r = await client.get("/api/v1/compliance/summary")
        assert r.status_code == 200

    async def test_health_accessible(self, client):
        r = await client.get("/health")
        assert r.status_code == 200


@pytest.mark.asyncio
class TestAuthEndpoints:
    async def test_status(self, client):
        r = await client.get("/api/v1/auth/status")
        assert r.status_code == 200
        assert "enabled" in r.json()

    async def test_list_keys(self, client):
        r = await client.get("/api/v1/auth/keys")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    async def test_create_and_revoke(self, client):
        r = await client.post("/api/v1/auth/keys", json={"name": "test"})
        assert r.status_code == 200
        d = r.json()
        assert d["key"].startswith("sk_sov_")
        kid = d["id"]
        r2 = await client.delete(f"/api/v1/auth/keys/{kid}")
        assert r2.status_code == 200
        assert r2.json()["revoked"] is True

    async def test_revoke_nonexistent(self, client):
        r = await client.delete("/api/v1/auth/keys/key_noexist")
        assert r.status_code == 404


@pytest.mark.asyncio
class TestMiddleware:
    async def test_rejects_missing_key(self, client):
        with patch("app.auth.middleware.is_auth_enabled", return_value=True):
            r = await client.get("/api/v1/compliance/summary")
            assert r.status_code == 401

    async def test_rejects_invalid_key(self, client):
        with patch("app.auth.middleware.is_auth_enabled", return_value=True):
            r = await client.get("/api/v1/compliance/summary", headers={"X-API-Key": "bad"})
            assert r.status_code == 403

    async def test_accepts_valid_key(self, client):
        cr = await client.post("/api/v1/auth/keys", json={"name": "mw-test"})
        key = cr.json()["key"]
        with patch("app.auth.middleware.is_auth_enabled", return_value=True), \
             patch("app.auth.middleware.get_api_keys", return_value=[{"key": key, "active": True}]):
            r = await client.get("/api/v1/compliance/summary", headers={"X-API-Key": key})
            assert r.status_code == 200

    async def test_exempt_paths(self, client):
        with patch("app.auth.middleware.is_auth_enabled", return_value=True):
            assert (await client.get("/health")).status_code == 200
            assert (await client.get("/")).status_code == 200

    async def test_bearer_token(self, client):
        cr = await client.post("/api/v1/auth/keys", json={"name": "bearer"})
        key = cr.json()["key"]
        with patch("app.auth.middleware.is_auth_enabled", return_value=True), \
             patch("app.auth.middleware.get_api_keys", return_value=[{"key": key, "active": True}]):
            r = await client.get("/api/v1/compliance/summary", headers={"Authorization": f"Bearer {key}"})
            assert r.status_code == 200
