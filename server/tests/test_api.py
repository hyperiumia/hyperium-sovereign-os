import json
import hmac as hmac_mod
import hashlib
import pytest
from app.core.crypto import sha256_hex


def sign(payload, secret):
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    event_hash = sha256_hex(canonical.encode())
    hmac_sig = hmac_mod.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return event_hash, hmac_sig


def make_event(payload, secret, event_type="test.event", severity="LOW"):
    eh, hs = sign(payload, secret)
    return {
        "agent_id": "test-agent", "device_id": "test-device",
        "event_type": event_type, "source_module": "test",
        "payload": payload, "severity": severity,
        "timestamp": "2025-01-01T00:00:00Z",
        "event_hash": eh, "hmac_signature": hs,
    }


@pytest.mark.asyncio
class TestHealth:
    async def test_root(self, client):
        r = await client.get("/")
        assert r.status_code == 200
        assert r.json()["product"] == "Hyperium Sovereign-OS"

    async def test_health(self, client):
        r = await client.get("/health")
        assert r.status_code == 200
        d = r.json()
        assert d["status"] == "healthy"
        assert d["signing_key_id"] is not None


@pytest.mark.asyncio
class TestWorkspaces:
    async def test_create_top_secret(self, client):
        r = await client.post("/api/v1/workspaces/", json={
            "name": "Vault Alpha", "classification": "TOP_SECRET",
            "is_air_gapped": True, "allow_usb": False, "allow_network": False,
        })
        assert r.status_code == 200
        d = r.json()
        assert d["name"] == "Vault Alpha"
        assert d["classification"] == "TOP_SECRET"
        assert len(d["id"]) == 36

    async def test_create_default(self, client):
        r = await client.post("/api/v1/workspaces/", json={"name": "Default"})
        assert r.status_code == 200
        assert r.json()["classification"] == "INTERNAL"

    async def test_list(self, client):
        await client.post("/api/v1/workspaces/", json={"name": "A"})
        await client.post("/api/v1/workspaces/", json={"name": "B"})
        r = await client.get("/api/v1/workspaces/")
        assert len(r.json()) == 2


@pytest.mark.asyncio
class TestPolicies:
    async def test_yaml_imported(self, client):
        r = await client.get("/api/v1/policies/")
        policies = r.json()
        assert len(policies) >= 5
        names = [p["name"] for p in policies]
        assert "block-usb-confidential" in names

    async def test_create_custom(self, client):
        r = await client.post("/api/v1/policies/", json={
            "name": "custom-export-alert",
            "trigger_event": "data.export.*",
            "conditions": [{"field": "session.risk_score", "operator": "gt", "value": 0.7}],
            "action": "ALERT", "severity": "HIGH", "priority": 50,
        })
        assert r.status_code == 200
        assert r.json()["action"] == "ALERT"

    async def test_toggle(self, client):
        policies = (await client.get("/api/v1/policies/")).json()
        r = await client.put(f"/api/v1/policies/{policies[0]['id']}/toggle")
        assert "enabled" in r.json()


@pytest.mark.asyncio
class TestEventIngestion:
    async def test_valid_event_accepted(self, client):
        from app.config import settings
        payload = {"action": "usb.connected", "vendor": "0781", "data_bytes": 0}
        body = make_event(payload, settings.AGENT_HMAC_SECRET, "usb.device.connected", "MEDIUM")
        r = await client.post("/api/v1/events/ingest", json=body)
        assert r.status_code == 200
        d = r.json()
        assert d["status"] == "accepted"
        assert d["event_id"] is not None
        assert len(d["event_id"]) == 36

    async def test_rejects_tampered_hash(self, client):
        from app.config import settings
        payload = {"action": "file.read"}
        body = make_event(payload, settings.AGENT_HMAC_SECRET)
        body["event_hash"] = "a" * 64
        r = await client.post("/api/v1/events/ingest", json=body)
        assert r.status_code == 400

    async def test_rejects_bad_hmac(self, client):
        from app.config import settings
        payload = {"action": "data.export"}
        eh, _ = sign(payload, settings.AGENT_HMAC_SECRET)
        body = make_event(payload, settings.AGENT_HMAC_SECRET)
        body["event_hash"] = eh
        body["hmac_signature"] = "0" * 64
        r = await client.post("/api/v1/events/ingest", json=body)
        assert r.status_code == 400


@pytest.mark.asyncio
class TestEvidenceVerification:
    async def test_verify_stored_event(self, client):
        from app.config import settings
        payload = {"action": "verify.me", "data": 123}
        body = make_event(payload, settings.AGENT_HMAC_SECRET, "verify.test")
        ingest = await client.post("/api/v1/events/ingest", json=body)
        assert ingest.status_code == 200
        event_id = ingest.json()["event_id"]
        assert event_id is not None

        verify = await client.get(f"/api/v1/evidence/verify/{event_id}")
        assert verify.status_code == 200
        d = verify.json()
        assert d["is_valid"] is True
        assert d["hash_valid"] is True

    async def test_verify_nonexistent(self, client):
        r = await client.get("/api/v1/evidence/verify/does-not-exist-xyz")
        assert r.status_code == 200
        d = r.json()
        assert d["is_valid"] is False
        assert d["message"] == "Event not found"

    async def test_evidence_stats(self, client):
        from app.config import settings
        for i in range(3):
            body = make_event({"i": i}, settings.AGENT_HMAC_SECRET, f"s.{i}")
            await client.post("/api/v1/events/ingest", json=body)
        r = await client.get("/api/v1/evidence/stats")
        d = r.json()
        assert d["total_events"] == 3
        assert len(d["signing_key_id"]) == 16


@pytest.mark.asyncio
class TestAlerts:
    async def test_list_empty(self, client):
        r = await client.get("/api/v1/alerts/")
        assert r.status_code == 200
        assert isinstance(r.json(), list)


@pytest.mark.asyncio
class TestBatchIngestion:
    async def test_batch(self, client):
        from app.config import settings
        events = []
        for i in range(5):
            eh, hs = sign({"i": i}, settings.AGENT_HMAC_SECRET)
            events.append({
                "agent_id": "batch-agent", "device_id": "batch-device",
                "event_type": f"batch.{i}", "source_module": "batch",
                "payload": {"i": i}, "severity": "LOW",
                "timestamp": "2025-01-01T00:00:00Z",
                "event_hash": eh, "hmac_signature": hs,
            })
        r = await client.post("/api/v1/events/ingest/batch", json={"events": events})
        assert r.status_code == 200
        d = r.json()
        assert d["processed"] == 5
        for result in d["results"]:
            assert result["status"] == "accepted"
            assert result["event_id"] is not None
