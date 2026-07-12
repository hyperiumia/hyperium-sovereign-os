import json
import pytest
import hmac as hmac_mod
import hashlib
from app.core.evidence_vault import EvidenceVault
from app.core.crypto import sha256_hex, key_manager
from app.models import MerkleEpoch
from sqlalchemy import select


def make_signed(payload, secret):
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    event_hash = sha256_hex(canonical.encode())
    hmac_sig = hmac_mod.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return event_hash, hmac_sig


def fresh_vault():
    v = EvidenceVault()
    v._current_epoch = 0
    v._events_in_epoch = 0
    return v


@pytest.mark.asyncio
class TestEvidenceVaultIngest:
    async def test_ingest_valid_event(self, db):
        from app.config import settings
        old = settings.AGENT_HMAC_SECRET
        settings.AGENT_HMAC_SECRET = "vault-secret"
        key_manager.initialize()

        vault = fresh_vault()
        payload = {"action": "file.read", "path": "/etc/passwd"}
        eh, hs = make_signed(payload, "vault-secret")
        event = await vault.ingest_event(db, None, "file.read", "fs", payload, "LOW", eh, hs)

        assert event.id is not None
        assert len(event.id) == 36
        assert event.event_hash == eh
        assert event.merkle_leaf_index == 0
        settings.AGENT_HMAC_SECRET = old

    async def test_reject_tampered_hash(self, db):
        from app.config import settings
        old = settings.AGENT_HMAC_SECRET
        settings.AGENT_HMAC_SECRET = "vault-secret"
        key_manager.initialize()

        vault = fresh_vault()
        _, hs = make_signed({"x": 1}, "vault-secret")
        with pytest.raises(ValueError, match="hash mismatch"):
            await vault.ingest_event(db, None, "t", "t", {"x": 1}, "LOW", "a" * 64, hs)
        settings.AGENT_HMAC_SECRET = old

    async def test_reject_invalid_hmac(self, db):
        from app.config import settings
        old = settings.AGENT_HMAC_SECRET
        settings.AGENT_HMAC_SECRET = "vault-secret"
        key_manager.initialize()

        vault = fresh_vault()
        eh, _ = make_signed({"x": 1}, "vault-secret")
        with pytest.raises(ValueError, match="HMAC verification failed"):
            await vault.ingest_event(db, None, "t", "t", {"x": 1}, "LOW", eh, "b" * 64)
        settings.AGENT_HMAC_SECRET = old

    async def test_multiple_events_increment_index(self, db):
        from app.config import settings
        old = settings.AGENT_HMAC_SECRET
        settings.AGENT_HMAC_SECRET = "vault-secret"
        key_manager.initialize()

        vault = fresh_vault()
        for i in range(5):
            eh, hs = make_signed({"i": i}, "vault-secret")
            event = await vault.ingest_event(db, None, f"t.{i}", "test", {"i": i}, "LOW", eh, hs)
            assert event.merkle_leaf_index == i
            assert event.id is not None
            assert len(event.id) == 36
        settings.AGENT_HMAC_SECRET = old


@pytest.mark.asyncio
class TestMerkleIntegration:
    async def test_epoch_closes_after_limit(self, db):
        from app.config import settings
        old = settings.AGENT_HMAC_SECRET
        settings.AGENT_HMAC_SECRET = "mk-secret"
        key_manager.initialize()

        vault = fresh_vault()
        vault._epoch_limit = 3
        for i in range(4):
            eh, hs = make_signed({"i": i}, "mk-secret")
            await vault.ingest_event(db, None, f"e.{i}", "t", {"i": i}, "LOW", eh, hs)

        assert vault._current_epoch == 1
        epoch = (await db.execute(select(MerkleEpoch).where(MerkleEpoch.epoch_number == 0))).scalar_one_or_none()
        assert epoch is not None
        assert epoch.leaf_count == 3
        settings.AGENT_HMAC_SECRET = old

    async def test_force_close_epoch(self, db):
        from app.config import settings
        old = settings.AGENT_HMAC_SECRET
        settings.AGENT_HMAC_SECRET = "mk-secret"
        key_manager.initialize()

        vault = fresh_vault()
        vault._epoch_limit = 9999
        for i in range(5):
            eh, hs = make_signed({"i": i}, "mk-secret")
            await vault.ingest_event(db, None, f"e.{i}", "t", {"i": i}, "LOW", eh, hs)

        await vault.force_close_epoch(db)
        epoch = (await db.execute(select(MerkleEpoch).where(MerkleEpoch.epoch_number == 0))).scalar_one_or_none()
        assert epoch is not None
        assert epoch.leaf_count == 5
        settings.AGENT_HMAC_SECRET = old

    async def test_epoch_signature_valid(self, db):
        from app.config import settings
        old = settings.AGENT_HMAC_SECRET
        settings.AGENT_HMAC_SECRET = "sig-secret"
        key_manager.initialize()

        vault = fresh_vault()
        vault._epoch_limit = 9999
        for i in range(3):
            eh, hs = make_signed({"i": i}, "sig-secret")
            await vault.ingest_event(db, None, f"s.{i}", "t", {"i": i}, "LOW", eh, hs)

        await vault.force_close_epoch(db)
        epoch = (await db.execute(select(MerkleEpoch).where(MerkleEpoch.epoch_number == 0))).scalar_one_or_none()
        assert key_manager.verify(bytes.fromhex(epoch.root_hash), epoch.signature) is True
        settings.AGENT_HMAC_SECRET = old


@pytest.mark.asyncio
class TestEventVerification:
    async def test_verify_valid_event(self, db):
        from app.config import settings
        old = settings.AGENT_HMAC_SECRET
        settings.AGENT_HMAC_SECRET = "vf-secret"
        key_manager.initialize()

        vault = fresh_vault()
        eh, hs = make_signed({"action": "verify.me", "v": 42}, "vf-secret")
        event = await vault.ingest_event(db, None, "vf", "t", {"action": "verify.me", "v": 42}, "LOW", eh, hs)
        await vault.force_close_epoch(db)

        result = await vault.verify_event(db, event.id)
        assert result["is_valid"] is True
        assert result["hash_valid"] is True
        assert result["epoch_signature_valid"] is True
        settings.AGENT_HMAC_SECRET = old

    async def test_verify_nonexistent(self, db):
        key_manager.initialize()
        vault = fresh_vault()
        result = await vault.verify_event(db, "does-not-exist-xyz")
        assert result["is_valid"] is False
        assert result["event_id"] == "does-not-exist-xyz"
        assert result["message"] == "Event not found"
