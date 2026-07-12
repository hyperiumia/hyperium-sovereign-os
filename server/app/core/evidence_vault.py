from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import Event, MerkleEpoch, gen_uuid
from app.core.crypto import MerkleTree, key_manager, compute_event_hash, verify_hmac, sha256_hex
from app.config import settings
import json
import structlog

logger = structlog.get_logger(__name__)


class EvidenceVault:
    def __init__(self):
        self._current_tree = MerkleTree()
        self._current_epoch = 0
        self._events_in_epoch = 0
        self._epoch_limit = 100

    async def initialize(self, db: AsyncSession):
        result = await db.execute(
            select(MerkleEpoch).order_by(MerkleEpoch.epoch_number.desc()).limit(1)
        )
        last_epoch = result.scalar_one_or_none()
        if last_epoch:
            self._current_epoch = last_epoch.epoch_number + 1
        else:
            self._current_epoch = 0
        key_manager.initialize()
        logger.info("evidence_vault.initialized", epoch=self._current_epoch)

    async def ingest_event(self, db: AsyncSession, session_id, event_type, source_module,
                           payload, severity, event_hash, hmac_signature) -> Event:
        computed_hash = compute_event_hash(payload)
        if computed_hash != event_hash:
            raise ValueError("Event hash mismatch: payload tampered in transit")

        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        if not verify_hmac(payload_bytes, hmac_signature, settings.AGENT_HMAC_SECRET):
            raise ValueError("HMAC verification failed: event not authenticated")

        leaf_index = self._current_tree.add_leaf(event_hash)

        new_id = gen_uuid()
        event = Event(
            id=new_id,
            session_id=session_id,
            event_type=event_type,
            source_module=source_module,
            payload=payload,
            severity=severity,
            event_hash=event_hash,
            hmac_signature=hmac_signature,
            merkle_epoch=self._current_epoch,
            merkle_leaf_index=leaf_index,
        )
        db.add(event)
        await db.flush()

        logger.info("evidence_vault.stored", event_id=event.id, epoch=self._current_epoch, leaf=leaf_index)

        self._events_in_epoch += 1
        if self._events_in_epoch >= self._epoch_limit:
            await self._close_epoch(db)

        return event

    async def _close_epoch(self, db: AsyncSession):
        root_hash = self._current_tree.compute_root()
        signature = key_manager.sign(bytes.fromhex(root_hash))
        db.add(MerkleEpoch(
            epoch_number=self._current_epoch,
            root_hash=root_hash,
            leaf_count=self._events_in_epoch,
            signature=signature,
            signed_by=key_manager.key_id,
        ))
        await db.flush()
        await db.execute(
            Event.__table__.update()
            .where(Event.merkle_epoch == self._current_epoch)
            .values(merkle_root_hash=root_hash)
        )
        logger.info("evidence_vault.epoch_closed", epoch=self._current_epoch, root=root_hash[:16])
        self._current_epoch += 1
        self._events_in_epoch = 0
        self._current_tree = MerkleTree()

    async def force_close_epoch(self, db: AsyncSession):
        if self._events_in_epoch > 0:
            await self._close_epoch(db)

    async def verify_event(self, db: AsyncSession, event_id: str) -> dict:
        result = await db.execute(select(Event).where(Event.id == event_id))
        event = result.scalar_one_or_none()
        if not event:
            return {
                "event_id": event_id, "is_valid": False,
                "computed_hash": None, "stored_hash": None,
                "hash_valid": False, "merkle_epoch": None,
                "merkle_root": None, "epoch_signature_valid": None,
                "message": "Event not found",
            }

        recomputed_hash = compute_event_hash(event.payload)
        hash_valid = recomputed_hash == event.event_hash

        epoch_result = await db.execute(
            select(MerkleEpoch).where(MerkleEpoch.epoch_number == event.merkle_epoch)
        )
        epoch = epoch_result.scalar_one_or_none()
        epoch_signature_valid = None
        if epoch and hash_valid:
            epoch_signature_valid = key_manager.verify(bytes.fromhex(epoch.root_hash), epoch.signature)

        return {
            "event_id": event_id,
            "is_valid": hash_valid,
            "computed_hash": recomputed_hash,
            "stored_hash": event.event_hash,
            "hash_valid": hash_valid,
            "merkle_epoch": event.merkle_epoch,
            "merkle_root": epoch.root_hash if epoch else None,
            "epoch_signature_valid": epoch_signature_valid,
            "message": "Integrity verified" if hash_valid else "INTEGRITY VIOLATION DETECTED",
        }


evidence_vault = EvidenceVault()
