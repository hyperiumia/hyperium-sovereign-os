from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.models import Event, MerkleEpoch
from app.core.evidence_vault import evidence_vault
from app.core.crypto import key_manager

router = APIRouter(prefix="/api/v1/evidence", tags=["evidence"])


@router.get("/verify/{event_id}")
async def verify_event(event_id: str, db: AsyncSession = Depends(get_db)):
    return await evidence_vault.verify_event(db, event_id)


@router.get("/epoch/{epoch_number}")
async def get_epoch(epoch_number: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(MerkleEpoch).where(MerkleEpoch.epoch_number == epoch_number))
    epoch = result.scalar_one_or_none()
    if not epoch:
        raise HTTPException(status_code=404, detail="Epoch not found")
    return {
        "epoch_number": epoch.epoch_number, "root_hash": epoch.root_hash,
        "leaf_count": epoch.leaf_count, "signature": epoch.signature,
        "signed_by": epoch.signed_by, "created_at": epoch.created_at.isoformat(),
    }


@router.get("/epoch/{epoch_number}/verify")
async def verify_epoch(epoch_number: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(MerkleEpoch).where(MerkleEpoch.epoch_number == epoch_number))
    epoch = result.scalar_one_or_none()
    if not epoch:
        raise HTTPException(status_code=404, detail="Epoch not found")
    is_valid = key_manager.verify(bytes.fromhex(epoch.root_hash), epoch.signature)
    return {"epoch_number": epoch.epoch_number, "signature_valid": is_valid, "root_hash": epoch.root_hash}


@router.get("/stats")
async def evidence_stats(db: AsyncSession = Depends(get_db)):
    event_count = await db.execute(select(func.count(Event.id)))
    epoch_count = await db.execute(select(func.count(MerkleEpoch.epoch_number)))
    latest_epoch = await db.execute(select(MerkleEpoch).order_by(MerkleEpoch.epoch_number.desc()).limit(1))
    latest = latest_epoch.scalar_one_or_none()
    return {
        "total_events": event_count.scalar(),
        "total_epochs": epoch_count.scalar(),
        "latest_epoch": latest.epoch_number if latest else 0,
        "latest_root_hash": latest.root_hash if latest else None,
        "signing_key_id": key_manager.key_id,
    }
