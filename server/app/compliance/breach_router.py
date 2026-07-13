"""Breach Notification and RFC 3161 API endpoints."""
from fastapi import APIRouter, Query
import structlog

logger = structlog.get_logger("compliance.breach_router")
router = APIRouter()


@router.get("/breach/evaluate")
async def evaluate_breach(hours: int = Query(24, ge=1, le=720)):
    from app.database import async_session
    from .breach_notification import BreachNotificationEngine
    async with async_session() as db:
        return await BreachNotificationEngine.evaluate_breach(db, hours=hours)


@router.get("/breach/report/{regulation}")
async def get_breach_report(regulation: str, hours: int = Query(24)):
    from app.database import async_session
    from .breach_notification import BreachNotificationEngine
    async with async_session() as db:
        breach = await BreachNotificationEngine.evaluate_breach(db, hours=hours)
        return BreachNotificationEngine.generate_notification_report(breach, regulation)


@router.get("/timestamp/{event_id}")
async def get_timestamp(event_id: str):
    from app.database import async_session
    from app.models import Event
    from sqlalchemy import select
    from .rfc3161 import timestamp_authority
    async with async_session() as db:
        result = await db.execute(select(Event).where(Event.id == event_id))
        event = result.scalar_one_or_none()
        if not event:
            return {"error": "Event not found"}
        return timestamp_authority.generate_timestamp(event.event_hash, event_id)


@router.get("/timestamp/verify/{event_id}")
async def verify_timestamp(event_id: str):
    from app.database import async_session
    from app.models import Event
    from sqlalchemy import select
    from .rfc3161 import timestamp_authority
    async with async_session() as db:
        result = await db.execute(select(Event).where(Event.id == event_id))
        event = result.scalar_one_or_none()
        if not event:
            return {"error": "Event not found"}
        ts = timestamp_authority.generate_timestamp(event.event_hash, event_id)
        return timestamp_authority.verify_timestamp(ts, event.event_hash)
