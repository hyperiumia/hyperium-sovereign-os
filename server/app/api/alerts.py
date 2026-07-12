from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.models import Alert, AlertStatus
from app.schemas import AlertResponse
from datetime import datetime, timezone

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


@router.get("/")
async def list_alerts(status: str = None, severity: str = None, db: AsyncSession = Depends(get_db)):
    query = select(Alert).order_by(Alert.created_at.desc()).limit(100)
    if status:
        query = query.where(Alert.status == status)
    if severity:
        query = query.where(Alert.severity == severity)
    result = await db.execute(query)
    return [AlertResponse.model_validate(a) for a in result.scalars().all()]


@router.put("/{alert_id}/resolve")
async def resolve_alert(alert_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(404, "Alert not found")
    alert.status = AlertStatus.RESOLVED
    alert.resolved_at = datetime.now(timezone.utc)
    return {"status": "resolved", "alert_id": alert_id}
