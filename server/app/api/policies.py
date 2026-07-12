from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.models import Policy
from app.schemas import PolicyCreate, PolicyResponse
from app.core.policy_engine import policy_engine

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])


@router.get("/")
async def list_policies(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Policy).order_by(Policy.priority.asc()))
    return [PolicyResponse.model_validate(p) for p in result.scalars().all()]


@router.post("/")
async def create_policy(policy_in: PolicyCreate, db: AsyncSession = Depends(get_db)):
    policy = Policy(
        name=policy_in.name, description=policy_in.description,
        trigger_event=policy_in.trigger_event,
        conditions=[c.model_dump() for c in policy_in.conditions],
        action=policy_in.action, severity=policy_in.severity, priority=policy_in.priority,
    )
    db.add(policy)
    await db.flush()
    await policy_engine.load_policies(db)
    return PolicyResponse.model_validate(policy)


@router.put("/{policy_id}/toggle")
async def toggle_policy(policy_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Policy).where(Policy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    policy.is_enabled = not policy.is_enabled
    await policy_engine.load_policies(db)
    return {"id": policy.id, "enabled": policy.is_enabled}
