from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.models import Workspace, AccessGrant, Revocation
from app.schemas import WorkspaceCreate, WorkspaceResponse
from datetime import datetime, timezone, timedelta

router = APIRouter(prefix="/api/v1/workspaces", tags=["workspaces"])


@router.get("/")
async def list_workspaces(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Workspace).where(Workspace.is_active == True))
    return [WorkspaceResponse.model_validate(w) for w in result.scalars().all()]


@router.post("/")
async def create_workspace(ws_in: WorkspaceCreate, db: AsyncSession = Depends(get_db)):
    workspace = Workspace(**ws_in.model_dump())
    db.add(workspace)
    await db.flush()
    return WorkspaceResponse.model_validate(workspace)


@router.post("/{workspace_id}/grant")
async def grant_access(workspace_id: str, user_id: str, granted_by: str, hours: int = 8, reason: str = "", db: AsyncSession = Depends(get_db)):
    grant = AccessGrant(
        user_id=user_id, workspace_id=workspace_id, granted_by=granted_by,
        reason=reason, expires_at=datetime.now(timezone.utc) + timedelta(hours=hours),
    )
    db.add(grant)
    await db.flush()
    return {"grant_id": grant.id, "expires_at": grant.expires_at.isoformat()}


@router.post("/{workspace_id}/revoke/{grant_id}")
async def revoke_access(workspace_id: str, grant_id: str, revoked_by: str, reason: str = "", db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AccessGrant).where(AccessGrant.id == grant_id))
    grant = result.scalar_one_or_none()
    if not grant:
        raise HTTPException(status_code=404, detail="Grant not found")
    grant.is_active = False
    grant.revoked_at = datetime.now(timezone.utc)
    grant.revoke_reason = reason
    revocation = Revocation(grant_id=grant_id, revoked_by=revoked_by, reason=reason)
    db.add(revocation)
    return {"status": "revoked", "grant_id": grant_id}
