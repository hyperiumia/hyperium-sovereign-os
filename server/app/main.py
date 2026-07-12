import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
import structlog
from app.config import settings
from app.database import init_db, async_session, get_db
from app.models import Session, SessionStatus, MerkleEpoch
from app.core.evidence_vault import evidence_vault
from app.core.policy_engine import policy_engine
from app.core.crypto import key_manager
from app.api import events, policies, evidence, alerts, workspaces

logger = structlog.get_logger(__name__)
START_TIME = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("sovereign_os.starting", version=settings.VERSION)
    await init_db()
    async with async_session() as db:
        key_manager.initialize()
        await evidence_vault.initialize(db)
        await policy_engine.import_from_yaml(db)
        await policy_engine.load_policies(db)
        await db.commit()
    logger.info("sovereign_os.ready")
    yield
    logger.info("sovereign_os.shutdown")


app = FastAPI(
    title=settings.APP_NAME, version=settings.VERSION,
    description="Sistema de Soberania Corporativa y Anti-Espionaje", lifespan=lifespan,
)
app.include_router(events.router)
app.include_router(policies.router)
app.include_router(evidence.router)
app.include_router(alerts.router)
app.include_router(workspaces.router)


@app.get("/health")
async def health_check(db: AsyncSession = Depends(get_db)):
    active = await db.execute(
        select(func.count(Session.id)).where(Session.status == SessionStatus.ACTIVE)
    )
    latest = await db.execute(select(func.max(MerkleEpoch.epoch_number)))
    return {
        "status": "healthy",
        "version": settings.VERSION,
        "uptime_seconds": round(time.time() - START_TIME, 1),
        "active_sessions": active.scalar() or 0,
        "merkle_current_epoch": latest.scalar() or 0,
        "signing_key_id": key_manager.key_id,
    }


@app.get("/")
async def root():
    return {"product": "Hyperium Sovereign-OS", "version": settings.VERSION, "docs": "/docs"}
