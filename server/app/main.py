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
from app.compliance.router import router as compliance_router
from app.compliance.breach_router import router as breach_router
from app.forensics.router import router as forensics_router
from app.auth.middleware import APIKeyMiddleware
from app.auth.router import router as auth_router
from app.reporting.router import router as reporting_router
from app.middleware.rate_limiter import RateLimiter
from app.api.metrics import router as metrics_router
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import os

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
app.add_middleware(APIKeyMiddleware)
app.add_middleware(RateLimiter)
app.include_router(events.router)
app.include_router(policies.router)
app.include_router(evidence.router)
app.include_router(compliance_router, prefix="/api/v1/compliance", tags=["compliance"])
app.include_router(breach_router, prefix="/api/v1/compliance", tags=["compliance"])
app.include_router(forensics_router, prefix="/api/v1/forensics", tags=["forensics"])
app.include_router(alerts.router)
app.include_router(workspaces.router)
app.include_router(auth_router)
app.include_router(reporting_router)
app.include_router(metrics_router)


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


# Static files & dashboard
_static_dir = os.path.join(os.path.dirname(__file__), "..", "static")
if os.path.isdir(_static_dir):
    app.mount("/static", StaticFiles(directory=_static_dir), name="static")

@app.get("/dashboard")
async def _dashboard():
    return RedirectResponse(url="/static/dashboard.html")
