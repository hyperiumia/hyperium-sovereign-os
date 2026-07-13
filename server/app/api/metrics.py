"""Metrics endpoint — System health and platform stats."""
import os, time
from fastapi import APIRouter
from app.config import settings

router = APIRouter(tags=["Metrics"])
_boot = time.time()


@router.get("/metrics")
async def metrics():
    from app.core.evidence_vault import evidence_vault
    from app.core.policy_engine import policy_engine

    uptime = round(time.time() - _boot, 1)
    vault = {}
    try:
        if hasattr(evidence_vault, "get_stats"):
            vault = await evidence_vault.get_stats()
    except Exception:
        pass
    pcount = 0
    try:
        if hasattr(policy_engine, "_policies"):
            pcount = len(policy_engine._policies)
    except Exception:
        pass

    return {
        "platform": settings.APP_NAME,
        "version": settings.VERSION,
        "uptime_seconds": uptime,
        "config": {
            "auth_enabled": os.getenv("SOVEREIGN_AUTH_ENABLED", "").lower() in ("true", "1", "yes"),
            "rate_limit_rpm": int(os.getenv("SOVEREIGN_RATE_LIMIT", "0")),
        },
        "vault": vault,
        "policies_loaded": pcount,
    }
