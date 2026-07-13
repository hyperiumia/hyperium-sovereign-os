"""Forensics API Router — Timeline, packages, watermarking, taint analysis, SIEM export."""
from fastapi import APIRouter, Query
from fastapi.responses import Response
import structlog

logger = structlog.get_logger("forensics.router")
router = APIRouter()


@router.get("/timeline")
async def get_timeline(user_id: str = None, device_id: str = None,
                       hours: int = Query(24, ge=1, le=720)):
    from app.database import async_session
    from .timeline import ForensicTimeline
    async with async_session() as db:
        return await ForensicTimeline.build_timeline(db, user_id=user_id, device_id=device_id)


@router.get("/package/{case_id}")
async def get_package(case_id: str, format: str = Query("json", pattern="^(json|zip)$")):
    from app.database import async_session
    from .package import ForensicPackageExporter
    async with async_session() as db:
        if format == "zip":
            data = await ForensicPackageExporter.export_zip(db, case_id)
            return Response(content=data, media_type="application/zip",
                           headers={"Content-Disposition": f"attachment; filename=forensic-{case_id}.zip"})
        return await ForensicPackageExporter.export_package(db, case_id)


@router.post("/watermark")
async def create_watermark(user_id: str, document_id: str, workspace_id: str = None):
    from .watermark import DocumentWatermarker
    return DocumentWatermarker.generate_watermark(user_id, document_id, workspace_id)


@router.get("/watermark/verify")
async def verify_watermark(token: str):
    from .watermark import DocumentWatermarker
    return DocumentWatermarker.verify_watermark(token)


@router.get("/taint")
async def get_taint_analysis(user_id: str = None, document_id: str = None, hours: int = Query(24)):
    from app.database import async_session
    from .taint import TaintAnalyzer
    async with async_session() as db:
        return await TaintAnalyzer.analyze_data_flow(db, user_id=user_id,
                                                      document_id=document_id, hours=hours)


@router.get("/siem/export")
async def export_siem(format: str = Query("json", pattern="^(json|cef|leef|syslog)$")):
    from app.database import async_session
    from app.models import Event
    from sqlalchemy import select
    from app.integrations.siem import SIEMExporter
    async with async_session() as db:
        result = await db.execute(select(Event).order_by(Event.created_at.desc()).limit(1000))
        events = result.scalars().all()
        formatted = SIEMExporter.format_events(events, format)
        if format in ("cef", "leef", "syslog"):
            return Response(content=formatted, media_type="text/plain")
        return formatted


@router.get("/siem/formats")
async def get_siem_formats():
    from app.integrations.siem import SIEMExporter
    return SIEMExporter.get_supported_formats()
