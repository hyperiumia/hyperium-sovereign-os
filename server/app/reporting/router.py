from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from ..compliance.engine import ComplianceEngine
from .html_report import generate_framework_report, generate_executive_summary

router = APIRouter(prefix="/api/v1/reports", tags=["Reports"])

@router.get("/executive", response_class=HTMLResponse)
async def executive_summary():
    return HTMLResponse(content=generate_executive_summary(
        ComplianceEngine.generate_summary()))

@router.get("/compliance/{framework}", response_class=HTMLResponse)
async def compliance_report(framework: str):
    report = ComplianceEngine.evaluate_framework(framework)
    if not report:
        return HTMLResponse(
            "<h1 style='color:#ef4444;padding:40px;font-family:monospace'>Framework not found</h1>",
            status_code=404)
    gaps = ComplianceEngine.find_gaps(framework)
    controls = ComplianceEngine.get_controls(framework)
    if controls:
        report["controls"] = controls
    return HTMLResponse(content=generate_framework_report(report, gaps))
