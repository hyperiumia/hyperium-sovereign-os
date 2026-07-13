"""
Sovereign-OS Compliance API Router
REST endpoints for compliance framework evaluation and reporting.
"""
from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse
import structlog
from .engine import ComplianceEngine

logger = structlog.get_logger("compliance.router")
router = APIRouter()


@router.get("/frameworks")
async def list_frameworks():
    logger.info("compliance.frameworks.listed")
    frameworks = ComplianceEngine.list_frameworks()
    return {"frameworks": frameworks, "total": len(frameworks)}


@router.get("/report/{framework_name}")
async def get_report(framework_name: str):
    logger.info("compliance.report.requested", framework=framework_name)
    report = ComplianceEngine.evaluate_framework(framework_name)
    if not report:
        return {"error": f"Framework not found: {framework_name}", "available": ["nist-csf-2.0", "iso-27001"]}
    return report


@router.get("/gaps/{framework_name}")
async def get_gaps(framework_name: str):
    logger.info("compliance.gaps.requested", framework=framework_name)
    gaps = ComplianceEngine.find_gaps(framework_name)
    if not gaps:
        return {"error": f"Framework not found: {framework_name}", "available": ["nist-csf-2.0", "iso-27001"]}
    return gaps


@router.get("/controls/{framework_name}")
async def get_controls(framework_name: str):
    logger.info("compliance.controls.requested", framework=framework_name)
    controls = ComplianceEngine.get_controls(framework_name)
    if not controls:
        return {"error": f"Framework not found: {framework_name}", "available": ["nist-csf-2.0", "iso-27001"]}
    return controls


@router.get("/summary")
async def get_summary():
    logger.info("compliance.summary.requested")
    return ComplianceEngine.generate_summary()


@router.get("/evidence/{framework_name}")
async def get_evidence_package(framework_name: str):
    logger.info("compliance.evidence.requested", framework=framework_name)
    evidence = ComplianceEngine.generate_evidence_package(framework_name)
    if not evidence:
        return {"error": f"Framework not found: {framework_name}", "available": ["nist-csf-2.0", "iso-27001"]}
    return evidence


@router.get("/export/{framework_name}")
async def export_report(framework_name: str, format: str = Query("json", regex="^(json|html)$")):
    logger.info("compliance.export.requested", framework=framework_name, format=format)
    report = ComplianceEngine.evaluate_framework(framework_name)
    if not report:
        return {"error": f"Framework not found: {framework_name}"}

    if format == "html":
        return HTMLResponse(content=_render_html_report(report))
    return report


def _render_html_report(report):
    controls_html = ""
    for ctrl in report["controls"]:
        color = {"covered": "#00ff88", "partial": "#ffd600", "not_covered": "#ff2d55", "not_applicable": "#555"}
        c = color.get(ctrl["status"], "#555")
        badge = f'<span style="background:{c}22;color:{c};border:1px solid {c}44;padding:2px 8px;font-size:11px;text-transform:uppercase">{ctrl["status"]}</span>'
        controls_html += f'<tr><td>{ctrl["id"]}</td><td>{ctrl["title"]}</td><td>{ctrl["component"]}</td><td>{badge}</td><td style="color:#888;font-size:12px">{ctrl["notes"]}</td></tr>\n'

    functions_html = ""
    for func, stats in report.get("by_function", {}).items():
        functions_html += f'<tr><td><strong>{func}</strong></td><td style="color:#00ff88">{stats["covered"]}</td><td style="color:#ffd600">{stats["partial"]}</td><td style="color:#ff2d55">{stats["not_covered"]}</td><td>{stats["score"]}</td></tr>\n'

    return f"""<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>Compliance Report - {report["framework"]}</title>
<link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;600;700&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
body{{background:#080808;color:#e0e0e0;font-family:'Space Mono',monospace;font-size:13px;padding:40px}}
h1{{font-family:'Rajdhani',sans-serif;font-size:36px;color:#00f0ff;letter-spacing:2px}}
h2{{font-family:'Rajdhani',sans-serif;font-size:24px;color:#fff;margin-top:40px}}
.score{{font-size:72px;font-weight:700;color:#00f0ff}}
table{{width:100%;border-collapse:collapse;margin-top:16px}}
th{{text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#555;padding:10px;border-bottom:1px solid #1a1a1a}}
td{{padding:10px;border-bottom:1px solid #1a1a1a;font-size:12px}}
.summary-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:24px 0}}
.summary-card{{background:#111;border:1px solid #1a1a1a;padding:20px;text-align:center}}
.summary-num{{font-family:'Rajdhani',sans-serif;font-size:36px;font-weight:700}}
.footer{{margin-top:60px;padding-top:20px;border-top:1px solid #1a1a1a;color:#555;font-size:11px;text-align:center}}
</style></head><body>
<h1>COMPLIANCE REPORT</h1>
<p style="color:#555">{report["framework"]} v{report["version"]} — Generated: {report["generated_at"]}</p>
<div class="score">{report["overall_score"]}</div>
<div class="summary-grid">
<div class="summary-card"><div class="summary-num" style="color:#00ff88">{report["summary"]["covered"]}</div><div>Covered</div></div>
<div class="summary-card"><div class="summary-num" style="color:#ffd600">{report["summary"]["partial"]}</div><div>Partial</div></div>
<div class="summary-card"><div class="summary-num" style="color:#ff2d55">{report["summary"]["not_covered"]}</div><div>Not Covered</div></div>
<div class="summary-card"><div class="summary-num" style="color:#555">{report["summary"]["not_applicable"]}</div><div>N/A</div></div>
</div>
<h2>Coverage by Function</h2>
<table><thead><tr><th>Function</th><th>Covered</th><th>Partial</th><th>Not Covered</th><th>Score</th></tr></thead>
<tbody>{functions_html}</tbody></table>
<h2>All Controls</h2>
<table><thead><tr><th>ID</th><th>Title</th><th>Component</th><th>Status</th><th>Evidence</th></tr></thead>
<tbody>{controls_html}</tbody></table>
<div class="footer">Hyperium Sovereign-OS v0.1.0 — Compliance Report — hyperiumia.com</div>
</body></html>"""
