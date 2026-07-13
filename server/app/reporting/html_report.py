from datetime import datetime, timezone


def _sc(s):
    if s >= 80: return "#00e87b"
    if s >= 60: return "#f59e0b"
    if s >= 40: return "#f97316"
    return "#ef4444"


def _si(s):
    return {
        "covered": "\u2705", "partial": "\u26a0\ufe0f",
        "not_covered": "\u274c", "not_applicable": "\u2796"
    }.get(s, "?")


def _normalize_fw(fw):
    if isinstance(fw, dict):
        return fw
    return {"name": str(fw) if fw else "Unknown", "source": "N/A"}


def _normalize_controls(raw):
    out = []
    for x in (raw or []):
        if isinstance(x, str):
            out.append({"id": x, "category": "-", "description": "-",
                        "status": "covered", "priority": "medium", "component": "-"})
        elif isinstance(x, dict):
            out.append(x)
    return out


def generate_framework_report(report, gaps=None):
    fw = _normalize_fw(report.get("framework", {}))
    controls = _normalize_controls(report.get("controls", []))
    score = report.get("overall_score", "0%")
    sv = float(str(score).replace("%", "")) if score else 0
    color = _sc(sv)

    rows = ""
    for x in controls:
        pc = {"critical": "#ef4444", "high": "#f97316",
              "medium": "#f59e0b", "low": "#22c55e"}.get(x.get("priority", "medium"), "#888")
        desc = (x.get("description", "") or "")[:80]
        rows += '<tr><td style="font-family:monospace;color:#4488ff">{}</td><td>{}</td><td>{}</td><td style="text-align:center">{}</td><td style="text-align:center"><span style="color:{};font-weight:600">{}</span></td><td style="font-family:monospace;font-size:11px">{}</td></tr>\n'.format(
            x.get("id", ""), x.get("category", ""), desc,
            _si(x.get("status", "")), pc, x.get("priority", "").upper(),
            x.get("component", "-"))

    gap_rows = ""
    if gaps and gaps.get("gaps"):
        for g in gaps["gaps"]:
            pc = {"critical": "#ef4444", "high": "#f97316",
                  "medium": "#f59e0b", "low": "#22c55e"}.get(g.get("priority", "medium"), "#888")
            gdesc = (g.get("description", "") or "")[:80]
            gap_rows += '<tr><td style="font-family:monospace;color:#4488ff">{}</td><td>{}</td><td><span style="color:{};font-weight:600">{}</span></td><td>{}</td></tr>\n'.format(
                g.get("control_id", ""), gdesc, pc,
                g.get("priority", "").upper(), g.get("recommendation", ""))

    gap_section = ""
    if gap_rows:
        gl = len(gaps.get("gaps", []))
        gap_section = '<section style="margin-top:40px"><h2 style="color:#f59e0b;border-bottom:1px solid #1e1e2e;padding-bottom:8px">Gap Analysis</h2><p style="color:#888;margin-bottom:16px">{} gaps identified</p><table><thead><tr><th>Control ID</th><th>Description</th><th>Priority</th><th>Recommendation</th></tr></thead><tbody>{}</tbody></table></section>'.format(gl, gap_rows)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cov = sum(1 for x in controls if x.get("status") == "covered")
    par = sum(1 for x in controls if x.get("status") == "partial")
    gn = len(gaps.get("gaps", [])) if gaps else 0
    fw_name = fw.get("name", "Unknown")
    fw_source = fw.get("source", "N/A")

    css = """*{margin:0;padding:0;box-sizing:border-box}body{background:#050508;color:#d0d0d8;font-family:'JetBrains Mono',monospace;font-size:13px;line-height:1.6;padding:40px}.c{max-width:1100px;margin:0 auto}.hdr{border:1px solid #1e1e2e;border-radius:8px;padding:40px;margin-bottom:32px;background:linear-gradient(135deg,#0a0a12,#0f0f1a);position:relative;overflow:hidden}.hdr::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,COLOR,#4488ff,COLOR)}.hdr h1{font-family:'Orbitron',sans-serif;font-size:28px;color:#fff;letter-spacing:4px;margin-bottom:4px}.hdr .sub{font-size:18px;color:COLOR;margin-bottom:8px}.hdr .meta{font-size:11px;color:#606070}.sc{display:flex;align-items:center;gap:40px;margin:32px 0;padding:32px;background:#0a0a12;border:1px solid #1e1e2e;border-radius:8px}.sq{width:140px;height:140px;border-radius:50%;border:4px solid COLOR;display:flex;flex-direction:column;align-items:center;justify-content:center;box-shadow:0 0 30px COLOR33;flex-shrink:0}.sq .v{font-family:'Orbitron',sans-serif;font-size:36px;font-weight:700;color:COLOR}.sq .l{font-size:10px;color:#888;text-transform:uppercase;letter-spacing:2px}table{width:100%;border-collapse:collapse;margin-top:16px}th{background:#0f0f1a;color:#888;font-size:10px;text-transform:uppercase;letter-spacing:1.5px;padding:12px 16px;text-align:left;border-bottom:1px solid #1e1e2e}td{padding:10px 16px;border-bottom:1px solid #0f0f16;font-size:12px}tr:hover td{background:#0a0a12}h2{font-family:'Orbitron',sans-serif;font-size:14px;letter-spacing:2px;text-transform:uppercase;color:#fff}.ft{margin-top:60px;padding-top:20px;border-top:1px solid #1e1e2e;font-size:10px;color:#404050;text-align:center}@media print{body{background:#fff;color:#000;padding:20px}}""".replace("COLOR", color)

    html = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">'
    html += '<title>Compliance Report -- {}</title>'.format(fw_name)
    html += '<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Orbitron:wght@400;700&display=swap" rel="stylesheet">'
    html += '<style>{}</style>'.format(css)
    html += '</head><body><div class="c">'
    html += '<div class="hdr"><h1>HYPERIUM SOVEREIGN-OS</h1>'
    html += '<div class="sub">Compliance Report -- {}</div>'.format(fw_name)
    html += '<div class="meta">Generated: {} | CONFIDENTIAL | v0.1.0</div></div>'.format(now)
    html += '<div class="sc"><div class="sq"><span class="v">{}</span><span class="l">Coverage</span></div>'.format(score)
    html += '<div><h3 style="color:#fff;margin-bottom:12px">Executive Summary</h3>'
    html += '<p style="color:#888;font-size:12px;line-height:1.8">Framework: {}<br>'.format(fw_name)
    html += 'Source: {}<br>Total Controls: {}<br>'.format(fw_source, len(controls))
    html += 'Covered: {} | Partial: {} | Gaps: {}</p></div></div>'.format(cov, par, gn)
    html += '<section><h2>Control Assessment</h2><table><thead><tr><th>Control ID</th>'
    html += '<th>Category</th><th>Description</th><th>Status</th><th>Priority</th>'
    html += '<th>Component</th></tr></thead><tbody>{}</tbody></table></section>'.format(rows)
    html += gap_section
    html += '<div class="ft">Hyperium Sovereign-OS v0.1.0 -- Confidential -- {}</div>'.format(now)
    html += '</div></body></html>'
    return html


def generate_executive_summary(summary):
    fws = summary.get("frameworks", [])
    cards = ""
    for fw in fws:
        cov = fw.get("covered", 0)
        total = cov + fw.get("not_covered", 0) + fw.get("partial", 0) + fw.get("not_applicable", 0)
        pct = (cov / total * 100) if total > 0 else 0
        cl = _sc(pct)
        cards += '<div style="background:#0a0a12;border:1px solid #1e1e2e;border-radius:8px;padding:20px;position:relative;overflow:hidden">'
        cards += '<div style="position:absolute;top:0;left:0;right:0;height:2px;background:{}"></div>'.format(cl)
        cards += '<div style="font-size:11px;color:#606070;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">{}</div>'.format(fw["name"])
        cards += '<div style="font-family:Orbitron,sans-serif;font-size:28px;color:{};margin-bottom:4px">{:.1f}%</div>'.format(cl, pct)
        cards += '<div style="font-size:11px;color:#888">{} of {} controls</div>'.format(cov, total)
        cards += '<div style="margin-top:12px;background:#050508;border-radius:4px;height:6px;overflow:hidden">'
        cards += '<div style="width:{:.1f}%;height:100%;background:{};border-radius:4px"></div></div></div>\n'.format(pct, cl)

    tc = sum(f.get("covered", 0) for f in fws)
    tg = sum(f.get("not_covered", 0) for f in fws)
    te = sum(f.get("covered", 0) + f.get("not_covered", 0) + f.get("partial", 0) for f in fws)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ver = summary.get("version", "0.1.0")

    css = """*{margin:0;padding:0;box-sizing:border-box}body{background:#050508;color:#d0d0d8;font-family:'JetBrains Mono',monospace;font-size:13px;padding:40px}.c{max-width:1100px;margin:0 auto}.hdr{text-align:center;padding:48px 40px;background:linear-gradient(135deg,#0a0a12,#0f0f1a);border:1px solid #1e1e2e;border-radius:8px;margin-bottom:40px;position:relative;overflow:hidden}.hdr::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,#00e87b,#4488ff,#00e87b)}.hdr h1{font-family:'Orbitron',sans-serif;font-size:32px;color:#fff;letter-spacing:6px;margin-bottom:8px}.hdr .sub{color:#00e87b;font-size:16px}.hdr .meta{color:#606070;font-size:11px}.t{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:32px}.tc{background:#0a0a12;border:1px solid #1e1e2e;border-radius:8px;padding:20px;text-align:center}.tc .v{font-family:'Orbitron',sans-serif;font-size:32px;color:#00e87b}.tc .l{font-size:10px;color:#606070;text-transform:uppercase;letter-spacing:1.5px;margin-top:4px}.g{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:16px;margin-top:24px}h2{font-family:'Orbitron',sans-serif;font-size:14px;letter-spacing:2px;text-transform:uppercase;color:#fff;margin-bottom:16px}.ft{margin-top:60px;padding-top:20px;border-top:1px solid #1e1e2e;font-size:10px;color:#404050;text-align:center}"""

    html = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
    html += '<meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Executive Summary</title>'
    html += '<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Orbitron:wght@400;700&display=swap" rel="stylesheet">'
    html += '<style>{}</style>'.format(css)
    html += '</head><body><div class="c">'
    html += '<div class="hdr"><h1>HYPERIUM SOVEREIGN-OS</h1>'
    html += '<div class="sub">Executive Compliance Summary</div>'
    html += '<div class="meta">{} -- All Frameworks -- v{}</div></div>'.format(now, ver)
    html += '<div class="t"><div class="tc"><div class="v">{}</div><div class="l">Frameworks</div></div>'.format(len(fws))
    html += '<div class="tc"><div class="v">{}</div><div class="l">Covered</div></div>'.format(tc)
    html += '<div class="tc"><div class="v">{}</div><div class="l">Gaps</div></div>'.format(tg)
    html += '<div class="tc"><div class="v">{}</div><div class="l">Total Controls</div></div></div>'.format(te)
    html += '<h2>Framework Coverage</h2><div class="g">{}</div>'.format(cards)
    html += '<div class="ft">Hyperium Sovereign-OS v{} -- Confidential -- {}</div>'.format(ver, now)
    html += '</div></body></html>'
    return html
