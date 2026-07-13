"""Breach Notification Engine — GDPR/LGPD compliant breach detection and notification."""
import hashlib
import json
from datetime import datetime, timezone, timedelta
import structlog

logger = structlog.get_logger("compliance.breach")

NOTIFICATION_DEADLINES = {
    "GDPR": {"hours": 72, "authority": "Supervisory Authority", "region": "EU"},
    "LGPD": {"hours": 72, "authority": "ANPD", "region": "Brazil"},
    "NIS2": {"hours": 24, "authority": "CSIRT/Authority", "region": "EU"},
    "HIPAA": {"days": 60, "authority": "HHS OCR", "region": "USA"},
    "CCPA": {"hours": None, "authority": "AG California", "region": "California"},
}


class BreachNotificationEngine:

    @staticmethod
    async def evaluate_breach(db, event_ids: list = None, hours: int = 24):
        from app.models import Event, Alert
        from sqlalchemy import select, and_, func
        from datetime import timedelta

        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        conditions = [Event.created_at >= cutoff, Event.severity.in_(["CRITICAL", "HIGH"])]
        query = select(Event).where(and_(*conditions)).order_by(Event.created_at.desc())
        result = await db.execute(query)
        events = result.scalars().all()

        breach_indicators = {
            "unauthorized_access": 0,
            "data_exfiltration": 0,
            "ransomware": 0,
            "log_tampering": 0,
            "mass_data_movement": 0,
        }

        for event in events:
            etype = (event.event_type or "").lower()
            if "unauthorized" in etype or "blocked" in etype:
                breach_indicators["unauthorized_access"] += 1
            if "usb" in etype or "transfer" in etype:
                breach_indicators["data_exfiltration"] += 1
            if "mass_encrypt" in etype or "ransomware" in etype:
                breach_indicators["ransomware"] += 1
            if "log_deletion" in etype:
                breach_indicators["log_tampering"] += 1
            if "data_volume" in etype:
                breach_indicators["mass_data_movement"] += 1

        severity_score = sum([
            breach_indicators["ransomware"] * 10,
            breach_indicators["data_exfiltration"] * 5,
            breach_indicators["log_tampering"] * 8,
            breach_indicators["unauthorized_access"] * 3,
            breach_indicators["mass_data_movement"] * 4,
        ])

        is_breach = severity_score >= 10
        breach_severity = "CRITICAL" if severity_score >= 50 else "HIGH" if severity_score >= 25 else "MEDIUM" if severity_score >= 10 else "LOW"

        applicable_regulations = []
        if is_breach:
            for reg, details in NOTIFICATION_DEADLINES.items():
                deadline_hours = details.get("hours") or (details.get("days", 0) * 24)
                applicable_regulations.append({
                    "regulation": reg,
                    "authority": details["authority"],
                    "region": details["region"],
                    "notification_deadline_hours": deadline_hours,
                    "deadline": (datetime.now(timezone.utc) + timedelta(hours=deadline_hours)).isoformat() if deadline_hours else None,
                    "status": "PENDING",
                })

        breach = {
            "breach_id": hashlib.sha256(
                json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "score": severity_score}).encode()
            ).hexdigest()[:16],
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "is_breach": is_breach,
            "severity": breach_severity,
            "severity_score": severity_score,
            "indicators": breach_indicators,
            "related_events": len(events),
            "applicable_regulations": applicable_regulations,
            "recommended_actions": BreachNotificationEngine._get_recommendations(breach_indicators),
            "notification_status": {
                "internal_notified": True,
                "authority_notified": False,
                "data_subjects_notified": False,
            },
        }

        logger.info("breach.evaluation.completed",
                     is_breach=is_breach,
                     severity=breach_severity,
                     score=severity_score)
        return breach

    @staticmethod
    def _get_recommendations(indicators):
        recs = []
        if indicators["ransomware"] > 0:
            recs.append("CRITICAL: Isolate affected systems immediately")
            recs.append("Preserve all evidence before remediation")
            recs.append("Engage incident response team")
        if indicators["data_exfiltration"] > 0:
            recs.append("Review all external connections in timeframe")
            recs.append("Identify data that may have been exfiltrated")
            recs.append("Consider DLP controls for affected workspaces")
        if indicators["log_tampering"] > 0:
            recs.append("Verify Evidence Vault integrity (Merkle tree)")
            recs.append("Logs are preserved in immutable Evidence Vault")
            recs.append("Check for additional tampering indicators")
        if indicators["unauthorized_access"] > 0:
            recs.append("Review access grants and revoke suspicious permissions")
            recs.append("Force password reset for affected accounts")
        if not recs:
            recs.append("Continue monitoring")
        return recs

    @staticmethod
    def generate_notification_report(breach, regulation: str):
        reg_info = None
        for reg in breach.get("applicable_regulations", []):
            if reg["regulation"].upper() == regulation.upper():
                reg_info = reg
                break

        if not reg_info:
            return {"error": f"Regulation {regulation} not applicable to this breach"}

        report = {
            "report_type": "breach_notification",
            "regulation": regulation,
            "breach_id": breach["breach_id"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "breach_summary": {
                "detected_at": breach["detected_at"],
                "severity": breach["severity"],
                "indicators": breach["indicators"],
                "related_events": breach["related_events"],
            },
            "notification_details": {
                "authority": reg_info["authority"],
                "region": reg_info["region"],
                "deadline": reg_info["deadline"],
                "hours_remaining": reg_info["notification_deadline_hours"],
            },
            "template": {
                "nature_of_breach": "Automated detection by Sovereign-OS",
                "categories_affected": "See indicators",
                "approximate_data_subjects": "Determined by forensic analysis",
                "dpo_contact": "[TO BE COMPLETED]",
                "measures_taken": breach["recommended_actions"],
            },
        }
        return report
