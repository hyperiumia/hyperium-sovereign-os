"""Taint Analysis — Tracks data flow through the organization to detect exfiltration paths."""
import hashlib
import json
from datetime import datetime, timezone
from typing import Optional
import structlog

logger = structlog.get_logger("forensics.taint")


class TaintAnalyzer:

    @staticmethod
    async def analyze_data_flow(db, user_id: Optional[str] = None,
                                document_id: Optional[str] = None,
                                workspace_id: Optional[str] = None,
                                hours: int = 24):
        from app.models import Event
        from sqlalchemy import select, and_, func
        from datetime import timedelta

        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        conditions = [Event.created_at >= cutoff]
        if user_id:
            conditions.append(Event.payload["user_id"].astext == user_id)
        if document_id:
            conditions.append(Event.payload["document_id"].astext == document_id)

        query = select(Event).where(and_(*conditions)).order_by(Event.created_at.asc())
        result = await db.execute(query)
        events = result.scalars().all()

        data_movements = []
        tainted_paths = []
        risk_zones = {}

        for event in events:
            payload = event.payload if isinstance(event.payload, dict) else {}
            movement = TaintAnalyzer._extract_movement(event.event_type, payload)
            if movement:
                movement["event_id"] = str(event.id)
                movement["timestamp"] = event.created_at.isoformat() if event.created_at else None
                movement["severity"] = event.severity
                data_movements.append(movement)

                zone = movement.get("destination_zone", "INTERNAL")
                if zone not in risk_zones:
                    risk_zones[zone] = {"count": 0, "data_types": set()}
                risk_zones[zone]["count"] += 1
                if movement.get("data_type"):
                    risk_zones[zone]["data_types"].add(movement["data_type"])

        exfiltration_paths = TaintAnalyzer._detect_exfiltration(data_movements)

        for zone in risk_zones:
            risk_zones[zone]["data_types"] = list(risk_zones[zone]["data_types"])

        taint_map = {
            "analysis_id": hashlib.sha256(
                json.dumps({"ts": datetime.now(timezone.utc).isoformat()}).encode()
            ).hexdigest()[:16],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "time_window_hours": hours,
            "filters": {
                "user_id": user_id,
                "document_id": document_id,
                "workspace_id": workspace_id,
            },
            "summary": {
                "total_movements": len(data_movements),
                "exfiltration_paths_detected": len(exfiltration_paths),
                "risk_zones_affected": len(risk_zones),
                "risk_level": "HIGH" if exfiltration_paths else "LOW",
            },
            "risk_zones": risk_zones,
            "data_movements": data_movements,
            "exfiltration_paths": exfiltration_paths,
        }

        logger.info("taint.analysis.completed",
                     movements=len(data_movements),
                     exfiltration_paths=len(exfiltration_paths))
        return taint_map

    @staticmethod
    def _extract_movement(event_type, payload):
        if not event_type:
            return None

        movement = {
            "event_type": event_type,
            "data_type": None,
            "source_zone": "INTERNAL",
            "destination_zone": "INTERNAL",
        }

        if "usb" in event_type.lower():
            movement["data_type"] = "USB_TRANSFER"
            movement["destination_zone"] = "USB_EXTERNAL"
            movement["risk"] = "HIGH"
        elif "network" in event_type.lower() and "connection" in event_type.lower():
            movement["data_type"] = "NETWORK_TRANSFER"
            dest_ip = payload.get("destination_ip", "")
            if dest_ip.startswith("10.") or dest_ip.startswith("192.168.") or dest_ip.startswith("172."):
                movement["destination_zone"] = "INTERNAL"
                movement["risk"] = "LOW"
            else:
                movement["destination_zone"] = "EXTERNAL"
                movement["risk"] = "MEDIUM"
        elif "filesystem" in event_type.lower():
            movement["data_type"] = "FILE_OPERATION"
            movement["destination_zone"] = "LOCAL"
            movement["risk"] = "LOW"
            if "mass_encrypt" in event_type.lower():
                movement["risk"] = "CRITICAL"
                movement["data_type"] = "RANSOMWARE"
        elif "session" in event_type.lower():
            movement["data_type"] = "SESSION_CHANGE"
            movement["risk"] = "LOW"

        return movement if movement["data_type"] else None

    @staticmethod
    def _detect_exfiltration(movements):
        paths = []
        usb_events = [m for m in movements if m.get("destination_zone") == "USB_EXTERNAL"]
        external_events = [m for m in movements if m.get("destination_zone") == "EXTERNAL"]

        if usb_events:
            paths.append({
                "path_type": "USB_EXFILTRATION",
                "severity": "HIGH",
                "description": f"{len(usb_events)} USB transfer(s) detected",
                "events": [m["event_id"] for m in usb_events],
                "recommendation": "Block USB in confidential workspaces",
            })

        if len(external_events) > 10:
            paths.append({
                "path_type": "NETWORK_EXFILTRATION",
                "severity": "HIGH",
                "description": f"{len(external_events)} external connections detected — possible data exfiltration",
                "events": [m["event_id"] for m in external_events[:20]],
                "recommendation": "Review external connection destinations and data volume",
            })

        ransomware = [m for m in movements if m.get("data_type") == "RANSOMWARE"]
        if ransomware:
            paths.append({
                "path_type": "RANSOMWARE_ATTACK",
                "severity": "CRITICAL",
                "description": "Ransomware patterns detected — mass file encryption",
                "events": [m["event_id"] for m in ransomware],
                "recommendation": "ISOLATE immediately, preserve evidence",
            })

        return paths
