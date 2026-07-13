"""Forensic Timeline Builder — Constructs chronological event timelines for investigations."""
import hashlib
import json
from datetime import datetime, timezone
from typing import Optional
import structlog

logger = structlog.get_logger("forensics.timeline")


class ForensicTimeline:

    @staticmethod
    async def build_timeline(db, case_id: Optional[str] = None,
                             user_id: Optional[str] = None,
                             device_id: Optional[str] = None,
                             start_time: Optional[str] = None,
                             end_time: Optional[str] = None,
                             severity_filter: Optional[list] = None):
        from app.models import Event, EvidenceItem, Alert
        from sqlalchemy import select, and_

        conditions = []
        if user_id:
            conditions.append(Event.payload["user_id"].astext == user_id)
        if device_id:
            conditions.append(Event.device_id == device_id)
        if start_time:
            conditions.append(Event.created_at >= datetime.fromisoformat(start_time))
        if end_time:
            conditions.append(Event.created_at <= datetime.fromisoformat(end_time))

        query = select(Event).order_by(Event.created_at.asc())
        if conditions:
            query = query.where(and_(*conditions))

        result = await db.execute(query)
        events = result.scalars().all()

        timeline_entries = []
        phases = []
        current_phase = None

        for event in events:
            entry = {
                "timestamp": event.created_at.isoformat() if event.created_at else None,
                "event_id": str(event.id),
                "event_type": event.event_type,
                "severity": event.severity,
                "source_module": event.source_module,
                "payload": event.payload if isinstance(event.payload, dict) else {},
                "hash": event.event_hash,
                "merkle_leaf": event.merkle_leaf_index,
                "epoch": event.epoch_number,
            }

            severity = event.severity or "LOW"
            if severity in ("CRITICAL", "HIGH"):
                entry["classification"] = "THREAT"
                entry["color"] = "red" if severity == "CRITICAL" else "orange"
            elif severity == "MEDIUM":
                entry["classification"] = "SUSPICIOUS"
                entry["color"] = "yellow"
            else:
                entry["classification"] = "NORMAL"
                entry["color"] = "green"

            timeline_entries.append(entry)

            phase_type = ForensicTimeline._classify_phase(event.event_type)
            if phase_type != current_phase:
                current_phase = phase_type
                phases.append({
                    "phase": phase_type,
                    "started_at": entry["timestamp"],
                    "trigger_event": str(event.id),
                    "severity": severity,
                })

        total_events = len(timeline_entries)
        threat_events = len([e for e in timeline_entries if e["classification"] == "THREAT"])
        suspicious_events = len([e for e in timeline_entries if e["classification"] == "SUSPICIOUS"])

        timeline = {
            "case_id": case_id or hashlib.sha256(
                json.dumps({"generated": datetime.now(timezone.utc).isoformat()}).encode()
            ).hexdigest()[:16],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "filters": {
                "user_id": user_id,
                "device_id": device_id,
                "start_time": start_time,
                "end_time": end_time,
                "severity_filter": severity_filter,
            },
            "summary": {
                "total_events": total_events,
                "threat_events": threat_events,
                "suspicious_events": suspicious_events,
                "normal_events": total_events - threat_events - suspicious_events,
                "timeline_duration": ForensicTimeline._calculate_duration(timeline_entries),
                "phases_detected": len(phases),
            },
            "phases": phases,
            "entries": timeline_entries,
        }

        timeline["integrity_hash"] = hashlib.sha256(
            json.dumps(timeline["entries"], sort_keys=True).encode()
        ).hexdigest()

        logger.info("forensic.timeline.built",
                     case_id=timeline["case_id"],
                     total_events=total_events,
                     threats=threat_events)
        return timeline

    @staticmethod
    def _classify_phase(event_type):
        if not event_type:
            return "UNKNOWN"
        if "usb" in event_type.lower():
            return "USB_ACTIVITY"
        if "network" in event_type.lower():
            return "NETWORK_ACTIVITY"
        if "filesystem" in event_type.lower():
            return "FILESYSTEM_ACTIVITY"
        if "session" in event_type.lower():
            return "SESSION_ACTIVITY"
        return "OTHER"

    @staticmethod
    def _calculate_duration(entries):
        if len(entries) < 2:
            return "0s"
        try:
            first = datetime.fromisoformat(entries[0]["timestamp"])
            last = datetime.fromisoformat(entries[-1]["timestamp"])
            delta = last - first
            total_seconds = int(delta.total_seconds())
            if total_seconds < 60:
                return f"{total_seconds}s"
            if total_seconds < 3600:
                return f"{total_seconds // 60}m {total_seconds % 60}s"
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            return f"{hours}h {minutes}m"
        except Exception:
            return "unknown"
