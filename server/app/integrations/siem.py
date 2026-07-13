"""SIEM Integration — Exports events in CEF, LEEF, and JSON formats for SIEM ingestion."""
import json
from datetime import datetime, timezone
import structlog

logger = structlog.get_logger("integrations.siem")

CEF_SEVERITY_MAP = {
    "CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 2, "INFO": 1,
}


class SIEMExporter:

    @staticmethod
    def to_cef(event):
        severity = CEF_SEVERITY_MAP.get(event.get("severity", "LOW"), 1)
        event_type = event.get("event_type", "unknown")
        payload = event.get("payload", {})
        event_id = event.get("id", "unknown")

        extensions = []
        extensions.append(f"eventId={event_id}")
        extensions.append(f"rt={event.get('created_at', datetime.now(timezone.utc).isoformat())}")
        extensions.append(f"severity={severity}")
        for key, value in payload.items():
            clean_key = str(key).replace(" ", "_").replace(".", "_")
            extensions.append(f"{clean_key}={value}")

        cef = f"CEF:0|Hyperium|Sovereign-OS|0.1.0|{event_type}|{event_type}|{severity}|"
        cef += " ".join(extensions)
        return cef

    @staticmethod
    def to_leef(event):
        severity = CEF_SEVERITY_MAP.get(event.get("severity", "LOW"), 1)
        event_type = event.get("event_type", "unknown")
        payload = event.get("payload", {})

        attrs = []
        attrs.append(f"devTime={event.get('created_at', '')}")
        attrs.append(f"severity={severity}")
        attrs.append(f"eventId={event.get('id', '')}")
        for key, value in payload.items():
            attrs.append(f"{key}={value}")

        leef = f"LEEF:2.0|Hyperium|Sovereign-OS|0.1.0|{event_type}|"
        leef += "\t".join(attrs)
        return leef

    @staticmethod
    def to_syslog(event):
        severity = CEF_SEVERITY_MAP.get(event.get("severity", "LOW"), 1)
        facility = 16
        priority = facility * 8 + severity
        timestamp = event.get("created_at", datetime.now(timezone.utc).isoformat())

        msg = f"<{priority}>{timestamp} sovereign-os: "
        msg += f"type={event.get('event_type', 'unknown')} "
        msg += f"severity={event.get('severity', 'LOW')} "
        msg += f"source={event.get('source_module', 'unknown')}"

        payload = event.get("payload", {})
        for key, value in payload.items():
            msg += f" {key}={value}"
        return msg

    @staticmethod
    def format_events(events, format_type="json"):
        formatted = []
        for event in events:
            event_dict = event if isinstance(event, dict) else {
                "id": str(event.id),
                "event_type": event.event_type,
                "source_module": event.source_module,
                "payload": event.payload if isinstance(event.payload, dict) else {},
                "severity": event.severity,
                "created_at": event.created_at.isoformat() if event.created_at else None,
            }

            if format_type == "cef":
                formatted.append(SIEMExporter.to_cef(event_dict))
            elif format_type == "leef":
                formatted.append(SIEMExporter.to_leef(event_dict))
            elif format_type == "syslog":
                formatted.append(SIEMExporter.to_syslog(event_dict))
            else:
                formatted.append(event_dict)

        if format_type in ("cef", "leef", "syslog"):
            return "\n".join(formatted)
        return formatted

    @staticmethod
    def get_supported_formats():
        return {
            "formats": [
                {"name": "json", "description": "Standard JSON array of events", "mime": "application/json"},
                {"name": "cef", "description": "Common Event Format (Arcsight)", "mime": "text/plain"},
                {"name": "leef", "description": "Log Event Extended Format (QRadar)", "mime": "text/plain"},
                {"name": "syslog", "description": "Syslog (RFC 5424)", "mime": "text/plain"},
            ]
        }
