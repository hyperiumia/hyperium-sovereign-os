"""Forensic Package Exporter — Generates complete forensic evidence packages."""
import hashlib
import json
import zipfile
import io
from datetime import datetime, timezone
import structlog

logger = structlog.get_logger("forensics.package")


class ForensicPackageExporter:

    @staticmethod
    async def export_package(db, case_id: str, format: str = "json"):
        from app.models import Event, Alert, EvidenceItem, MerkleEpoch
        from sqlalchemy import select
        from app.core.evidence_vault import evidence_vault

        events_result = await db.execute(select(Event).order_by(Event.created_at.asc()))
        events = events_result.scalars().all()

        alerts_result = await db.execute(select(Alert).order_by(Alert.created_at.asc()))
        alerts = alerts_result.scalars().all()

        epochs_result = await db.execute(select(MerkleEpoch).order_by(MerkleEpoch.epoch_number.asc()))
        epochs = epochs_result.scalars().all()

        events_data = []
        for e in events:
            events_data.append({
                "id": str(e.id),
                "event_type": e.event_type,
                "source_module": e.source_module,
                "payload": e.payload if isinstance(e.payload, dict) else {},
                "severity": e.severity,
                "event_hash": e.event_hash,
                "hmac_signature": e.hmac_signature,
                "merkle_leaf_index": e.merkle_leaf_index,
                "epoch_number": getattr(e, "epoch_number", None),
                "created_at": e.created_at.isoformat() if e.created_at else None,
            })

        alerts_data = []
        for a in alerts:
            alerts_data.append({
                "id": str(a.id),
                "event_type": a.event_type,
                "severity": a.severity,
                "message": a.message,
                "status": a.status,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            })

        epochs_data = []
        for ep in epochs:
            verification = evidence_vault.verify_epoch(ep.epoch_number)
            epochs_data.append({
                "epoch_number": ep.epoch_number,
                "merkle_root": ep.merkle_root,
                "signature": ep.signature,
                "leaf_count": ep.leaf_count,
                "closed_at": ep.closed_at.isoformat() if ep.closed_at else None,
                "verification": verification,
            })

        package = {
            "package_type": "sovereign_os_forensic_package",
            "package_version": "1.0",
            "case_id": case_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "platform": "Hyperium Sovereign-OS v0.1.0",
            "summary": {
                "total_events": len(events_data),
                "total_alerts": len(alerts_data),
                "total_epochs": len(epochs_data),
                "severity_breakdown": ForensicPackageExporter._severity_breakdown(events_data),
            },
            "chain_of_custody": {
                "events_signed": all(e.get("hmac_signature") for e in events_data),
                "merkle_integrity": all(ep["verification"]["valid"] for ep in epochs_data),
                "epochs_signed": all(ep.get("signature") for ep in epochs_data),
            },
            "evidence": {
                "events": events_data,
                "alerts": alerts_data,
                "epochs": epochs_data,
            },
        }

        content = json.dumps(package, indent=2, default=str)
        package["package_hash"] = hashlib.sha256(content.encode()).hexdigest()

        logger.info("forensic.package.exported",
                     case_id=case_id,
                     events=len(events_data),
                     alerts=len(alerts_data))
        return package

    @staticmethod
    async def export_zip(db, case_id: str):
        package = await ForensicPackageExporter.export_package(db, case_id)

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("manifest.json", json.dumps({
                "case_id": case_id,
                "generated_at": package["generated_at"],
                "platform": package["platform"],
                "summary": package["summary"],
                "chain_of_custody": package["chain_of_custody"],
                "package_hash": package["package_hash"],
            }, indent=2))

            zf.writestr("evidence/events.json",
                        json.dumps(package["evidence"]["events"], indent=2, default=str))
            zf.writestr("evidence/alerts.json",
                        json.dumps(package["evidence"]["alerts"], indent=2, default=str))
            zf.writestr("evidence/epochs.json",
                        json.dumps(package["evidence"]["epochs"], indent=2, default=str))
            zf.writestr("package.json", json.dumps(package, indent=2, default=str))

        buffer.seek(0)
        return buffer.getvalue()

    @staticmethod
    def _severity_breakdown(events):
        breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for e in events:
            sev = e.get("severity", "LOW")
            if sev in breakdown:
                breakdown[sev] += 1
        return breakdown
