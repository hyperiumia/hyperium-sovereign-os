from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.models import Session as DBSession, SessionStatus, Alert, Workspace
from app.schemas import AgentEvent, AgentEventBatch
from app.core.evidence_vault import evidence_vault
from app.core.policy_engine import policy_engine
from app.core.risk_engine import risk_engine
import structlog

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/v1/events", tags=["events"])


async def _process_event(event: AgentEvent, db: AsyncSession) -> dict:
    stored_event = await evidence_vault.ingest_event(
        db=db, session_id=event.session_id, event_type=event.event_type,
        source_module=event.source_module, payload=event.payload,
        severity=event.severity.value, event_hash=event.event_hash,
        hmac_signature=event.hmac_signature,
    )

    context = {"event": {"severity": event.severity.value, "payload": event.payload}}

    if event.session_id:
        session_obj = await db.get(DBSession, event.session_id)
        if session_obj:
            data_volume = event.payload.get("data_bytes", 0)
            if data_volume:
                session_obj.data_volume_bytes = (session_obj.data_volume_bytes or 0) + data_volume
            risk_score = await risk_engine.compute_session_risk(db, session_obj)
            session_obj.risk_score = risk_score
            context["session"] = {
                "risk_score": risk_score,
                "data_volume_bytes": session_obj.data_volume_bytes,
                "status": session_obj.status.value,
            }
            context["user"] = {"role": "EMPLOYEE"}
            if session_obj.workspace_id:
                ws = await db.get(Workspace, session_obj.workspace_id)
                if ws:
                    context["workspace"] = {
                        "classification": ws.classification.value,
                        "allow_usb": ws.allow_usb,
                        "allow_network": ws.allow_network,
                        "is_air_gapped": ws.is_air_gapped,
                    }

    decisions = policy_engine.evaluate(event.event_type, context)
    actions_taken = []
    for decision in decisions:
        action = decision.policy.action
        if action in ("ALERT", "ALERT_AND_FREEZE"):
            db.add(Alert(
                event_id=stored_event.id, policy_id=decision.policy.id,
                severity=decision.severity, title=f"[{decision.severity.value}] {decision.policy.name}",
                description=decision.policy.description, action_taken=action,
            ))
            actions_taken.append("ALERT_CREATED")
        if action in ("FREEZE", "ALERT_AND_FREEZE") and event.session_id:
            s = await db.get(DBSession, event.session_id)
            if s and s.status == SessionStatus.ACTIVE:
                s.status = SessionStatus.FROZEN
                s.freeze_reason = f"Policy '{decision.policy.name}' triggered"
                actions_taken.append("SESSION_FROZEN")
        if action == "ISOLATE" and event.session_id:
            s = await db.get(DBSession, event.session_id)
            if s:
                s.status = SessionStatus.ISOLATED
                s.freeze_reason = f"ISOLATION: {decision.policy.name}"
                actions_taken.append("SESSION_ISOLATED")
        if action == "BLOCK":
            actions_taken.append("ACTION_BLOCKED")

    return {
        "status": "accepted",
        "event_id": stored_event.id,
        "merkle_epoch": stored_event.merkle_epoch,
        "actions_taken": actions_taken,
    }


@router.post("/ingest")
async def ingest_event(event: AgentEvent, db: AsyncSession = Depends(get_db)):
    try:
        return await _process_event(event, db)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/ingest/batch")
async def ingest_batch(batch: AgentEventBatch, db: AsyncSession = Depends(get_db)):
    results = []
    for event in batch.events:
        try:
            results.append(await _process_event(event, db))
        except ValueError as e:
            results.append({"status": "rejected", "error": str(e)})
        except Exception as e:
            results.append({"status": "error", "error": str(e)})
    return {"processed": len(results), "results": results}
