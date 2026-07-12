from datetime import datetime, timezone
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import Event, Session, User
import structlog

logger = structlog.get_logger(__name__)

WEIGHTS = {
    "volume_spike": 0.30,
    "security_events": 0.25,
    "off_hours": 0.10,
    "classification": 0.20,
    "user_history": 0.15,
}


class RiskEngine:
    def __init__(self):
        self._baseline_volume: dict[str, float] = {}

    async def compute_session_risk(self, db: AsyncSession, session: Session) -> float:
        scores = {}
        baseline = self._baseline_volume.get(session.user_id, 10 * 1024 * 1024)
        current_volume = session.data_volume_bytes or 0
        scores["volume_spike"] = min(current_volume / max(baseline, 1), 5.0) / 5.0

        result = await db.execute(
            select(func.count(Event.id))
            .where(Event.session_id == session.id)
            .where(Event.severity.in_(["HIGH", "CRITICAL"]))
        )
        security_count = result.scalar() or 0
        scores["security_events"] = min(security_count / 10.0, 1.0)

        now = datetime.now(timezone.utc)
        is_off_hours = now.hour >= 20 or now.hour < 6 or now.weekday() >= 5
        scores["off_hours"] = 1.0 if is_off_hours else 0.0
        scores["classification"] = 0.5

        user_result = await db.execute(select(User).where(User.id == session.user_id))
        user = user_result.scalar_one_or_none()
        scores["user_history"] = (user.risk_score or 0.0) if user else 0.0

        final_score = sum(scores.get(f, 0.0) * w for f, w in WEIGHTS.items())
        final_score = min(max(final_score, 0.0), 1.0)
        return final_score


risk_engine = RiskEngine()
