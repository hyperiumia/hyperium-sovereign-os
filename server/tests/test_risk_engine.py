"""
Tests para el Risk Engine:
- Score base con sesión normal
- Score elevado por volumen
- Score elevado por eventos de seguridad
- Score en horario laboral vs fuera de horario
"""
import pytest
import pytest_asyncio
from app.core.risk_engine import RiskEngine
from app.models import Session, User, SessionStatus


@pytest.mark.asyncio
class TestRiskEngine:
    async def test_baseline_score_is_low(self, db):
        """Una sesión normal con poco tráfico tiene score bajo."""
        user = User(username="testuser", email="test@test.com", role="EMPLOYEE", risk_score=0.0)
        device = None
        db.add(user)
        await db.flush()

        session = Session(
            user_id=user.id, device_id="dev-1", status=SessionStatus.ACTIVE,
            risk_score=0.0, data_volume_bytes=1024,
        )
        db.add(session)
        await db.flush()

        engine = RiskEngine()
        score = await engine.compute_session_risk(db, session)

        assert 0.0 <= score <= 1.0
        assert score < 0.5  # Should be low for normal activity

    async def test_high_volume_increases_risk(self, db):
        """Mucho tráfico de datos aumenta el score."""
        user = User(username="heavyuser", email="heavy@test.com", role="EMPLOYEE", risk_score=0.0)
        db.add(user)
        await db.flush()

        session = Session(
            user_id=user.id, device_id="dev-1", status=SessionStatus.ACTIVE,
            risk_score=0.0, data_volume_bytes=500 * 1024 * 1024,  # 500MB
        )
        db.add(session)
        await db.flush()

        engine = RiskEngine()
        score = await engine.compute_session_risk(db, session)

        assert score > 0.2  # Volume alone should push it up

    async def test_user_history_affects_score(self, db):
        """Un usuario con historial riesgoso contribuye al score."""
        user = User(username="riskyuser", email="risky@test.com", role="EMPLOYEE", risk_score=0.8)
        db.add(user)
        await db.flush()

        session = Session(
            user_id=user.id, device_id="dev-1", status=SessionStatus.ACTIVE,
            risk_score=0.0, data_volume_bytes=1024,
        )
        db.add(session)
        await db.flush()

        engine = RiskEngine()
        score = await engine.compute_session_risk(db, session)

        assert score > 0.1  # User history weight is 0.15 * 0.8 = 0.12

    async def test_score_bounded_0_to_1(self, db):
        """El score siempre está entre 0.0 y 1.0."""
        user = User(username="boundtest", email="bound@test.com", role="EMPLOYEE", risk_score=1.0)
        db.add(user)
        await db.flush()

        session = Session(
            user_id=user.id, device_id="dev-1", status=SessionStatus.ACTIVE,
            risk_score=0.0, data_volume_bytes=10 * 1024 * 1024 * 1024,  # 10GB
        )
        db.add(session)
        await db.flush()

        engine = RiskEngine()
        score = await engine.compute_session_risk(db, session)

        assert 0.0 <= score <= 1.0
