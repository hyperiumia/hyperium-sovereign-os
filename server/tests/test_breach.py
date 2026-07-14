import pytest


@pytest.mark.asyncio
class TestBreachEvaluate:
    async def test_endpoint(self, client):
        r = await client.get("/api/v1/compliance/breach/evaluate")
        assert r.status_code == 200
        assert isinstance(r.json(), dict)

    async def test_has_data(self, client):
        r = await client.get("/api/v1/compliance/breach/evaluate")
        assert len(r.json()) > 0


class TestBreachNotification:
    def test_engine_import(self):
        from app.compliance.breach_notification import BreachNotificationEngine
        engine = BreachNotificationEngine()
        assert engine is not None

    def test_has_methods(self):
        from app.compliance.breach_notification import BreachNotificationEngine
        engine = BreachNotificationEngine()
        assert callable(getattr(engine, "evaluate_breach", None))


class TestRFC3161:
    def test_import(self):
        from app.compliance.rfc3161 import TimestampAuthority
        assert TimestampAuthority is not None

    def test_instance(self):
        from app.compliance.rfc3161 import timestamp_authority
        assert timestamp_authority is not None
