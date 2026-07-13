import pytest
from fastapi.testclient import TestClient
from app.main import app
client = TestClient(app)

class TestBreachEvaluate:
    def test_endpoint(self):
        r = client.get("/api/v1/compliance/breach/evaluate")
        assert r.status_code == 200
        assert isinstance(r.json(), dict)
    def test_has_data(self):
        r = client.get("/api/v1/compliance/breach/evaluate")
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
