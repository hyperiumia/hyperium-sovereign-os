"""Tests for rate limiting middleware."""
import os
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from app.main import app


class TestRateLimiterDisabled:
    def test_passes_when_disabled(self):
        c = TestClient(app)
        r = c.get("/health")
        assert r.status_code == 200

    def test_no_headers_when_disabled(self):
        c = TestClient(app)
        r = c.get("/health")
        assert "X-RateLimit-Limit" not in r.headers


class TestRateLimiterEnabled:
    def test_headers_present(self):
        with patch.dict(os.environ, {"SOVEREIGN_RATE_LIMIT": "1000"}):
            c = TestClient(app)
            r = c.get("/api/v1/compliance/summary")
            assert r.status_code == 200
            assert "X-RateLimit-Limit" in r.headers
            assert r.headers["X-RateLimit-Limit"] == "1000"
            assert "X-RateLimit-Remaining" in r.headers

    def test_exempt_paths_not_limited(self):
        with patch.dict(os.environ, {"SOVEREIGN_RATE_LIMIT": "1"}):
            c = TestClient(app)
            r1 = c.get("/health")
            r2 = c.get("/health")
            assert r1.status_code == 200
            assert r2.status_code == 200
