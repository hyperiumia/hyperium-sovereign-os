import pytest
from fastapi.testclient import TestClient
from app.main import app
client = TestClient(app)

class TestExecutive:
    def test_html(self):
        r = client.get("/api/v1/reports/executive")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert "SOVEREIGN-OS" in r.text
    def test_has_frameworks(self):
        r = client.get("/api/v1/reports/executive")
        assert "NIST" in r.text
        assert "ISO" in r.text

class TestComplianceReport:
    def test_nist(self):
        r = client.get("/api/v1/reports/compliance/nist-csf-2.0")
        assert r.status_code == 200
        assert "NIST" in r.text
    def test_iso(self):
        r = client.get("/api/v1/reports/compliance/iso-27001")
        assert r.status_code == 200
        assert "ISO" in r.text
    def test_has_controls(self):
        r = client.get("/api/v1/reports/compliance/nist-csf-2.0")
        assert "Control Assessment" in r.text
        assert "NIST" in r.text
    def test_404(self):
        r = client.get("/api/v1/reports/compliance/nonexistent")
        assert r.status_code == 404

class TestHTMLModule:
    def test_framework_report(self):
        from app.reporting.html_report import generate_framework_report
        mock = {"framework": {"name": "Test", "source": "t"}, "overall_score": "75%", "controls": [
            {"id": "C1", "category": "X", "description": "d", "status": "covered", "priority": "high", "component": "c"},
        ]}
        html = generate_framework_report(mock, {"gaps": []})
        assert "Test" in html and "75%" in html and "C1" in html
    def test_executive_summary(self):
        from app.reporting.html_report import generate_executive_summary
        mock = {"platform": "X", "version": "0.1.0", "frameworks": [
            {"name": "FW1", "covered": 8, "not_covered": 2, "partial": 1, "not_applicable": 0},
        ], "totals": {"total_covered": 8, "total_gaps": 2, "controls_evaluated": 11}}
        html = generate_executive_summary(mock)
        assert "SOVEREIGN-OS" in html and "FW1" in html
