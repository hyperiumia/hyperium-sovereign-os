import pytest


@pytest.mark.asyncio
class TestExecutive:
    async def test_html(self, client):
        r = await client.get("/api/v1/reports/executive")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert "SOVEREIGN-OS" in r.text

    async def test_has_frameworks(self, client):
        r = await client.get("/api/v1/reports/executive")
        assert "NIST" in r.text
        assert "ISO" in r.text


@pytest.mark.asyncio
class TestComplianceReport:
    async def test_nist(self, client):
        r = await client.get("/api/v1/reports/compliance/nist-csf-2.0")
        assert r.status_code == 200
        assert "NIST" in r.text

    async def test_iso(self, client):
        r = await client.get("/api/v1/reports/compliance/iso-27001")
        assert r.status_code == 200
        assert "ISO" in r.text

    async def test_has_controls(self, client):
        r = await client.get("/api/v1/reports/compliance/nist-csf-2.0")
        assert "Control Assessment" in r.text
        assert "NIST" in r.text

    async def test_404(self, client):
        r = await client.get("/api/v1/reports/compliance/nonexistent")
        assert r.status_code == 404

    async def test_soc2(self, client):
        r = await client.get("/api/v1/reports/compliance/soc2")
        assert r.status_code == 200
        assert "SOC" in r.text

    async def test_gdpr(self, client):
        r = await client.get("/api/v1/reports/compliance/gdpr")
        assert r.status_code == 200
        assert "GDPR" in r.text

    async def test_cmmc(self, client):
        r = await client.get("/api/v1/reports/compliance/cmmc")
        assert r.status_code == 200
        assert "CMMC" in r.text

    async def test_pci(self, client):
        r = await client.get("/api/v1/reports/compliance/pci-dss-4.0")
        assert r.status_code == 200
        assert "PCI" in r.text
