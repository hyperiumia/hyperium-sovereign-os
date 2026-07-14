<p align="center">
  <img src="https://img.shields.io/badge/HYPERIUM-Sovereign--OS-00e87b?style=for-the-badge&labelColor=050508&color=00e87b" alt="Hyperium Sovereign-OS">
</p>

<p align="center">
  <strong>Corporate Sovereignty & Anti-Espionage Security Platform</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-00e87b?style=flat-square&labelColor=0d0d0d" alt="Version">
  <img src="https://img.shields.io/badge/python-3.11%20|%203.12-4488ff?style=flat-square&labelColor=0d0d0d" alt="Python">
  <img src="https://img.shields.io/badge/tests-128%20passed-00e87b?style=flat-square&labelColor=0d0d0d" alt="Tests">
  <img src="https://img.shields.io/badge/coverage-74%25-f59e0b?style=flat-square&labelColor=0d0d0d" alt="Coverage">
  <img src="https://img.shields.io/badge/license-Proprietary-ef4444?style=flat-square&labelColor=0d0d0d" alt="License">
  <img src="https://img.shields.io/badge/compliance-7%20frameworks-4488ff?style=flat-square&labelColor=0d0d0d" alt="Compliance">
</p>

<p align="center">
  <a href="#architecture">Architecture</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#features">Features</a> &bull;
  <a href="#api">API</a> &bull;
  <a href="#deployment">Deployment</a> &bull;
  <a href="#security">Security</a> &bull;
  <a href="#testing">Testing</a>
</p>

---

## What is Sovereign-OS?

Sovereign-OS is an enterprise security platform that provides **cryptographic evidence integrity**, **policy-driven threat detection**, **multi-framework compliance mapping**, and **forensic investigation capabilities** for Security Operations Centers (SOC).

Built for organizations that cannot afford to trust their network perimeter, Sovereign-OS cryptographically signs every security event, maintains append-only evidence chains, and maps operational controls against 7 international regulatory frameworks.

**Key differentiators:**

- Every event is SHA-256 hashed, HMAC-signed, and anchored in a Merkle tree
- Evidence integrity is mathematically verifiable, not just audited
- Compliance assessment covers NIST CSF 2.0, ISO 27001, SOC 2, GDPR, CMMC 2.0, PCI DSS 4.0, and HIPAA
- Forensic engine reconstructs attack timelines with phase classification and taint analysis
- Zero-trust architecture: assumes the internal network is compromised

---

## Architecture

                    +-------------------------------------+
                    |         REST API (FastAPI)           |
                    |   30+ endpoints | Auth | Rate        |
                    |   Limiting | Metrics | Dashboard     |
                    +--------+--------------+-------------+
                             |              |
        +--------------------+--------------+--------------------+
        |                    |              |                    |
+--------+---------+ +-------+-------+ +----+--------+ +--------+----------+
| Evidence Vault | | Policy Engine | | Risk Engine | | Compliance Mapper |
| | | | | | | |
| SHA-256 hashing | | 10 operators | | Multifactor | | NIST CSF 2.0 |
| HMAC-SHA256 | | Wildcards | | scoring | | ISO 27001:2022 |
| Merkle Tree | | YAML import | | 0.0 - 1.0 | | SOC 2 Type II |
| Ed25519 epochs | | 7 policies | | Volume, | | GDPR |
| Tamper detection | | | | history, | | CMMC 2.0 |
| | | | | behavior | | PCI DSS 4.0 |
+--------+----------+ +-------+-------+ +------+------+ | HIPAA |
| | | +--------+----------+
| +--------+----------------+--------+ |
| | Core Cryptography | |
| | SHA-256 | HMAC | Merkle | Ed25519| |
| +----------------+------------------+ |
| | |
+--------+------------------------+-----------------------------+----------+
| |
| +--------------+ +--------------+ +-------------+ |
| | Forensic | | Breach | | SIEM | |
| | Engine | | Notification | | Export | |
| | | | | | | |
| | Timeline | | RFC 3161 | | JSON | |
| | Taint | | 72h SLA | | CEF | |
| | Watermark | | Templates | | LEEF | |
| | Packaging | | | | Syslog | |
| +--------------+ +--------------+ +-------------+ |
| |
+--------------------------------------------------------------------------+
|
+----------------+----------------+
| Storage (SQLAlchemy Async) |
| PostgreSQL / SQLite |
+---------------------------------+

text

---

## Quick Start

### Docker (Recommended)

```bash
git clone https://github.com/hyperiumia/hyperium-sovereign-os.git
cd hyperium-sovereign-os
docker-compose up -d

---

## Quick Start

### Docker (Recommended)

```bash
git clone https://github.com/hyperiumia/hyperium-sovereign-os.git
cd hyperium-sovereign-os
docker-compose up -d

API available at http://localhost:8000. Interactive docs at http://localhost:8000/docs.


Local Development

bash
cd server
pip install -r requirements.txt
uvicorn app.main:app --reload
cd server
pip install -r requirements.txt
uvicorn app.main:app --reload

Verify Installation

bash
curl http://localhost:8000/health | python3 -m json.tool
curl http://localhost:8000/health | python3 -m json.tool

json
{
    "status": "healthy",
    "version": "1.0.0",
    "uptime_seconds": 1.2,
    "active_sessions": 0,
    "merkle_current_epoch": 0,
    "signing_key_id": "1fc0e6ec1f1da6ae"
}
{
    "status": "healthy",
    "version": "1.0.0",
    "uptime_seconds": 1.2,
    "active_sessions": 0,
    "merkle_current_epoch": 0,
    "signing_key_id": "1fc0e6ec1f1da6ae"
}


Features

Evidence Vault

Cryptographic evidence integrity with mathematical verification. Every security event is hashed, signed, and anchored in an append-only Merkle tree.


Component	Algorithm	Purpose
Event Hashing	SHA-256	Deterministic, key-order independent content hashing
Integrity	HMAC-SHA256	Symmetric signed verification with shared secret
Chain	Merkle Tree	Append-only proof generation and verification
Epochs	Ed25519	Asymmetric epoch signing for non-repudiation
Timestamps	RFC 3161	Trusted timestamp authority for legal-grade evidence

Policy Engine

Declarative threat detection with 10 comparison operators, wildcard trigger matching, and YAML-based policy import.


Supported operators:eq, neq, gt, gte, lt, lte, contains, in_list, in_csv, matches_regex


Trigger matching: Exact match, prefix wildcards (usb.*), suffix wildcards (*.exfiltration), full wildcards (*)


Risk Engine

Multifactor risk scoring (0.0 - 1.0) combining event volume analysis, user behavioral history, and session anomaly detection. Configurable alert and freeze thresholds.


Compliance Mapper

7 international regulatory frameworks with automated gap analysis, priority-ranked findings, and exportable evidence packages.


Framework	Controls	Domains
NIST CSF 2.0	106	Govern, Identify, Protect, Detect, Respond, Recover
ISO 27001:2022	93	Organizational, People, Physical, Technological
SOC 2 Type II	56	Security, Availability, Processing Integrity
GDPR	15	Data Protection, Privacy Rights, Consent Management
CMMC 2.0	17	Access Control, Audit, Incident Response
PCI DSS 4.0	12	Network Security, Data Protection, Secure Development
HIPAA	18	Administrative, Physical, Technical Safeguards

Forensic Engine

Complete forensic investigation toolkit for Security Operations Centers.


Timeline Construction — Chronological event reconstruction with automatic phase classification (USB Activity, Network Activity, Filesystem Activity, Session Activity)
Taint Analysis — Data flow tracking to identify information exfiltration paths
Evidence Packaging — Exportable forensic packages in JSON and ZIP formats with chain-of-custody verification
Document Watermarking — HMAC-signed document watermarks for leak attribution
SIEM Export — Native export in JSON, CEF (ArcSight), LEEF (QRadar), and Syslog (RFC 5424)

Breach Notification

Automated breach response with RFC 3161 trusted timestamps, 72-hour SLA tracking, notification templates, and regulatory compliance mapping.


SOC Dashboard

Real-time Security Operations Center dashboard with:


Executive compliance score across all frameworks
Gap analysis with priority-ranked findings
Framework coverage visualization (bar chart + distribution)
Security alerts feed
Forensic timeline display
Configurable API key management


API

Authentication

Sovereign-OS supports API key authentication (disabled by default, enable with SOVEREIGN_AUTH_ENABLED=true).


bash
# Create an API key
curl -X POST http://localhost:8000/api/v1/auth/keys \
  -H "Content-Type: application/json" \
  -d '{"name": "ops-team"}'

# Use the key
curl http://localhost:8000/api/v1/compliance/summary \
  -H "X-API-Key: sk_sov_..."
# Create an API key
curl -X POST http://localhost:8000/api/v1/auth/keys \
  -H "Content-Type: application/json" \
  -d '{"name": "ops-team"}'

# Use the key
curl http://localhost:8000/api/v1/compliance/summary \
  -H "X-API-Key: sk_sov_..."

Bearer token authentication is also supported: Authorization: Bearer sk_sov_...


Key Endpoints

Method	Endpoint	Description
GET	/health	Health check with dependency status
GET	/metrics	Platform metrics and configuration
GET	/dashboard	SOC Dashboard (HTML)
Events		
POST	/api/v1/events	Ingest security event
POST	/api/v1/events/batch	Batch event ingestion
Evidence		
GET	/api/v1/evidence/verify/{id}	Verify event cryptographic integrity
GET	/api/v1/evidence/stats	Evidence vault statistics
Compliance		
GET	/api/v1/compliance/summary	All frameworks executive summary
GET	/api/v1/compliance/evaluate/{fw}	Evaluate specific framework
GET	/api/v1/compliance/gaps/{fw}	Gap analysis with recommendations
GET	/api/v1/compliance/controls/{fw}	Framework control listing
Reports		
GET	/api/v1/reports/executive	Executive HTML report (all frameworks)
GET	/api/v1/reports/compliance/{fw}	Per-framework HTML report
Forensics		
GET	/api/v1/forensics/timeline	Forensic timeline construction
GET	/api/v1/forensics/taint	Taint analysis report
POST	/api/v1/forensics/watermark	Generate document watermark
GET	/api/v1/forensics/watermark/verify	Verify document watermark
GET	/api/v1/forensics/package/{id}	Export forensic evidence package
GET	/api/v1/forensics/siem/formats	Available SIEM export formats
GET	/api/v1/forensics/siem/export	Export events for SIEM ingestion
Auth		
GET	/api/v1/auth/status	Authentication configuration status
GET	/api/v1/auth/keys	List API keys
POST	/api/v1/auth/keys	Create API key
DELETE	/api/v1/auth/keys/{id}	Revoke API key

Example: Ingest Event

bash
curl -X POST http://localhost:8000/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "usb.device_inserted",
    "source_module": "endpoint_agent",
    "device_id": "WS-FINANCE-042",
    "severity": "HIGH",
    "payload": {
      "user_id": "jsmith",
      "device_serial": "USB_SANDISK_4C530001260818116245",
      "vendor": "SanDisk",
      "capacity_gb": 64,
      "mount_point": "/media/usb0",
      "department": "Finance"
    }
  }'
curl -X POST http://localhost:8000/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "usb.device_inserted",
    "source_module": "endpoint_agent",
    "device_id": "WS-FINANCE-042",
    "severity": "HIGH",
    "payload": {
      "user_id": "jsmith",
      "device_serial": "USB_SANDISK_4C530001260818116245",
      "vendor": "SanDisk",
      "capacity_gb": 64,
      "mount_point": "/media/usb0",
      "department": "Finance"
    }
  }'

Response:


json
{
    "event_id": "evt_3f8a9c2d1e",
    "status": "accepted",
    "hash": "a1b2c3d4e5f6...",
    "hmac_verified": true,
    "risk_score": 0.72,
    "matched_policies": ["POL-USB-HIGH-RISK"],
    "alerts_generated": 1
}
{
    "event_id": "evt_3f8a9c2d1e",
    "status": "accepted",
    "hash": "a1b2c3d4e5f6...",
    "hmac_verified": true,
    "risk_score": 0.72,
    "matched_policies": ["POL-USB-HIGH-RISK"],
    "alerts_generated": 1
}

Example: Compliance Evaluation

bash
curl http://localhost:8000/api/v1/compliance/evaluate/nist-csf-2.0 | python3 -m json.tool
curl http://localhost:8000/api/v1/compliance/evaluate/nist-csf-2.0 | python3 -m json.tool

json
{
    "framework": "NIST CSF 2.0",
    "overall_score": "65.2%",
    "total_controls": 106,
    "covered": 45,
    "partial": 19,
    "not_covered": 12,
    "not_applicable": 1,
    "function_breakdown": {
        "Govern": {"covered": 10, "total": 16},
        "Identify": {"covered": 8, "total": 13},
        "Protect": {"covered": 12, "total": 20},
        "Detect": {"covered": 7, "total": 9},
        "Respond": {"covered": 5, "total": 7},
        "Recover": {"covered": 3, "total": 4}
    }
}
{
    "framework": "NIST CSF 2.0",
    "overall_score": "65.2%",
    "total_controls": 106,
    "covered": 45,
    "partial": 19,
    "not_covered": 12,
    "not_applicable": 1,
    "function_breakdown": {
        "Govern": {"covered": 10, "total": 16},
        "Identify": {"covered": 8, "total": 13},
        "Protect": {"covered": 12, "total": 20},
        "Detect": {"covered": 7, "total": 9},
        "Respond": {"covered": 5, "total": 7},
        "Recover": {"covered": 3, "total": 4}
    }
}


Deployment

Production Stack

Sovereign-OS ships with a production-ready Docker stack including PostgreSQL, nginx reverse proxy, and Let's Encrypt TLS.


bash
# 1. Clone and configure
git clone https://github.com/hyperiumia/hyperium-sovereign-os.git
cd hyperium-sovereign-os
cp .env.production .env

# 2. Edit .env — set strong passwords
# POSTGRES_PASSWORD=<random-64-hex>
# AGENT_HMAC_SECRET=<random-64-hex>
# DOMAIN=your.domain.com

# 3. Deploy
chmod +x deploy.sh
./deploy.sh

# 4. Configure TLS (after DNS is pointing)
chmod +x setup-tls.sh
./setup-tls.sh
# 1. Clone and configure
git clone https://github.com/hyperiumia/hyperium-sovereign-os.git
cd hyperium-sovereign-os
cp .env.production .env

# 2. Edit .env — set strong passwords
# POSTGRES_PASSWORD=<random-64-hex>
# AGENT_HMAC_SECRET=<random-64-hex>
# DOMAIN=your.domain.com

# 3. Deploy
chmod +x deploy.sh
./deploy.sh

# 4. Configure TLS (after DNS is pointing)
chmod +x setup-tls.sh
./setup-tls.sh

Environment Variables

Variable	Default	Description
SOS_DATABASE_URL	sqlite+aiosqlite:///./sovereign_os.db	Database connection string
SOS_AGENT_HMAC_SECRET	(default)	HMAC shared secret for event signing
SOVEREIGN_AUTH_ENABLED	false	Enable API key authentication
SOVEREIGN_RATE_LIMIT	0	Requests per minute per IP (0 = disabled)
SOVEREIGN_LOG_LEVEL	INFO	Logging level
SOVEREIGN_LOG_FILE	(empty)	Log file path (empty = stdout only)

Production Checklist

1.Set SOVEREIGN_AUTH_ENABLED=true and generate API keys
2.Set SOVEREIGN_RATE_LIMIT=120 (or appropriate value)
3.Configure SOVEREIGN_LOG_FILE for persistent logging
4.Use PostgreSQL: set SOS_DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/sovereign_os
5.Deploy behind TLS-terminating reverse proxy (included in docker-compose.prod.yml)
6.Monitor /health and /metrics endpoints
7.Set strong SOS_AGENT_HMAC_SECRET (64+ random hex characters)

Docker Compose Files

File	Purpose
docker-compose.yml	Development / quick start (SQLite)
docker-compose.prod.yml	Production (PostgreSQL + nginx + TLS + Certbot)


Security

Cryptographic Stack

Algorithm	Role	Why
SHA-256	Event hashing	Deterministic, key-order independent, industry standard
HMAC-SHA256	Integrity verification	Symmetric signing with shared secret, tamper detection
Merkle Tree	Evidence chain	Append-only proof structure, efficient verification
Ed25519	Epoch signing	Asymmetric non-repudiation, fast verification
RFC 3161	Trusted timestamps	Legal-grade temporal proof

Threat Model

Sovereign-OS is designed for environments where the internal network cannot be trusted.


Assumptions:

Attackers may have network-level access
Operators may be adversarial (insider threat)
Evidence must be verifiable without trusting any single component

Mitigations:

Every event is independently hashable and verifiable
HMAC signatures detect tampering without revealing the secret
Merkle proofs allow third-party verification of evidence integrity
Ed25519 epoch signatures provide non-repudiation
API authentication prevents unauthorized access to sensitive endpoints


Testing

bash
cd server
pip install -r requirements.txt
python -m pytest tests/ -v --cov=app --cov-report=term-missing
cd server
pip install -r requirements.txt
python -m pytest tests/ -v --cov=app --cov-report=term-missing

Test Suite

Suite	Tests	What it covers
test_crypto.py	18	SHA-256, HMAC, Merkle tree, Ed25519 key management
test_policy_engine.py	18	10 operators, wildcards, conditions, priorities
test_evidence_vault.py	9	Ingestion, tamper rejection, epoch management, verification
test_api.py	16	Health, workspaces, CRUD, ingestion, batch, verification, alerts
test_risk_engine.py	4	Scoring, volume impact, history, bounds
test_compliance.py	20	7 frameworks, engine evaluation, gaps, evidence, export
test_auth.py	11	API keys, middleware, Bearer tokens, exempt paths
test_reports.py	10	Executive report, framework reports, HTML generation
test_forensics.py	10	Watermark, timeline, taint, SIEM, packaging
test_breach.py	5	Breach evaluation, notification engine, RFC 3161
test_rate_limiter.py	4	Disabled mode, enabled mode, 429 responses, exempt paths
test_metrics.py	7	Platform info, version, uptime, config, vault, policies
Total	128	74% code coverage


Technology Stack

Layer	Technology
Framework	FastAPI (async)
ORM	SQLAlchemy 2.0 (async)
Database	PostgreSQL 16 (production) / SQLite (development)
Cryptography	cryptography (Ed25519, HMAC) + hashlib (SHA-256)
Validation	Pydantic v2
Logging	structlog (structured JSON)
Reverse Proxy	nginx 1.27
TLS	Let's Encrypt (Certbot)
Container	Docker + Docker Compose
CI/CD	GitHub Actions (Python 3.11 + 3.12)


Roadmap

All phases complete as of v1.0.0.


Phase 1 — MVP: Evidence Vault, Policy Engine, Risk Engine, REST API
Phase 2 — Forensics: Watermarking, Taint Analysis, Timeline, Packaging
Phase 3 — Compliance: RFC 3161, SIEM Export, 7 Regulatory Frameworks
v1.0.0 — Production: Auth, Rate Limiting, Dashboard, Reports, Docker, CI/CD

Planned for v1.1:

WebSocket alerts (real-time push to dashboard)
Multi-tenant workspace isolation
EDR integration (CrowdStrike, Microsoft Sentinel)
PDF report export
Prometheus /metrics endpoint


About

Hyperium Sovereign-OS is developed by Hyperium IA — Applied AI for Corporate Cybersecurity.


Built for organizations that require mathematical certainty over their security posture, not just audit logs.



www.hyperiumia.com




Copyright © 2026 Hyperium IA. All rights reserved.


