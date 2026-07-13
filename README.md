# Hyperium Sovereign-OS

> Corporate Sovereignty and Anti-Espionage Security Platform

[![CI](https://github.com/hyperiumia/hyperium-sovereign-os/actions/workflows/ci.yml/badge.svg)](https://github.com/hyperiumia/hyperium-sovereign-os/actions)
[![Python](https://img.shields.io/badge/python-3.11%20|%203.12-blue)](https://python.org)
[![Version](https://img.shields.io/badge/version-1.0.0-green)](https://github.com/hyperiumia/hyperium-sovereign-os/releases/tag/v1.0.0)

Sovereign-OS provides cryptographic evidence integrity, policy-based threat detection,
multi-framework compliance mapping, and forensic investigation capabilities for
enterprise security operations.

## Architecture

+-----------------------------------------------------+
| REST API (FastAPI) |
| 30+ endpoints | Auth | Rate Limiting |
+------------+----------+--------+--------------------+
| Evidence | Policy | Risk | Compliance |
| Vault | Engine | Engine | Mapper (7 FW) |
+------------+----------+--------+--------------------+
| Forensic | Breach | SIEM | Reporting |
| Engine | Notific. | Export | & Dashboard |
+------------+----------+--------+--------------------+
| Cryptographic Core |
| SHA-256 | HMAC-SHA256 | Merkle Tree | Ed25519 |
+-----------------------------------------------------+
| Storage (SQLAlchemy Async) |
| PostgreSQL / SQLite |
+-----------------------------------------------------+

text

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/hyperiumia/hyperium-sovereign-os.git
cd hyperium-sovereign-os
docker-compose up -d

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/hyperiumia/hyperium-sovereign-os.git
cd hyperium-sovereign-os
docker-compose up -d

API at http://localhost:8000. Dashboard at http://localhost:8000/dashboard.


Local

bash
cd server
pip install -r requirements.txt
uvicorn app.main:app --reload
cd server
pip install -r requirements.txt
uvicorn app.main:app --reload

Features

Evidence Vault
Cryptographic evidence integrity with tamper detection.


Component	Algorithm	Purpose
Event Hashing	SHA-256	Key-order independent content hashing
Integrity	HMAC-SHA256	Signed event verification
Chain	Merkle Tree	Append-only proof generation
Epochs	Ed25519	Signed epoch boundaries

Policy Engine
10 comparison operators with wildcard trigger matching and YAML import.
Operators: eq, neq, gt, gte, lt, lte, contains, in_list, in_csv, matches_regex


Risk Engine
Multifactor scoring (0.0 - 1.0) based on event volume, user history, and session behavior.


Compliance Mapper
7 frameworks with gap analysis, priority ranking, and evidence package generation.


Framework	Controls	Coverage
NIST CSF 2.0	106	Govern, Identify, Protect, Detect, Respond, Recover
ISO 27001:2022	93	Organizational, People, Physical, Technological
SOC 2 Type II	56	Security, Availability, Processing Integrity
GDPR	15	Data Protection, Privacy Rights
CMMC 2.0	17	Access Control, Audit, Incident Response
PCI DSS 4.0	12	Network, Configuration, Data Protection
HIPAA	18	Administrative, Physical, Technical

Forensic Engine
Chronological timeline construction with phase classification
Taint analysis for data flow tracking
Evidence packaging (JSON / ZIP export)
Document watermarking with HMAC signatures
SIEM export formats: JSON, CEF, LEEF, Syslog

Breach Notification
RFC 3161 trusted timestamps with 72-hour SLA tracking and notification templates.


Auth and Security
API key authentication with Bearer token support
Sliding window rate limiting (configurable RPM)
HMAC event integrity verification
Tamper detection on all evidence events

API Documentation

Interactive API docs at http://localhost:8000/docs (Swagger UI).


Key Endpoints

Method	Path	Description
GET	/health	Health check with dependency status
GET	/metrics	Platform metrics (JSON)
GET	/dashboard	SOC Dashboard
POST	/api/v1/events	Ingest security event
POST	/api/v1/events/batch	Batch event ingestion
GET	/api/v1/evidence/verify/{event_id}	Verify event integrity
GET	/api/v1/evidence/stats	Evidence vault statistics
GET	/api/v1/compliance/summary	All frameworks summary
GET	/api/v1/compliance/evaluate/{fw}	Evaluate specific framework
GET	/api/v1/compliance/gaps/{fw}	Gap analysis
GET	/api/v1/reports/executive	Executive HTML report
GET	/api/v1/reports/compliance/{fw}	Framework HTML report
GET	/api/v1/forensics/timeline	Forensic timeline
GET	/api/v1/forensics/taint	Taint analysis
POST	/api/v1/forensics/watermark	Generate document watermark
GET	/api/v1/forensics/siem/formats	Available SIEM formats
GET	/api/v1/auth/status	Authentication status
POST	/api/v1/auth/keys	Create API key
GET	/api/v1/alerts	List security alerts

Configuration

Environment variables (.env file or system):


Variable	Default	Description
SOVEREIGN_AUTH_ENABLED	false	Enable API key authentication
SOVEREIGN_RATE_LIMIT	0	Requests per minute per IP (0=disabled)
SOVEREIGN_LOG_LEVEL	INFO	Logging level
SOVEREIGN_LOG_FILE	(empty)	Log file path (empty=stdout only)

Security

Cryptographic Stack
SHA-256: Deterministic, key-order independent event hashing
HMAC-SHA256: Symmetric integrity verification with shared secret
Merkle Tree: Append-only hash tree with proof generation and verification
Ed25519: Asymmetric epoch signing for non-repudiation
RFC 3161: Trusted timestamp authority for legal-grade evidence

Threat Model
Sovereign-OS assumes the internal network may be compromised. All events are
cryptographically signed and verified independently. Evidence integrity does not
depend on network security or operator trust.


Testing

bash
cd server
pip install -r requirements.txt
python -m pytest tests/ -v --cov=app --cov-report=term-missing
cd server
pip install -r requirements.txt
python -m pytest tests/ -v --cov=app --cov-report=term-missing

128 tests with 74% code coverage covering crypto, policy engine, risk engine,
compliance mapper, evidence vault, forensics, auth, reporting, rate limiting,
and metrics.


Suite	Tests	Coverage
test_crypto.py	18	SHA-256, HMAC, Merkle tree, Ed25519
test_policy_engine.py	18	10 operators, wildcards, conditions, priorities
test_evidence_vault.py	9	Ingestion, tamper rejection, epochs, verification
test_api.py	16	Health, CRUD, ingestion, batch, verification, alerts
test_risk_engine.py	4	Scoring, volume, history, bounds
test_compliance.py	20	7 frameworks, engine, gaps, evidence, export
test_auth.py	11	API keys, middleware, Bearer, exempt paths
test_reports.py	10	Executive report, framework reports, HTML generation
test_forensics.py	10	Watermark, timeline, taint, SIEM, packaging
test_breach.py	5	Breach evaluation, notification engine, RFC 3161
test_rate_limiter.py	4	Disabled, enabled, 429, exempt paths
test_metrics.py	7	Platform, version, uptime, config, vault, policies

Deployment

Production Checklist
1.Set SOVEREIGN_AUTH_ENABLED=true and generate API keys
2.Set SOVEREIGN_RATE_LIMIT=120 (or appropriate value)
3.Configure SOVEREIGN_LOG_FILE for persistent logging
4.Use PostgreSQL instead of SQLite for the database
5.Deploy behind a TLS-terminating reverse proxy (nginx, Caddy)
6.Set up monitoring on /health and /metrics endpoints

Docker Production
bash
docker-compose up -d
docker-compose up -d

systemd (Agent)
bash
sudo cp agent/target/release/sovereign-agent /usr/local/bin/
sudo cp agent/config/agent.toml /etc/sovereign-agent/
sudo cp agent/systemd/sovereign-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sovereign-agent
sudo systemctl start sovereign-agent
sudo cp agent/target/release/sovereign-agent /usr/local/bin/
sudo cp agent/config/agent.toml /etc/sovereign-agent/
sudo cp agent/systemd/sovereign-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sovereign-agent
sudo systemctl start sovereign-agent

Demo

bash
cd server
python scripts/demo_attack.py
cd server
python scripts/demo_attack.py

Roadmap

All phases complete as of v1.0.0:


Phase 1 - MVP: Evidence Vault, Policy Engine, Risk Engine, REST API
Phase 2 - Forensics: Watermarking, Taint Analysis, Timeline, Packaging
Phase 3 - Compliance: RFC 3161, SIEM Export, 7 Regulatory Frameworks
v1.0.0 - Production: Auth, Rate Limiting, Dashboard, Reports, Docker, CI/CD

License

Proprietary - Hyperium IA. All rights reserved.


Contact: 
security@hyperiumia.com



Developed by Hyperium IA - Applied AI for Corporate Cybersecurity.


Hyperium Sovereign-OS - Operational Corporate Sovereignty.


www.hyperiumia.com

