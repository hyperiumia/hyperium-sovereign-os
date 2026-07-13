<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.0-blue.svg" alt="version">
  <img src="https://img.shields.io/badge/python-3.12+-green.svg" alt="python">
  <img src="https://img.shields.io/badge/rust-1.70+-orange.svg" alt="rust">
  <img src="https://img.shields.io/badge/license-Proprietary-red.svg" alt="license">
  <img src="https://img.shields.io/badge/tests-94%2F94-brightgreen.svg" alt="tests">
  <img src="https://img.shields.io/badge/compliance-NIST%20CSF%202.0%20%2B%20ISO%2027001-blueviolet.svg" alt="compliance">
</p>

---

# Hyperium Sovereign-OS

## Sistema de Soberanía Corporativa y Anti-Espionaje

**Sovereign-OS** es una plataforma de contención, detección, evidencia y gobernanza diseñada para proteger los activos más críticos de una corporación: código fuente, propiedad intelectual, secretos industriales y documentos estratégicos.

No es un firewall. No es un EDR. Es una capa de soberanía que se superpone a la infraestructura existente y garantiza tres cosas:

1. **Aislamiento** — Los datos críticos viven en entornos controlados donde nadie puede moverlos sin autorización explícita.
2. **Detección** — Cada intento de exfiltración, comportamiento anómalo o manipulación de datos se detecta en tiempo real.
3. **Evidencia** — Cada evento se firma criptográficamente y se almacena en un Merkle tree inmutable, creando una cadena de custodia con valor legal.

---

## Arquitectura

| Pilar | Módulo | Función |
|---|---|---|
| **Soberanía del Dato** | Agent + Policy Engine | Control absoluto sobre quién y qué procesos acceden a datos críticos |
| **Soberanía Operacional** | Monitores + Risk Engine | Blindaje contra exfiltración, insider threat y sabotaje |
| **Soberanía Probatoria** | Evidence Vault + Merkle Tree | Evidencia inmutable con valor legal para tribunales y reguladores |

---

## Componentes

### Servidor (Python 3.12 + FastAPI)

| Componente | Descripción |
|---|---|
| **Evidence Vault** | Hash SHA-256, firma HMAC-SHA256, Merkle tree. Epochs firmados con Ed25519. |
| **Policy Engine** | 10 operadores, wildcards, prioridades, condiciones AND. Carga desde YAML. |
| **Risk Engine** | Scoring multifactor: volumen, seguridad, horario, workspace, historial. |
| **Compliance Mapper** | NIST CSF 2.0 (75 controles) + ISO 27001:2022 (40+ controles). Gap analysis y export. |
| **REST API** | 22+ endpoints: ingesta, verificación, workspaces, alertas, compliance. |
| **14 Entidades** | User, Device, Session, Workspace, Asset, Policy, Event, Alert, EvidenceItem, ForensicCase, AccessGrant, Revocation, MerkleEpoch. |

### Agent (Rust)

| Monitor | Método | Detecta |
|---|---|---|
| **USB** | Polling /sys/bus/usb | Dispositivos USB, clasificación |
| **Network** | Parsing /proc/net/tcp | Conexiones externas, puertos C2 |
| **Filesystem** | inotify non-blocking | Creación/eliminación, ransomware, log deletion |
| **Session** | who + env | Cambios de usuario |

### Enforcement

| Acción | Trigger | Efecto |
|---|---|---|
| **FREEZE** | Risk alto, transferencia masiva | Bloqueo de pantalla, kill procesos |
| **ISOLATE** | Ransomware, borrado de logs | iptables DROP salvo servidor |
| **BLOCK** | USB en workspace confidencial | Bloqueo de acción específica |

### Resiliencia

| Característica | Implementación |
|---|---|
| **Cola offline** | JSONL local. Se envían al reconectar. |
| **Retry backoff** | Exponencial hasta 30s. |
| **Batch sending** | Hasta 50 eventos por request. |
| **Health checks** | Cada 30s. |

---

## Criptografía

Cada evento que llega al servidor:

1. Se **hashea** con SHA-256 (hash canónico del payload JSON).
2. Se **verifica** el HMAC-SHA256 enviado por el agent (autenticidad).
3. Se **agrega** como hoja del Merkle tree del epoch actual.
4. Cada 100 eventos, el epoch se **cierra**: raíz Merkle firmada con Ed25519.
5. La raíz firmada es un checkpoint inmutable: cualquier manipulación es detectable.

---

## Compliance Mapper

Motor de compliance que mapea automáticamente la cobertura de controles contra frameworks regulatorios internacionales.

### Frameworks soportados

| Framework | Controles | Score | Estado |
|---|---|---|---|
| **NIST CSF 2.0** | 75 controles (6 funciones) | >40% | Operacional |
| **ISO 27001:2022** | 40+ controles (4 temas) | >30% | Operacional |

### NIST CSF 2.0 — Funciones cubiertas

| Función | Descripción | Componente |
|---|---|---|
| **Govern (GV)** | Gobernanza y estrategia | Workspace classification, Policy Engine, Risk Engine |
| **Identify (ID)** | Activos y riesgos | Device Monitor, Risk Engine |
| **Protect (PR)** | Protección de datos | Evidence Vault, Session Monitor, Access Grants |
| **Detect (DE)** | Monitoreo continuo | 4 monitores, Risk Engine, Alert System |
| **Respond (RS)** | Respuesta a incidentes | Enforcement (FREEZE/ISOLATE/BLOCK) |
| **Recover (RC)** | Recuperación | Planeado para Fase 3 |

### ISO 27001:2022 — Temas cubiertos

| Tema | Controles | Estado |
|---|---|---|
| **A.5 Organizational** | 24 controles | Mayoría cubiertos |
| **A.6 People** | 4 controles | Parcial |
| **A.7 Physical** | 3 controles | USB cubre A.7.10 |
| **A.8 Technological** | 16 controles | Mayoría cubiertos |

### Capacidades

- **Gap Analysis** — Controles no cubiertos, priorizado HIGH/MEDIUM
- **Scoring** — Por función y global
- **Evidence Package** — Exportable para auditores
- **HTML Export** — Reporte visual descargable

### Endpoints de compliance

```
curl http://localhost:8000/api/v1/compliance/summary
curl http://localhost:8000/api/v1/compliance/frameworks
curl http://localhost:8000/api/v1/compliance/report/nist-csf-2.0
curl http://localhost:8000/api/v1/compliance/gaps/iso-27001
curl http://localhost:8000/api/v1/compliance/evidence/nist-csf-2.0
curl http://localhost:8000/api/v1/compliance/export/nist-csf-2.0?format=html > report.html
```

### Próximos frameworks

| Prioridad | Framework | Región |
|---|---|---|
| 1 | SOC 2 Type II | USA |
| 2 | GDPR | Unión Europea |
| 3 | CMMC 2.0 | USA DoD |
| 4 | PCI DSS 4.0 | Global |
| 5 | HIPAA | USA Salud |
| 6 | LGPD | Brasil |
| 7 | NIS2 | UE |
| 8 | DORA | UE Finanzas |

---

## Políticas

### Operadores soportados

| Operador | Descripción |
|---|---|
| `eq` / `neq` | Igualdad / Desigualdad |
| `gt` / `gte` / `lt` / `lte` | Comparaciones numéricas |
| `contains` | Substring |
| `in` | Membership en lista |
| `matches` | Regex |

### Políticas por defecto

| Política | Trigger | Acción | Prioridad |
|---|---|---|---|
| isolate-ransomware-signal | `filesystem.mass_encrypt` | ISOLATE | 0 |
| isolate-log-deletion | `filesystem.log_deletion_attempt` | ISOLATE | 0 |
| freeze-high-risk-session | risk >= 0.85 | FREEZE | 1 |
| block-airgap-network | network.* (air-gapped) | BLOCK | 2 |
| freeze-large-transfer | session.data_volume > 500MB | ALERT_AND_FREEZE | 5 |
| block-usb-confidential | usb.* (confidencial) | BLOCK | 10 |
| alert-usb-any-workspace | usb.* | LOG | 200 |

---

## Quick Start

### Requisitos

- Python 3.12+
- Rust 1.70+ (solo para compilar el agent)
- Linux (el agent usa /proc, /sys e inotify)

### Servidor

```bash
git clone https://github.com/hyperiumia/hyperium-sovereign-os.git
cd hyperium-sovereign-os/server
pip install -r requirements.txt
uvicorn app.main:app --port 8000
curl http://localhost:8000/health
```

### Agent

```bash
cd hyperium-sovereign-os/agent
cargo build --release
RUST_LOG=info ./target/release/sovereign-agent
```

### Compliance

```bash
curl http://localhost:8000/api/v1/compliance/summary
curl http://localhost:8000/api/v1/compliance/export/nist-csf-2.0?format=html > nist-report.html
```

### Demo de ataque

```bash
cd hyperium-sovereign-os/server
python scripts/demo_attack.py
```

---

## Tests

```bash
cd hyperium-sovereign-os/server
python -m pytest tests/ -v
```

**94 tests** passing:

| Suite | Tests | Cobertura |
|---|---|---|
| test_crypto.py | 18 | SHA-256, HMAC, Merkle tree, Ed25519 |
| test_policy_engine.py | 18 | 10 operadores, wildcards, condiciones, prioridades |
| test_evidence_vault.py | 9 | Ingesta, rechazo de manipulación, epochs, verificación |
| test_api.py | 16 | Health, CRUD, ingesta, batch, verificación, alertas |
| test_risk_engine.py | 4 | Scoring, volumen, historial, bounds |
| test_compliance.py | 20 | NIST CSF 2.0, ISO 27001, engine, gaps, evidence, export |

---

## Demos interactivas

| Demo | Descripción |
|---|---|
| [Landing Page](https://htmlpreview.github.io/?https://github.com/hyperiumia/hyperium-sovereign-os/blob/main/docs/demo-1-landing.html) | Product page con tríada de soberanía y features |
| [Security Dashboard](https://htmlpreview.github.io/?https://github.com/hyperiumia/hyperium-sovereign-os/blob/main/docs/demo-2-dashboard.html) | SOC con event feed en vivo, monitores, risk gauge |
| [Evidence Vault](https://htmlpreview.github.io/?https://github.com/hyperiumia/hyperium-sovereign-os/blob/main/docs/demo-3-evidence.html) | Merkle tree visual, verificación interactiva |
| [Policy Engine](https://htmlpreview.github.io/?https://github.com/hyperiumia/hyperium-sovereign-os/blob/main/docs/demo-4-policy.html) | 7 políticas expandibles, 10 operadores, test console |
| [Attack Simulation](https://htmlpreview.github.io/?https://github.com/hyperiumia/hyperium-sovereign-os/blob/main/docs/demo-5-attack.html) | Timeline de insider threat con detección y respuesta |

---

## API Reference

### Events

| Método | Endpoint | Descripción |
|---|---|---|
| POST | `/api/v1/events/ingest` | Ingesta individual |
| POST | `/api/v1/events/ingest/batch` | Ingesta en lote |

### Evidence

| Método | Endpoint | Descripción |
|---|---|---|
| GET | `/api/v1/evidence/verify/{id}` | Verificar integridad |
| GET | `/api/v1/evidence/epoch/{n}` | Datos de epoch Merkle |
| GET | `/api/v1/evidence/epoch/{n}/verify` | Verificar firma de epoch |
| GET | `/api/v1/evidence/stats` | Estadísticas del Vault |

### Workspaces

| Método | Endpoint | Descripción |
|---|---|---|
| GET | `/api/v1/workspaces/` | Listar workspaces |
| POST | `/api/v1/workspaces/` | Crear workspace |
| POST | `/api/v1/workspaces/{id}/grant` | Otorgar acceso |
| POST | `/api/v1/workspaces/{id}/revoke/{gid}` | Revocar acceso |

### Policies

| Método | Endpoint | Descripción |
|---|---|---|
| GET | `/api/v1/policies/` | Listar políticas |
| POST | `/api/v1/policies/` | Crear política |
| PUT | `/api/v1/policies/{id}/toggle` | Activar/desactivar |

### Alerts

| Método | Endpoint | Descripción |
|---|---|---|
| GET | `/api/v1/alerts/` | Listar alertas |
| PUT | `/api/v1/alerts/{id}/resolve` | Resolver alerta |

### Compliance

| Método | Endpoint | Descripción |
|---|---|---|
| GET | `/api/v1/compliance/summary` | Resumen general |
| GET | `/api/v1/compliance/frameworks` | Frameworks disponibles |
| GET | `/api/v1/compliance/report/{fw}` | Reporte completo |
| GET | `/api/v1/compliance/gaps/{fw}` | Gaps priorizados |
| GET | `/api/v1/compliance/controls/{fw}` | Todos los controles |
| GET | `/api/v1/compliance/evidence/{fw}` | Paquete para auditores |
| GET | `/api/v1/compliance/export/{fw}` | Export HTML/JSON |

### System

| Método | Endpoint | Descripción |
|---|---|---|
| GET | `/health` | Health check |
| GET | `/` | Info del sistema |
| GET | `/docs` | Swagger UI |

---

## Deployment

### Docker

```bash
cd hyperium-sovereign-os
docker-compose up -d
```

### systemd (Agent)

```bash
sudo cp agent/target/release/sovereign-agent /usr/local/bin/
sudo cp agent/config/agent.toml /etc/sovereign-agent/
sudo cp agent/systemd/sovereign-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sovereign-agent
sudo systemctl start sovereign-agent
```

---

## Modelo de amenaza

| Actor | Objetivo | Defensa |
|---|---|---|
| **Insider malicioso** | Exfiltrar IP | USB blocking, risk scoring |
| **Insider negligente** | Data leak accidental | Políticas automáticas, alertas |
| **Atacante externo** | Robar código, borrar logs | Aislamiento forense, sellado |
| **Competencia** | Espionaje corporativo | Watermarking, air-gapped |
| **Ransomware** | Cifrar evidencia | Detección de patrones, aislamiento |

---

## Roadmap

### Fase 1 — MVP Operacional (Actual)

- [x] Servidor con 14 entidades y 22+ endpoints
- [x] Evidence Vault con Merkle tree y Ed25519
- [x] Policy Engine declarativo con YAML
- [x] Risk Engine multifactor
- [x] Agent Rust con 4 monitores
- [x] Cola offline persistente
- [x] Enforcement local (freeze, isolate)
- [x] Compliance Mapper (NIST CSF 2.0 + ISO 27001:2022)
- [x] 94 tests passing
- [x] 5 demos HTML interactivas
- [x] Demo E2E de ataque

### Fase 2 — Observabilidad y Compliance avanzado

- [ ] Watermarking criptográfico
- [ ] Taint analysis corporativa
- [ ] Timeline forense visual
- [ ] Exportación de paquete forense
- [ ] SOC 2 Type II mappings
- [ ] GDPR/LGPD breach notification

### Fase 3 — DFIR y certificación

- [ ] Sellado RFC 3161
- [ ] Integración SIEM/EDR
- [ ] CMMC 2.0 compliance
- [ ] PCI DSS 4.0 + HIPAA
- [ ] Reportes ejecutivos
- [ ] Compliance dashboard visual

---

## Stack tecnológico

| Capa | Tecnología | Razón |
|---|---|---|
| **Servidor** | Python 3.12 + FastAPI | Async, ecosistema maduro |
| **Base de datos** | SQLAlchemy + SQLite/PostgreSQL | ORM robusto |
| **Criptografía** | hashlib + cryptography (Ed25519) | Estándares NIST |
| **Agent** | Rust + Tokio | Performance, sin dependencias |
| **Filesystem** | inotify non-blocking | Detección en tiempo real |
| **Compliance** | Custom engine (YAML) | NIST CSF 2.0 + ISO 27001 |
| **Despliegue** | Docker + systemd | On-premise |

---

## Licencia

Propiedad de **Hyperium IA**. Todos los derechos reservados.

Contacto: security@hyperiumia.com

---

Desarrollado por [Hyperium IA](https://www.hyperiumia.com) — Inteligencia Artificial aplicada a ciberseguridad corporativa.

<p align="center">
  <strong>Hyperium Sovereign-OS</strong><br>
  Soberanía corporativa operable.<br>
  <a href="https://www.hyperiumia.com">www.hyperiumia.com</a>
</p>