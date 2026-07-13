<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.0-blue.svg" alt="version">
  <img src="https://img.shields.io/badge/python-3.12+-green.svg" alt="python">
  <img src="https://img.shields.io/badge/rust-1.70+-orange.svg" alt="rust">
  <img src="https://img.shields.io/badge/license-Proprietary-red.svg" alt="license">
  <img src="https://img.shields.io/badge/tests-74%2F74-brightgreen.svg" alt="tests">
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

El sistema opera sobre tres pilares:

| Pilar | Módulo | Función |
|---|---|---|
| **Soberanía del Dato** | Agent + Policy Engine | Control absoluto sobre quién y qué procesos acceden a datos críticos |
| **Soberanía Operacional** | Monitores + Risk Engine | Blindaje contra exfiltración, insider threat y sabotaje |
| **Soberanía Probatoria** | Evidence Vault + Merkle Tree | Evidencia inmutable con valor legal para tribunales y reguladores |

---

## Componentes

### Servidor (Python 3.12 + FastAPI)

El cerebro de Sovereign-OS. Procesa eventos, evalúa políticas, almacena evidencia con integridad criptográfica.

| Componente | Descripción |
|---|---|
| **Evidence Vault** | Almacena eventos con hash SHA-256, firma HMAC-SHA256 y posición en Merkle tree. Epochs firmados con Ed25519. |
| **Policy Engine** | Motor declarativo con 10 operadores, wildcards, prioridades y condiciones AND. Carga políticas desde YAML. |
| **Risk Engine** | Scoring multifactor: volumen de datos, eventos de seguridad, horario, clasificación de workspace, historial. |
| **REST API** | 15+ endpoints: ingesta, verificación de integridad, workspaces, alertas, exportación forense. |
| **14 Entidades** | User, Device, Session, Workspace, Asset, Policy, Event, Alert, EvidenceItem, ForensicCase, AccessGrant, Revocation, MerkleEpoch. |

### Agent (Rust)

El guardian de cada endpoint. Monitorea en tiempo real y ejecuta acciones de enforcement.

| Monitor | Método | Detecta |
|---|---|---|
| **USB Monitor** | Polling /sys/bus/usb | Dispositivos USB, clasificación (storage, HID, network) |
| **Network Monitor** | Parsing /proc/net/tcp | Conexiones externas, puertos sospechosos (C2, exfiltración) |
| **Filesystem Monitor** | inotify non-blocking | Creación/eliminación de archivos, borrado de logs, ransomware |
| **Session Monitor** | who + env | Cambios de usuario, inicio/cierre de sesión |

### Enforcement

| Acción | Trigger | Efecto |
|---|---|---|
| **FREEZE** | Risk score alto, transferencia masiva, USB | Bloqueo de pantalla, kill de procesos |
| **ISOLATE** | Ransomware, borrado de logs | iptables DROP tráfico saliente excepto al servidor |
| **BLOCK** | USB en workspace confidencial | Bloqueo de la acción específica |

### Resiliencia

| Característica | Implementación |
|---|---|
| **Cola offline** | Eventos persistidos en JSONL local. Se envían al reconectar. |
| **Retry con backoff** | Exponencial hasta 30s. Nunca deja de monitorear. |
| **Batch sending** | Hasta 50 eventos por request. |
| **Health checks** | Cada 30s con alertas si el servidor no responde. |

---

## Criptografía

Cada evento que llega al servidor:

1. Se **hashea** con SHA-256 (hash canónico del payload JSON).
2. Se **verifica** el HMAC-SHA256 enviado por el agent (autenticidad).
3. Se **agrega** como hoja del Merkle tree del epoch actual.
4. Cada 100 eventos, el epoch se **cierra**: raíz Merkle firmada con Ed25519.
5. La raíz firmada es un checkpoint inmutable: cualquier manipulación es detectable.

Si un atacante altera un log después de ser almacenado, el sistema detecta la manipulación comparando el hash recalculado con el almacenado.

---

## Políticas

Las políticas se definen en YAML y se evalúan contra cada evento:

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
| isolate-ransomware-signal | filesystem.mass_encrypt | ISOLATE | 0 |
| isolate-log-deletion | filesystem.log_deletion_attempt | ISOLATE | 0 |
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

### Demo de ataque

```bash
cd hyperium-sovereign-os/server
python scripts/demo_attack.py
```

Simula un escenario completo de insider threat: USB no autorizado, transferencia masiva, borrado de logs, ransomware.

---

## Tests

```bash
cd hyperium-sovereign-os/server
python -m pytest tests/ -v
```

**74 tests** passing:

| Suite | Tests | Cobertura |
|---|---|---|
| test_crypto.py | 18 | SHA-256, HMAC, Merkle tree, Ed25519 |
| test_policy_engine.py | 18 | 10 operadores, wildcards, condiciones, prioridades |
| test_evidence_vault.py | 9 | Ingesta, rechazo de manipulación, epochs, verificación |
| test_api.py | 16 | Health, CRUD, ingesta, batch, verificación, alertas |
| test_risk_engine.py | 4 | Scoring, volumen, historial, bounds |

---

## API Reference

### Events

| Método | Endpoint | Descripción |
|---|---|---|
| POST | /api/v1/events/ingest | Ingesta individual |
| POST | /api/v1/events/ingest/batch | Ingesta en lote |

### Evidence

| Método | Endpoint | Descripción |
|---|---|---|
| GET | /api/v1/evidence/verify/{id} | Verificar integridad |
| GET | /api/v1/evidence/epoch/{n} | Datos de epoch Merkle |
| GET | /api/v1/evidence/epoch/{n}/verify | Verificar firma de epoch |
| GET | /api/v1/evidence/stats | Estadísticas del Vault |

### Workspaces

| Método | Endpoint | Descripción |
|---|---|---|
| GET | /api/v1/workspaces/ | Listar workspaces |
| POST | /api/v1/workspaces/ | Crear workspace |
| POST | /api/v1/workspaces/{id}/grant | Otorgar acceso |
| POST | /api/v1/workspaces/{id}/revoke/{gid} | Revocar acceso |

### Policies

| Método | Endpoint | Descripción |
|---|---|---|
| GET | /api/v1/policies/ | Listar políticas |
| POST | /api/v1/policies/ | Crear política |
| PUT | /api/v1/policies/{id}/toggle | Activar/desactivar |

### Alerts

| Método | Endpoint | Descripción |
|---|---|---|
| GET | /api/v1/alerts/ | Listar alertas |
| PUT | /api/v1/alerts/{id}/resolve | Resolver alerta |

### System

| Método | Endpoint | Descripción |
|---|---|---|
| GET | /health | Health check |
| GET | / | Info del sistema |
| GET | /docs | Swagger UI |

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

Sovereign-OS asume que **la red ya puede estar comprometida**:

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

- [x] Servidor con 14 entidades y 15+ endpoints
- [x] Evidence Vault con Merkle tree y Ed25519
- [x] Policy Engine declarativo con YAML
- [x] Risk Engine multifactor
- [x] Agent Rust con 4 monitores
- [x] Cola offline persistente
- [x] Enforcement local (freeze, isolate)
- [x] 74 tests passing
- [x] Demo E2E de ataque

### Fase 2 — Observabilidad avanzada

- [ ] Watermarking criptográfico
- [ ] Taint analysis corporativa
- [ ] Timeline forense visual
- [ ] Exportación de paquete forense

### Fase 3 — DFIR y compliance

- [ ] Sellado RFC 3161
- [ ] Integración SIEM/EDR
- [ ] NDAs dinámicos
- [ ] Reportes ejecutivos
- [ ] Mapeo ISO 27001

---

## Stack tecnológico

| Capa | Tecnología | Razón |
|---|---|---|
| **Servidor** | Python 3.12 + FastAPI | Async, ecosistema maduro |
| **Base de datos** | SQLAlchemy + SQLite/PostgreSQL | ORM robusto |
| **Criptografía** | hashlib + cryptography (Ed25519) | Estándares NIST |
| **Agent** | Rust + Tokio | Performance, sin dependencias |
| **Filesystem** | inotify non-blocking | Detección en tiempo real |
| **Despliegue** | Docker + systemd | On-premise |

---

## Licencia

Propiedad de **Hyperium IA**. Todos los derechos reservados.

Contacto: hyperiumia@protonmail.com

---

Desarrollado por [Hyperium IA](https://www.hyperiumia.com) — Inteligencia Artificial aplicada a ciberseguridad corporativa.

<p align="center">
  <strong>Hyperium Sovereign-OS</strong><br>
  Soberanía corporativa operable.<br>
  <a href="https://www.hyperiumia.com">www.hyperiumia.com</a>
</p>
