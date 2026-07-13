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

### Enforcement (Acciones Locales)

| Acción | Trigger | Efecto |
|---|---|---|
| **FREEZE** | Risk score alto, transferencia masiva, USB | Bloqueo de pantalla, kill de procesos sospechosos |
| **ISOLATE** | Ransomware, borrado de logs | iptables DROP tráfico saliente excepto al servidor |
| **BLOCK** | USB en workspace confidencial | Bloqueo de la acción específica |

### Resiliencia

| Característica | Implementación |
|---|---|
| **Cola offline** | Eventos persistidos en JSONL local. Se envían al reconectar. |
| **Retry con backoff** | Exponencial hasta 30s. Nunca deja de monitorear. |
| **Batch sending** | Hasta 50 eventos por request. |
| **Health checks** | Cada 30s con alertas si el servidor no responde. |
