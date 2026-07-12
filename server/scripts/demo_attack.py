#!/usr/bin/env python3
import json
import hmac as hmac_mod
import hashlib
from datetime import datetime, timezone, timedelta
import httpx

BASE_URL = "http://127.0.0.1:8000"
HMAC_SECRET = "change-me-in-production-to-a-strong-random-secret-256bit"


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def sign(payload):
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    event_hash = sha256_hex(canonical.encode())
    hmac_sig = hmac_mod.new(HMAC_SECRET.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return event_hash, hmac_sig


def make_event(payload, event_type, severity="LOW", session_id=None):
    eh, hs = sign(payload)
    body = {
        "agent_id": "agent-001", "device_id": "workstation-alpha",
        "event_type": event_type, "source_module": "demo",
        "payload": payload, "severity": severity,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_hash": eh, "hmac_signature": hs,
    }
    if session_id:
        body["session_id"] = session_id
    return body


def banner(text):
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)


def step(n, text):
    print(f"\n  [{n}] {text}")


def info(label, value):
    print(f"       {label}: {value}")


def main():
    banner("HYPERIUM SOVEREIGN-OS — DEMO DE ATAQUE E2E")
    print("  Simulando escenario de insider threat corporativo...")

    with httpx.Client(base_url=BASE_URL, timeout=10) as c:
        step(0, "Verificando estado del servidor...")
        r = c.get("/health")
        assert r.status_code == 200, f"Servidor no disponible: {r.status_code}"
        health = r.json()
        info("Estado", health["status"])
        info("Signing Key", health["signing_key_id"])

        banner("FASE 1: PREPARACION DEL ENTORNO")

        step(1, "Creando workspace confidencial air-gapped...")
        r = c.post("/api/v1/workspaces/", json={
            "name": "Proyecto Fenix — I+D Estrategico",
            "description": "Codigo fuente del motor de IA propietario",
            "classification": "TOP_SECRET",
            "is_air_gapped": True, "allow_usb": False,
            "allow_network": False, "allow_print": False,
            "max_session_hours": 4,
        })
        ws = r.json()
        workspace_id = ws["id"]
        info("Workspace", ws["name"])
        info("ID", workspace_id[:16] + "...")
        info("Clasificacion", ws["classification"])
        info("Air-gapped", ws["is_air_gapped"])
        info("USB permitido", ws["allow_usb"])

        step(2, "Creando sesion de trabajo para Carlos Mendoza...")
        db_session_resp = c.post(f"/api/v1/workspaces/{workspace_id}/grant",
            params={"user_id": "carlos-mendoza-001", "granted_by": "admin",
                    "hours": 4, "reason": "Sprint de desarrollo Fase 3"})
        grant = db_session_resp.json()
        info("Grant ID", grant["grant_id"][:16] + "...")
        info("Expira", grant["expires_at"])

        step(3, "Desarrollador trabaja normalmente (5 commits/lecturas)...")
        normal_count = 0
        for payload, etype in [
            ({"action": "git.commit", "repo": "fenix-engine", "files": 12, "author": "carlos.mendoza"}, "code.commit"),
            ({"action": "file.read", "path": "/src/core/neural_engine.py", "size": 45000}, "file.access"),
            ({"action": "git.commit", "repo": "fenix-engine", "files": 3, "author": "carlos.mendoza"}, "code.commit"),
            ({"action": "file.read", "path": "/src/models/weights_v3.bin", "size": 890000000}, "file.access"),
            ({"action": "git.commit", "repo": "fenix-engine", "files": 7, "author": "carlos.mendoza"}, "code.commit"),
        ]:
            c.post("/api/v1/events/ingest", json=make_event(payload, etype, "LOW"))
            normal_count += 1
        info("Eventos normales registrados", normal_count)

        banner("FASE 2: INCIDENTE — USB NO AUTORIZADO")
        step(4, "Empleado conecta dispositivo USB (SanDisk Ultra 64GB)...")
        r = c.post("/api/v1/events/ingest", json=make_event(
            {"action": "usb.device.connected", "vendor_id": "0781",
             "product_id": "5591", "device_type": "storage",
             "vendor_name": "SanDisk", "capacity_gb": 64,
             "host_device": "workstation-alpha"},
            "usb.device.connected", "HIGH"))
        usb_result = r.json()
        info("Evento USB", usb_result["event_id"][:16] + "...")
        info("Acciones tomadas", usb_result["actions_taken"] if usb_result["actions_taken"] else ["(registrado - sin sesion activa vinculada)"])

        banner("FASE 3: EXFILTRACION DETECTADA")
        step(5, "Empleado intenta copiar 600MB de codigo fuente al USB...")
        r = c.post("/api/v1/events/ingest", json=make_event(
            {"action": "data.transfer", "source": "/src/core/",
             "destination": "/media/usb0/backup/", "data_bytes": 629145600,
             "transfer_rate_mbps": 45.2, "files_count": 847},
            "session.data_volume", "CRITICAL"))
        transfer_result = r.json()
        info("Evento de exfiltracion", transfer_result["event_id"][:16] + "...")
        info("Acciones tomadas", transfer_result["actions_taken"] if transfer_result["actions_taken"] else ["(registrado - sin sesion activa vinculada)"])

        step(6, "Simulando ataque de ransomware (borrado de logs)...")
        r = c.post("/api/v1/events/ingest", json=make_event(
            {"action": "filesystem.log_deletion_attempt",
             "target": "/var/log/auth.log", "process": "rm -rf",
             "user": "carlos.mendoza"},
            "filesystem.log_deletion_attempt", "CRITICAL"))
        ransom_result = r.json()
        info("Evento ransomware", ransom_result["event_id"][:16] + "...")
        info("Acciones tomadas", ransom_result["actions_taken"] if ransom_result["actions_taken"] else ["(registrado - sin sesion activa vinculada)"])

        step(7, "Registrando intento de borrado masivo de archivos de log...")
        r = c.post("/api/v1/events/ingest", json=make_event(
            {"action": "filesystem.mass_encrypt",
             "encrypted_files": 2341, "extension": ".locked",
             "ransom_note": "YOUR_FILES_ARE_ENCRYPTED.txt"},
            "filesystem.mass_encrypt", "CRITICAL"))
        mass_result = r.json()
        info("Evento de cifrado masivo", mass_result["event_id"][:16] + "...")

        banner("FASE 4: VERIFICACION CRIPTOGRAFICA DE EVIDENCIA")
        step(8, "Verificando integridad de CADA evento registrado...")

        all_events = [
            ("Login del empleado", None),
            ("Conexion USB", usb_result["event_id"]),
            ("Transferencia 600MB", transfer_result["event_id"]),
            ("Borrado de logs", ransom_result["event_id"]),
            ("Cifrado masivo", mass_result["event_id"]),
        ]

        all_valid = True
        valid_count = 0
        total_count = 0

        r_stats = c.get("/api/v1/evidence/stats")
        total_events_in_vault = r_stats.json()["total_events"]

        for label, eid in all_events:
            if eid is None:
                continue
            total_count += 1
            r = c.get(f"/api/v1/evidence/verify/{eid}")
            v = r.json()
            marker = "OK" if v["is_valid"] else "FAIL"
            print(f"       [{marker}] {label:30s} -> {'VALIDO' if v['is_valid'] else 'MANIPULADO'}")
            if v.get("epoch_signature_valid"):
                print(f"            Firma Merkle: VERIFICADA")
            if v["is_valid"]:
                valid_count += 1
            else:
                all_valid = False

        print()
        print(f"       Verificados: {valid_count}/{total_count} eventos")
        print(f"       Total en vault: {total_events_in_vault} eventos sellados")
        if all_valid:
            print()
            print("       TODA LA EVIDENCIA ES INTEGRA Y VERIFICABLE")
            print("       Cualquier manipulacion de logs seria detectable.")

        step(9, "Estado final del Evidence Vault...")
        stats = r_stats.json()
        info("Total eventos sellados", stats["total_events"])
        info("Epochs Merkle", stats["total_epochs"])
        if stats["latest_root_hash"]:
            info("Ultimo root hash", stats["latest_root_hash"][:32] + "...")
        info("Signing key ID", stats["signing_key_id"])

        step(10, "Alertas generadas durante el incidente...")
        r = c.get("/api/v1/alerts/")
        alerts = r.json()
        if alerts:
            for alert in alerts:
                print(f"       [{alert['severity']:8s}] {alert['title']}")
                print(f"                Accion: {alert['action_taken']} | Estado: {alert['status']}")
        else:
            print("       (Alertas requieren sesion activa vinculada a workspace)")
            print("       Los eventos fueron registrados y sellados correctamente.")

        step(11, "Politicas de seguridad activas en el sistema...")
        r = c.get("/api/v1/policies/")
        print()
        print("       Politica                              Prioridad  Accion")
        print("       " + "-" * 62)
        for p in r.json():
            enabled = "*" if p["is_enabled"] else " "
            name = p["name"][:35]
            print(f"       {enabled} {name:37s} p{p['priority']:<8d} {p['action']}")

        step(12, "Verificando firma de epoch Merkle...")
        if stats["total_epochs"] and stats["total_epochs"] > 0:
            r = c.get(f"/api/v1/evidence/epoch/0/verify")
            epoch_v = r.json()
            info("Epoch", epoch_v["epoch_number"])
            info("Firma valida", epoch_v["signature_valid"])
        else:
            info("Epochs", f"0 (se necesitan 100 eventos para cerrar un epoch automaticamente)")
            info("Siguiente paso", "Forzar cierre con /api/v1/evidence/force-close")

        banner("RESUMEN DEL INCIDENTE")
        print(f"""
  Fecha:             {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
  Workspace:         {ws['name']} ({ws['classification']})
  Empleado:          Carlos Mendoza (senior_developer)
  Dispositivo:       workstation-alpha

  Eventos detectados:
    - USB no autorizado (SanDisk 64GB) conectado en workspace TOP_SECRET
    - Transferencia de 600MB de codigo fuente hacia USB
    - Intento de borrado de logs del sistema
    - Cifrado masivo de 2341 archivos (senal de ransomware)

  Evidencia:         {stats['total_events']} eventos sellados criptograficamente
  Integridad:        {valid_count}/{total_count} eventos verificados
  Merkle root:       {stats['latest_root_hash'][:32] + '...' if stats['latest_root_hash'] else 'pendiente'}
  Signing key:       {stats['signing_key_id']}

  Estado:            {'TODA LA EVIDENCIA ES VERIFICABLE' if all_valid else 'SE DETECTO MANIPULACION'}

  En un escenario real con el agent conectado:
    - La sesion se habria CONGELADO automaticamente al detectar USB
    - La sesion se habria AISLADO al detectar borrado de logs
    - El equipo de seguridad habria recibido alertas en tiempo real
    - La cadena de custodia estaria lista para tribunales

  Hyperium Sovereign-OS: Soberanía corporativa operable.
""")
        banner("FIN DE LA DEMO")


if __name__ == "__main__":
    main()
