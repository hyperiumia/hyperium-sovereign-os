"""
Sovereign-OS Compliance Engine
Evaluates framework coverage, identifies gaps, generates reports.
"""
import structlog
from datetime import datetime, timezone
from typing import Optional
from .frameworks import get_all_frameworks, get_framework

logger = structlog.get_logger("compliance.engine")

STATUS_ORDER = {"covered": 0, "partial": 1, "not_covered": 2, "not_applicable": 3}


class ComplianceEngine:

    @staticmethod
    def list_frameworks():
        result = []
        for fw in get_all_frameworks():
            controls = fw["controls"]
            counts = ComplianceEngine._count_statuses(controls)
            score = ComplianceEngine._calculate_score(controls)
            result.append({
                "name": fw["name"],
                "version": fw["version"],
                "description": fw["description"],
                "total_controls": len(controls),
                "covered": counts["covered"],
                "partial": counts["partial"],
                "not_covered": counts["not_covered"],
                "not_applicable": counts["not_applicable"],
                "score": f"{score:.1f}%",
            })
        return result

    @staticmethod
    def evaluate_framework(name):
        fw = get_framework(name)
        if not fw:
            return None

        controls = fw["controls"]
        counts = ComplianceEngine._count_statuses(controls)
        score = ComplianceEngine._calculate_score(controls)

        by_function = {}
        group_key = "function" if fw["name"].startswith("NIST") else "category"

        for ctrl in controls:
            group = ctrl[group_key]
            if group not in by_function:
                by_function[group] = {"covered": 0, "partial": 0, "not_covered": 0, "not_applicable": 0, "total": 0}
            by_function[group][ctrl["status"]] += 1
            by_function[group]["total"] += 1

        for group, stats in by_function.items():
            applicable = stats["total"] - stats["not_applicable"]
            if applicable > 0:
                weighted = stats["covered"] + stats["partial"] * 0.5
                stats["score"] = f"{(weighted / applicable) * 100:.1f}%"
            else:
                stats["score"] = "N/A"

        controls_sorted = sorted(controls, key=lambda x: STATUS_ORDER.get(x["status"], 9))

        return {
            "framework": fw["name"],
            "version": fw["version"],
            "description": fw["description"],
            "source": fw["source"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "overall_score": f"{score:.1f}%",
            "summary": counts,
            "by_function": by_function,
            "controls": controls_sorted,
        }

    @staticmethod
    def find_gaps(name):
        fw = get_framework(name)
        if not fw:
            return None

        gaps = []
        for ctrl in fw["controls"]:
            if ctrl["status"] in ("not_covered", "partial"):
                gaps.append({
                    "id": ctrl["id"],
                    "title": ctrl["title"],
                    "status": ctrl["status"],
                    "component": ctrl["component"],
                    "notes": ctrl["notes"],
                    "priority": "HIGH" if ctrl["status"] == "not_covered" else "MEDIUM",
                })

        gaps.sort(key=lambda x: (0 if x["priority"] == "HIGH" else 1, x["id"]))
        return {
            "framework": fw["name"],
            "total_gaps": len(gaps),
            "high_priority": len([g for g in gaps if g["priority"] == "HIGH"]),
            "medium_priority": len([g for g in gaps if g["priority"] == "MEDIUM"]),
            "gaps": gaps,
        }

    @staticmethod
    def get_controls(name):
        fw = get_framework(name)
        if not fw:
            return None

        controls = []
        for ctrl in fw["controls"]:
            controls.append({
                "id": ctrl["id"],
                "title": ctrl["title"],
                "function": ctrl["function"],
                "category": ctrl["category"],
                "component": ctrl["component"],
                "status": ctrl["status"],
                "notes": ctrl["notes"],
            })

        controls.sort(key=lambda x: STATUS_ORDER.get(x["status"], 9))
        return {
            "framework": fw["name"],
            "total": len(controls),
            "controls": controls,
        }

    @staticmethod
    def generate_summary():
        frameworks = ComplianceEngine.list_frameworks()
        total_controls = sum(f["total_controls"] for f in frameworks)
        total_covered = sum(f["covered"] for f in frameworks)
        total_partial = sum(f["partial"] for f in frameworks)
        total_not_covered = sum(f["not_covered"] for f in frameworks)

        applicable = total_controls - sum(f["not_applicable"] for f in frameworks)
        if applicable > 0:
            overall_score = ((total_covered + total_partial * 0.5) / applicable) * 100
        else:
            overall_score = 0

        return {
            "platform": "Hyperium Sovereign-OS",
            "version": "0.1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "overall_compliance_score": f"{overall_score:.1f}%",
            "frameworks": frameworks,
            "totals": {
                "controls_evaluated": total_controls,
                "covered": total_covered,
                "partial": total_partial,
                "not_covered": total_not_covered,
                "not_applicable": sum(f["not_applicable"] for f in frameworks),
            },
        }

    @staticmethod
    def generate_evidence_package(name):
        report = ComplianceEngine.evaluate_framework(name)
        if not report:
            return None

        evidence = {
            "package_type": "compliance_evidence",
            "framework": report["framework"],
            "generated_at": report["generated_at"],
            "overall_score": report["overall_score"],
            "evidence_items": [],
        }

        for ctrl in report["controls"]:
            if ctrl["status"] in ("covered", "partial"):
                evidence["evidence_items"].append({
                    "control_id": ctrl["id"],
                    "control_title": ctrl["title"],
                    "coverage_status": ctrl["status"],
                    "sovereign_component": ctrl["component"],
                    "evidence_description": ctrl["notes"],
                    "verification_endpoints": ComplianceEngine._get_endpoints(ctrl["component"]),
                })

        return evidence

    @staticmethod
    def _count_statuses(controls):
        counts = {"covered": 0, "partial": 0, "not_covered": 0, "not_applicable": 0}
        for ctrl in controls:
            counts[ctrl["status"]] += 1
        return counts

    @staticmethod
    def _calculate_score(controls):
        applicable = [c for c in controls if c["status"] != "not_applicable"]
        if not applicable:
            return 0.0
        covered = sum(1 for c in applicable if c["status"] == "covered")
        partial = sum(1 for c in applicable if c["status"] == "partial")
        return ((covered + partial * 0.5) / len(applicable)) * 100

    @staticmethod
    def _get_endpoints(component):
        endpoint_map = {
            "evidence_vault": ["/api/v1/evidence/stats", "/api/v1/evidence/verify/{id}"],
            "policy_engine": ["/api/v1/policies/"],
            "risk_engine": ["/api/v1/events/ingest"],
            "alert_system": ["/api/v1/alerts/"],
            "network_monitor": ["/api/v1/events/ingest"],
            "usb_monitor": ["/api/v1/events/ingest"],
            "filesystem_monitor": ["/api/v1/events/ingest"],
            "session_monitor": ["/api/v1/events/ingest"],
            "all_monitors": ["/api/v1/events/ingest"],
            "access_grants": ["/api/v1/workspaces/{id}/grant"],
            "workspace_management": ["/api/v1/workspaces/"],
            "workspace_classification": ["/api/v1/workspaces/"],
            "workspace_isolation": ["/api/v1/workspaces/"],
            "enforcement": ["/api/v1/events/ingest"],
            "enforcement_isolate": ["/api/v1/events/ingest"],
            "forensic_cases": ["/api/v1/alerts/"],
            "offline_queue": ["/api/v1/events/ingest/batch"],
            "compliance_mapper": ["/api/v1/compliance/summary"],
            "device_monitor": ["/api/v1/events/ingest"],
            "user_management": ["/api/v1/workspaces/"],
            "hmac_verification": ["/api/v1/events/ingest"],
            "event_logging": ["/api/v1/events/ingest"],
            "on_premise": ["/health"],
            "merkle_tree": ["/api/v1/evidence/stats"],
            "agent_config": [],
            "asset_management": ["/api/v1/workspaces/"],
        }
        return endpoint_map.get(component, [])
