"""
Tests for Compliance Mapper module.
"""
import pytest
from app.compliance.engine import ComplianceEngine
from app.compliance.frameworks import get_all_frameworks, get_framework, get_nist_csf2, get_iso_27001


class TestFrameworks:
    def test_get_all_frameworks(self):
        frameworks = get_all_frameworks()
        assert len(frameworks) == 2
        names = [f["name"] for f in frameworks]
        assert "NIST CSF 2.0" in names
        assert "ISO 27001:2022" in names

    def test_nist_csf2_structure(self):
        fw = get_nist_csf2()
        assert fw["name"] == "NIST CSF 2.0"
        assert fw["version"] == "2.0"
        assert len(fw["controls"]) > 40
        for ctrl in fw["controls"]:
            assert "id" in ctrl
            assert "title" in ctrl
            assert "function" in ctrl
            assert "status" in ctrl
            assert ctrl["status"] in ("covered", "partial", "not_covered", "not_applicable")

    def test_iso_27001_structure(self):
        fw = get_iso_27001()
        assert fw["name"] == "ISO 27001:2022"
        assert len(fw["controls"]) > 30
        for ctrl in fw["controls"]:
            assert "id" in ctrl
            assert ctrl["id"].startswith("A.")

    def test_get_framework_by_name(self):
        fw = get_framework("nist-csf-2.0")
        assert fw is not None
        assert fw["name"] == "NIST CSF 2.0"

    def test_get_framework_iso(self):
        fw = get_framework("iso-27001")
        assert fw is not None
        assert fw["name"] == "ISO 27001:2022"

    def test_get_framework_not_found(self):
        fw = get_framework("nonexistent-framework")
        assert fw is None

    def test_nist_has_all_functions(self):
        fw = get_nist_csf2()
        functions = set(ctrl["function"] for ctrl in fw["controls"])
        assert "Govern" in functions
        assert "Identify" in functions
        assert "Protect" in functions
        assert "Detect" in functions
        assert "Respond" in functions
        assert "Recover" in functions

    def test_iso_has_all_themes(self):
        fw = get_iso_27001()
        themes = set(ctrl["category"] for ctrl in fw["controls"])
        assert len(themes) >= 4


class TestComplianceEngine:
    def test_list_frameworks(self):
        result = ComplianceEngine.list_frameworks()
        assert len(result) == 2
        for fw in result:
            assert "name" in fw
            assert "score" in fw
            assert "covered" in fw
            assert "total_controls" in fw

    def test_evaluate_nist(self):
        report = ComplianceEngine.evaluate_framework("nist-csf-2.0")
        assert report is not None
        assert report["framework"] == "NIST CSF 2.0"
        assert "overall_score" in report
        assert "by_function" in report
        assert "controls" in report
        assert len(report["controls"]) > 40

    def test_evaluate_iso(self):
        report = ComplianceEngine.evaluate_framework("iso-27001")
        assert report is not None
        assert report["framework"] == "ISO 27001:2022"
        assert len(report["controls"]) > 30

    def test_evaluate_not_found(self):
        report = ComplianceEngine.evaluate_framework("nonexistent")
        assert report is None

    def test_find_gaps(self):
        gaps = ComplianceEngine.find_gaps("nist-csf-2.0")
        assert gaps is not None
        assert gaps["total_gaps"] > 0
        assert gaps["high_priority"] > 0
        for gap in gaps["gaps"]:
            assert gap["status"] in ("not_covered", "partial")
            assert gap["priority"] in ("HIGH", "MEDIUM")

    def test_gaps_sorted_by_priority(self):
        gaps = ComplianceEngine.find_gaps("nist-csf-2.0")
        priorities = [g["priority"] for g in gaps["gaps"]]
        high_indices = [i for i, p in enumerate(priorities) if p == "HIGH"]
        medium_indices = [i for i, p in enumerate(priorities) if p == "MEDIUM"]
        if high_indices and medium_indices:
            assert max(high_indices) < min(medium_indices)

    def test_get_controls(self):
        result = ComplianceEngine.get_controls("nist-csf-2.0")
        assert result is not None
        assert result["total"] > 40
        assert len(result["controls"]) == result["total"]

    def test_generate_summary(self):
        summary = ComplianceEngine.generate_summary()
        assert summary["platform"] == "Hyperium Sovereign-OS"
        assert summary["version"] == "0.1.0"
        assert len(summary["frameworks"]) == 2
        assert summary["totals"]["controls_evaluated"] > 70

    def test_generate_evidence_package(self):
        evidence = ComplianceEngine.generate_evidence_package("nist-csf-2.0")
        assert evidence is not None
        assert evidence["package_type"] == "compliance_evidence"
        assert len(evidence["evidence_items"]) > 0
        for item in evidence["evidence_items"]:
            assert item["coverage_status"] in ("covered", "partial")
            assert "verification_endpoints" in item

    def test_score_is_percentage(self):
        report = ComplianceEngine.evaluate_framework("nist-csf-2.0")
        score_str = report["overall_score"]
        score_val = float(score_str.replace("%", ""))
        assert 0 <= score_val <= 100

    def test_nist_coverage_greater_than_40(self):
        report = ComplianceEngine.evaluate_framework("nist-csf-2.0")
        score = float(report["overall_score"].replace("%", ""))
        assert score > 40, f"NIST coverage should be >40%, got {score}%"

    def test_iso_coverage_greater_than_30(self):
        report = ComplianceEngine.evaluate_framework("iso-27001")
        score = float(report["overall_score"].replace("%", ""))
        assert score > 30, f"ISO coverage should be >30%, got {score}%"
