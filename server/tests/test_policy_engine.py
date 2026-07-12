"""
Tests para el motor de políticas:
- Evaluación de condiciones
- Wildcards en triggers
- Operadores
- Prioridades
- Integración con YAML
"""
import pytest
from app.core.policy_engine import PolicyEngine, OPERATORS


class TestOperators:
    def test_eq(self):
        assert OPERATORS["eq"](5, 5) is True
        assert OPERATORS["eq"](5, 6) is False

    def test_neq(self):
        assert OPERATORS["neq"](5, 6) is True
        assert OPERATORS["neq"](5, 5) is False

    def test_gt(self):
        assert OPERATORS["gt"](10, 5) is True
        assert OPERATORS["gt"](5, 10) is False
        assert OPERATORS["gt"](5, 5) is False

    def test_gte(self):
        assert OPERATORS["gte"](10, 5) is True
        assert OPERATORS["gte"](5, 5) is True
        assert OPERATORS["gte"](4, 5) is False

    def test_lt(self):
        assert OPERATORS["lt"](3, 5) is True
        assert OPERATORS["lt"](5, 3) is False

    def test_lte(self):
        assert OPERATORS["lte"](5, 5) is True
        assert OPERATORS["lte"](3, 5) is True

    def test_contains(self):
        assert OPERATORS["contains"]("hello world", "world") is True
        assert OPERATORS["contains"]("hello", "xyz") is False

    def test_in_list(self):
        assert OPERATORS["in"]("HIGH", ["HIGH", "CRITICAL"]) is True
        assert OPERATORS["in"]("LOW", ["HIGH", "CRITICAL"]) is False

    def test_in_csv_string(self):
        assert OPERATORS["in"]("a", "a,b,c") is True
        assert OPERATORS["in"]("d", "a,b,c") is False

    def test_matches_regex(self):
        assert OPERATORS["matches"]("usb.device.connected", r"usb\..*") is True
        assert OPERATORS["matches"]("network.new", r"usb\..*") is False


class TestTriggerMatching:
    def setup_method(self):
        self.engine = PolicyEngine()

    def test_exact_match(self):
        assert self.engine._matches_trigger("usb.device.connected", "usb.device.connected") is True

    def test_wildcard_match(self):
        assert self.engine._matches_trigger("usb.*", "usb.device.connected") is True
        assert self.engine._matches_trigger("usb.*", "usb.device.removed") is True

    def test_wildcard_no_match(self):
        assert self.engine._matches_trigger("usb.*", "network.connection.new") is False

    def test_star_matches_everything(self):
        assert self.engine._matches_trigger("*", "anything.at.all") is True

    def test_partial_wildcard(self):
        assert self.engine._matches_trigger("network.connection.*", "network.connection.new") is True
        assert self.engine._matches_trigger("network.connection.*", "network.data") is False


class TestConditionEvaluation:
    def setup_method(self):
        self.engine = PolicyEngine()

    def test_single_condition_true(self):
        conditions = [{"field": "session.risk_score", "operator": "gte", "value": 0.5}]
        context = {"session": {"risk_score": 0.8}}
        assert self.engine._evaluate_conditions(conditions, context) is True

    def test_single_condition_false(self):
        conditions = [{"field": "session.risk_score", "operator": "gte", "value": 0.9}]
        context = {"session": {"risk_score": 0.3}}
        assert self.engine._evaluate_conditions(conditions, context) is False

    def test_multiple_conditions_and(self):
        conditions = [
            {"field": "workspace.classification", "operator": "in", "value": ["CONFIDENTIAL", "TOP_SECRET"]},
            {"field": "workspace.allow_usb", "operator": "eq", "value": False},
        ]
        context = {
            "workspace": {"classification": "CONFIDENTIAL", "allow_usb": False}
        }
        assert self.engine._evaluate_conditions(conditions, context) is True

    def test_multiple_conditions_partial_fail(self):
        conditions = [
            {"field": "workspace.classification", "operator": "in", "value": ["CONFIDENTIAL"]},
            {"field": "workspace.allow_usb", "operator": "eq", "value": True},
        ]
        context = {
            "workspace": {"classification": "CONFIDENTIAL", "allow_usb": False}
        }
        assert self.engine._evaluate_conditions(conditions, context) is False

    def test_missing_field_returns_false(self):
        conditions = [{"field": "nonexistent.field", "operator": "eq", "value": 1}]
        context = {"workspace": {}}
        assert self.engine._evaluate_conditions(conditions, context) is False

    def test_empty_conditions_always_true(self):
        assert self.engine._evaluate_conditions([], {}) is True

    def test_nested_field_resolution(self):
        context = {"a": {"b": {"c": 42}}}
        assert self.engine._resolve_field("a.b.c", context) == 42


class TestPolicyEvaluation:
    def test_evaluate_returns_matching_policies(self):
        from app.models import Policy, ActionType, SeverityLevel

        engine = PolicyEngine()
        engine._policies = [
            Policy(
                name="test-policy",
                trigger_event="usb.*",
                conditions=[{"field": "workspace.allow_usb", "operator": "eq", "value": False}],
                action=ActionType.BLOCK,
                severity=SeverityLevel.HIGH,
                is_enabled=True,
                priority=10,
            )
        ]

        context = {"workspace": {"allow_usb": False}}
        decisions = engine.evaluate("usb.device.connected", context)
        assert len(decisions) == 1
        assert decisions[0].matched is True

    def test_evaluate_no_match(self):
        from app.models import Policy, ActionType, SeverityLevel

        engine = PolicyEngine()
        engine._policies = [
            Policy(
                name="usb-only",
                trigger_event="usb.*",
                conditions=[],
                action=ActionType.BLOCK,
                severity=SeverityLevel.HIGH,
                is_enabled=True,
                priority=10,
            )
        ]

        decisions = engine.evaluate("network.connection.new", {})
        assert len(decisions) == 0
