import re
import yaml
from pathlib import Path
from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import Policy, ActionType, SeverityLevel
from app.config import settings
import structlog

logger = structlog.get_logger(__name__)

OPERATORS = {
    "eq": lambda a, b: a == b,
    "neq": lambda a, b: a != b,
    "gt": lambda a, b: float(a) > float(b),
    "gte": lambda a, b: float(a) >= float(b),
    "lt": lambda a, b: float(a) < float(b),
    "lte": lambda a, b: float(a) <= float(b),
    "contains": lambda a, b: str(b) in str(a),
    "in": lambda a, b: a in b if isinstance(b, list) else a in str(b).split(","),
    "matches": lambda a, b: bool(re.search(str(b), str(a))),
}


class PolicyDecision:
    def __init__(self, matched, policy=None, actions=None):
        self.matched = matched
        self.policy = policy
        self.actions = actions or []
        self.severity = policy.severity if policy else SeverityLevel.LOW


class PolicyEngine:
    def __init__(self):
        self._policies: list[Policy] = []

    async def load_policies(self, db: AsyncSession):
        result = await db.execute(
            select(Policy).where(Policy.is_enabled == True).order_by(Policy.priority.asc())
        )
        self._policies = list(result.scalars().all())
        logger.info("policy_engine.loaded", count=len(self._policies))

    async def import_from_yaml(self, db: AsyncSession, yaml_path=None):
        path = yaml_path or (settings.POLICIES_DIR / "default.yaml")
        if not path.exists():
            return
        with open(path) as f:
            data = yaml.safe_load(f)
        for p_def in data.get("policies", []):
            existing = await db.execute(select(Policy).where(Policy.name == p_def["name"]))
            if existing.scalar_one_or_none():
                continue
            policy = Policy(
                name=p_def["name"],
                description=p_def.get("description", ""),
                trigger_event=p_def["trigger"],
                conditions=p_def.get("conditions", []),
                action=ActionType(p_def["action"]),
                severity=SeverityLevel(p_def.get("severity", "MEDIUM")),
                priority=p_def.get("priority", 100),
            )
            db.add(policy)
        await db.flush()
        await self.load_policies(db)

    def evaluate(self, event_type: str, context: dict) -> list[PolicyDecision]:
        decisions = []
        for policy in self._policies:
            if not self._matches_trigger(policy.trigger_event, event_type):
                continue
            if self._evaluate_conditions(policy.conditions, context):
                decisions.append(PolicyDecision(matched=True, policy=policy, actions=[policy.action]))
        return decisions

    def _matches_trigger(self, trigger: str, event_type: str) -> bool:
        pattern = trigger.replace(".", r"\.").replace("*", ".*")
        return bool(re.fullmatch(pattern, event_type))

    def _evaluate_conditions(self, conditions: list, context: dict) -> bool:
        for cond in conditions:
            field = cond.get("field") or cond.get("path", "")
            operator = cond.get("operator", "eq")
            expected_value = cond.get("value")
            actual_value = self._resolve_field(field, context)
            if actual_value is None:
                return False
            op_func = OPERATORS.get(operator)
            if not op_func:
                return False
            if not op_func(actual_value, expected_value):
                return False
        return True

    def _resolve_field(self, field_path: str, context: dict):
        parts = field_path.split(".")
        current = context
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                current = getattr(current, part, None)
            if current is None:
                return None
        return current


policy_engine = PolicyEngine()
