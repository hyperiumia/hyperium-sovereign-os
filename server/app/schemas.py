from pydantic import ConfigDict,  BaseModel, Field
from datetime import datetime
from typing import Optional
from app.models import SeverityLevel, ActionType, WorkspaceClassification


class AgentEvent(BaseModel):
    agent_id: str
    device_id: str
    session_id: Optional[str] = None
    event_type: str
    source_module: str
    payload: dict
    severity: SeverityLevel = SeverityLevel.LOW
    timestamp: datetime
    event_hash: str
    hmac_signature: str


class AgentEventBatch(BaseModel):
    events: list[AgentEvent]


class PolicyCondition(BaseModel):
    field: str
    operator: str
    value: str | int | float | bool


class PolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    trigger_event: str
    conditions: list[PolicyCondition]
    action: ActionType
    severity: SeverityLevel = SeverityLevel.MEDIUM
    priority: int = 100


class PolicyResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    trigger_event: str
    conditions: list[dict]
    action: str
    severity: str
    is_enabled: bool
    priority: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class WorkspaceCreate(BaseModel):
    name: str
    description: Optional[str] = None
    classification: WorkspaceClassification = WorkspaceClassification.INTERNAL
    is_air_gapped: bool = False
    allow_usb: bool = False
    allow_network: bool = True
    allow_print: bool = False
    max_session_hours: int = 8


class WorkspaceResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    classification: str
    is_air_gapped: bool
    allow_usb: bool
    allow_network: bool
    allow_print: bool
    is_active: bool
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class AlertResponse(BaseModel):
    id: str
    event_id: str
    user_id: Optional[str]
    severity: str
    status: str
    title: str
    description: Optional[str]
    action_taken: Optional[str]
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)
