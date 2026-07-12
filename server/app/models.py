import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Float, Boolean, DateTime, Integer,
    Text, ForeignKey, Enum as SAEnum, JSON, LargeBinary,
    Index, UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, relationship
import enum


def utcnow():
    return datetime.now(timezone.utc)


def gen_uuid():
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class SeverityLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ActionType(str, enum.Enum):
    LOG = "LOG"
    ALERT = "ALERT"
    BLOCK = "BLOCK"
    FREEZE = "FREEZE"
    ALERT_AND_FREEZE = "ALERT_AND_FREEZE"
    ISOLATE = "ISOLATE"


class SessionStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    FROZEN = "FROZEN"
    ISOLATED = "ISOLATED"
    TERMINATED = "TERMINATED"


class WorkspaceClassification(str, enum.Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    TOP_SECRET = "TOP_SECRET"


class AlertStatus(str, enum.Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    ESCALATED = "ESCALATED"


class EvidenceType(str, enum.Enum):
    EVENT_LOG = "EVENT_LOG"
    MEMORY_DUMP = "MEMORY_DUMP"
    NETWORK_CAPTURE = "NETWORK_CAPTURE"
    FILE_SNAPSHOT = "FILE_SNAPSHOT"
    POLICY_DECISION = "POLICY_DECISION"


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=gen_uuid)
    username = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False)
    role = Column(String(100), nullable=False, default="EMPLOYEE")
    department = Column(String(255))
    risk_score = Column(Float, default=0.0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    sessions = relationship("Session", back_populates="user")
    alerts = relationship("Alert", back_populates="user")


class Device(Base):
    __tablename__ = "devices"
    id = Column(String, primary_key=True, default=gen_uuid)
    hostname = Column(String(255), nullable=False)
    mac_address = Column(String(17), unique=True)
    os_type = Column(String(50))
    agent_version = Column(String(50))
    is_trusted = Column(Boolean, default=False)
    last_seen = Column(DateTime)
    created_at = Column(DateTime, default=utcnow)
    sessions = relationship("Session", back_populates="device")


class Session(Base):
    __tablename__ = "sessions"
    id = Column(String, primary_key=True, default=gen_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False)
    workspace_id = Column(String, ForeignKey("workspaces.id"))
    status = Column(SAEnum(SessionStatus), default=SessionStatus.ACTIVE)
    risk_score = Column(Float, default=0.0)
    data_volume_bytes = Column(Integer, default=0)
    started_at = Column(DateTime, default=utcnow)
    ended_at = Column(DateTime, nullable=True)
    freeze_reason = Column(Text, nullable=True)
    user = relationship("User", back_populates="sessions")
    device = relationship("Device", back_populates="sessions")
    workspace = relationship("Workspace", back_populates="sessions")
    events = relationship("Event", back_populates="session")


class Workspace(Base):
    __tablename__ = "workspaces"
    id = Column(String, primary_key=True, default=gen_uuid)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    classification = Column(SAEnum(WorkspaceClassification), default=WorkspaceClassification.INTERNAL)
    is_air_gapped = Column(Boolean, default=False)
    allow_usb = Column(Boolean, default=False)
    allow_network = Column(Boolean, default=True)
    allow_print = Column(Boolean, default=False)
    max_session_hours = Column(Integer, default=8)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    sessions = relationship("Session", back_populates="workspace")
    assets = relationship("Asset", back_populates="workspace")


class Asset(Base):
    __tablename__ = "assets"
    id = Column(String, primary_key=True, default=gen_uuid)
    workspace_id = Column(String, ForeignKey("workspaces.id"), nullable=False)
    name = Column(String(255), nullable=False)
    asset_type = Column(String(100))
    classification = Column(SAEnum(WorkspaceClassification))
    fingerprint = Column(String(64))
    watermark_id = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=utcnow)
    workspace = relationship("Workspace", back_populates="assets")


class Policy(Base):
    __tablename__ = "policies"
    id = Column(String, primary_key=True, default=gen_uuid)
    name = Column(String(255), unique=True, nullable=False)
    description = Column(Text)
    trigger_event = Column(String(255), nullable=False, index=True)
    conditions = Column(JSON, nullable=False)
    action = Column(SAEnum(ActionType), nullable=False)
    severity = Column(SAEnum(SeverityLevel), default=SeverityLevel.MEDIUM)
    is_enabled = Column(Boolean, default=True)
    priority = Column(Integer, default=100)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class Event(Base):
    __tablename__ = "events"
    id = Column(String, primary_key=True, default=gen_uuid)
    session_id = Column(String, ForeignKey("sessions.id"), index=True)
    event_type = Column(String(255), nullable=False, index=True)
    source_module = Column(String(100))
    payload = Column(JSON, nullable=False)
    severity = Column(SAEnum(SeverityLevel), default=SeverityLevel.LOW)
    event_hash = Column(String(64), nullable=False)
    hmac_signature = Column(String(64), nullable=False)
    merkle_epoch = Column(Integer, nullable=True, index=True)
    merkle_leaf_index = Column(Integer, nullable=True)
    merkle_root_hash = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=utcnow, index=True)
    session = relationship("Session", back_populates="events")
    __table_args__ = (Index("ix_events_type_created", "event_type", "created_at"),)


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(String, primary_key=True, default=gen_uuid)
    event_id = Column(String, ForeignKey("events.id"), nullable=False)
    user_id = Column(String, ForeignKey("users.id"), index=True)
    policy_id = Column(String, ForeignKey("policies.id"))
    severity = Column(SAEnum(SeverityLevel), nullable=False)
    status = Column(SAEnum(AlertStatus), default=AlertStatus.OPEN)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    action_taken = Column(SAEnum(ActionType))
    assigned_to = Column(String(255), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    user = relationship("User", back_populates="alerts")
    event = relationship("Event")
    policy = relationship("Policy")


class EvidenceItem(Base):
    __tablename__ = "evidence_items"
    id = Column(String, primary_key=True, default=gen_uuid)
    case_id = Column(String, ForeignKey("forensic_cases.id"), index=True)
    evidence_type = Column(SAEnum(EvidenceType), nullable=False)
    event_id = Column(String, ForeignKey("events.id"))
    hash_sha256 = Column(String(64), nullable=False)
    storage_path = Column(String(1024))
    merkle_proof = Column(JSON, nullable=True)
    description = Column(Text)
    collected_at = Column(DateTime, default=utcnow)
    collected_by = Column(String(255))
    case = relationship("ForensicCase", back_populates="evidence_items")


class ForensicCase(Base):
    __tablename__ = "forensic_cases"
    id = Column(String, primary_key=True, default=gen_uuid)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    related_alert_id = Column(String, ForeignKey("alerts.id"), nullable=True)
    status = Column(String(50), default="OPEN")
    lead_analyst = Column(String(255))
    created_at = Column(DateTime, default=utcnow)
    closed_at = Column(DateTime, nullable=True)
    evidence_items = relationship("EvidenceItem", back_populates="case")


class AccessGrant(Base):
    __tablename__ = "access_grants"
    id = Column(String, primary_key=True, default=gen_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    workspace_id = Column(String, ForeignKey("workspaces.id"), nullable=False)
    granted_by = Column(String(255), nullable=False)
    reason = Column(Text)
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    revoke_reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)


class Revocation(Base):
    __tablename__ = "revocations"
    id = Column(String, primary_key=True, default=gen_uuid)
    grant_id = Column(String, ForeignKey("access_grants.id"), nullable=False)
    revoked_by = Column(String(255), nullable=False)
    reason = Column(Text)
    revoked_at = Column(DateTime, default=utcnow)


class MerkleEpoch(Base):
    __tablename__ = "merkle_epochs"
    epoch_number = Column(Integer, primary_key=True)
    root_hash = Column(String(64), nullable=False)
    leaf_count = Column(Integer, nullable=False)
    signature = Column(Text, nullable=False)
    signed_by = Column(String(255), nullable=False)
    external_timestamp_token = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)
