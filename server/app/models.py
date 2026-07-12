import datetime
import secrets

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


# Well-known id of the organization every pre-multi-tenancy row is backfilled
# into, and the default org new devices/users join. Its presence makes the
# single-tenant demo behave exactly as before M6.
DEFAULT_ORG_ID = "00000000000000000000000000000001"


class Organization(Base):
    """A tenant. All domain data is scoped to an organization (M6)."""

    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: secrets.token_hex(16))
    name: Mapped[str] = mapped_column(String(255))
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"), index=True, nullable=True)
    hostname: Mapped[str] = mapped_column(String(255))
    platform: Mapped[str] = mapped_column(String(64), default="unknown")
    agent_version: Mapped[str] = mapped_column(String(32), default="0.1.0")
    api_key: Mapped[str] = mapped_column(String(64), unique=True, default=lambda: secrets.token_hex(32))
    enrolled_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    isolated: Mapped[bool] = mapped_column(Boolean, default=False)
    pending_commands: Mapped[list] = mapped_column(JSON, default=list)
    # Tamper-resilience bookkeeping: set when the agent reports a clean stop,
    # and to avoid emitting duplicate "device_unresponsive" alerts.
    stopped: Mapped[bool] = mapped_column(Boolean, default=False)
    unresponsive_alerted: Mapped[bool] = mapped_column(Boolean, default=False)

    events: Mapped[list["ThreatEvent"]] = relationship(back_populates="device")


class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"), index=True, nullable=True)
    timestamp: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    # port_watchdog | dns_sinkhole | arp_guard | agent | isolation
    source: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16), default="info")  # info|warning|critical
    action: Mapped[str] = mapped_column(String(64))  # detected|killed|blocked|dropped|isolated|...
    summary: Mapped[str] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSON, default=dict)

    device: Mapped[Device] = relationship(back_populates="events")


class QuarantineItem(Base):
    """Fleet-wide view of files agents have quarantined. Rows are created and
    updated from agent telemetry (source=quarantine/file_drop); restores are
    requested from the dashboard and executed by the agent on next check-in."""

    __tablename__ = "quarantine_items"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # agent-side quarantine id
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"), index=True, nullable=True)
    original_path: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64), default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    verdict: Mapped[str] = mapped_column(String(16), default="unknown")  # known_bad|unknown
    # quarantined | restore_requested | restored
    status: Mapped[str] = mapped_column(String(24), default="quarantined")
    quarantined_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    restored_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class User(Base):
    """Dashboard/admin user account (M4). Replaces the single shared admin
    token as the identity model; the legacy token remains accepted during the
    transition."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(secrets.token_hex(16)))
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"), index=True, nullable=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="read_only")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Account-lockout bookkeeping.
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[datetime.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RefreshToken(Base):
    """Server-side record of an issued refresh token, keyed by its JWT ``jti``,
    so individual sessions can be revoked (logout, rotation)."""

    __tablename__ = "refresh_tokens"

    jti: Mapped[str] = mapped_column(String(32), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLogEntry(Base):
    """Immutable record of every admin action (isolate, release, blocklist
    add/remove, quarantine restore) with the acting token's fingerprint."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"), index=True, nullable=True)
    timestamp: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(32))  # admin token fingerprint
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(255), default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class BlocklistEntry(Base):
    __tablename__ = "blocklist"
    # Uniqueness is per-organization: the same value may be blocked in several
    # tenants independently.
    __table_args__ = (UniqueConstraint("org_id", "value", name="uq_blocklist_org_value"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id"), index=True, nullable=True)
    kind: Mapped[str] = mapped_column(String(16))  # domain | process | port
    value: Mapped[str] = mapped_column(String(255))
    added_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
