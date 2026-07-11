import datetime
import secrets

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255))
    platform: Mapped[str] = mapped_column(String(64), default="unknown")
    agent_version: Mapped[str] = mapped_column(String(32), default="0.1.0")
    api_key: Mapped[str] = mapped_column(String(64), unique=True, default=lambda: secrets.token_hex(32))
    enrolled_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    isolated: Mapped[bool] = mapped_column(Boolean, default=False)
    pending_commands: Mapped[list] = mapped_column(JSON, default=list)

    events: Mapped[list["ThreatEvent"]] = relationship(back_populates="device")


class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    timestamp: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    # port_watchdog | dns_sinkhole | arp_guard | agent | isolation
    source: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16), default="info")  # info|warning|critical
    action: Mapped[str] = mapped_column(String(64))  # detected|killed|blocked|dropped|isolated|...
    summary: Mapped[str] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSON, default=dict)

    device: Mapped[Device] = relationship(back_populates="events")


class BlocklistEntry(Base):
    __tablename__ = "blocklist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    kind: Mapped[str] = mapped_column(String(16))  # domain | process | port
    value: Mapped[str] = mapped_column(String(255), unique=True)
    added_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
