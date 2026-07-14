"""Shared time helpers.

`aware_utc` replaces three near-identical private `_aware` helpers that had
drifted into `scoring.py`, `monitor.py`, and `routers/admin.py` (Audit §14):
SQLite returns naive datetimes even for ``DateTime(timezone=True)`` columns, so
values read back from the DB must be coerced to UTC-aware before arithmetic.
"""
import datetime


def aware_utc(dt: datetime.datetime) -> datetime.datetime:
    """Return `dt` as a UTC-aware datetime, assuming UTC if it is naive."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=datetime.timezone.utc)
