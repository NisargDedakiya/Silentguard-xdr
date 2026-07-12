"""Unit tests for the M3 shared services/utils."""
import datetime

from app.services import events
from app.utils.time import aware_utc


def test_aware_utc_coerces_naive():
    naive = datetime.datetime(2026, 1, 1, 12, 0, 0)
    out = aware_utc(naive)
    assert out.tzinfo == datetime.timezone.utc


def test_aware_utc_preserves_aware():
    aware = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    assert aware_utc(aware) is aware


class _Row:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def _sample(**over):
    base = dict(id=7, device_id="dev-1", timestamp="2026-01-01T00:00:00Z",
                source="port_watchdog", severity="critical", action="killed",
                summary="killed nc", details={"port": 4444})
    base.update(over)
    return base


def test_broadcast_payload_from_orm_object_attaches_mitre():
    payload = events.broadcast_payload(_Row(**_sample()), "vm-1")
    assert payload["type"] == "threat_event"
    assert payload["hostname"] == "vm-1"
    assert payload["mitre"]["id"] == "T1059"
    assert payload["details"] == {"port": 4444}


def test_broadcast_payload_from_mapping():
    payload = events.broadcast_payload(_sample(), "vm-2")
    assert payload["id"] == 7
    assert payload["device_id"] == "dev-1"


def test_event_out_shape_and_none_details():
    out = events.event_out(_Row(**_sample(details=None)), "vm-3")
    assert out.hostname == "vm-3"
    assert out.details == {}
    assert out.mitre["id"] == "T1059"


def test_event_out_unmapped_source_has_no_mitre():
    out = events.event_out(_Row(**_sample(source="agent", action="started")), "vm")
    assert out.mitre is None
