"""Tests for M17 visibility & analytics endpoints."""
from tests.conftest import ADMIN_HEADERS


def _seed_events(client, headers):
    events = [
        {"source": "port_watchdog", "action": "killed", "severity": "critical",
         "summary": "killed", "details": {"port": 4444, "pid": 200, "ppid": 100, "process": "nc"}},
        {"source": "usb_guard", "action": "usb_inserted", "severity": "warning",
         "summary": "usb in", "details": {"vendor": "SanDisk"}},
        {"source": "dns_sinkhole", "action": "blocked", "severity": "warning",
         "summary": "blocked", "details": {"domain": "bad.example"}},
        {"source": "agent", "action": "heartbeat", "severity": "info", "summary": "hb"},
    ]
    return client.post("/api/agent/telemetry", json={"events": events}, headers=headers)


def test_summary(client, enrolled_device):
    _seed_events(client, enrolled_device["headers"])
    s = client.get("/api/admin/analytics/summary", headers=ADMIN_HEADERS).json()
    assert s["devices"] == 1
    assert s["events"] >= 4
    assert s["detections"] >= 1  # port_watchdog kill → reverse_shell detection
    assert s["open_critical"] >= 1
    assert "critical" in s["detections_by_severity"]


def test_events_by_day(client, enrolled_device):
    _seed_events(client, enrolled_device["headers"])
    days = client.get("/api/admin/analytics/events-by-day?days=7", headers=ADMIN_HEADERS).json()
    assert len(days) == 7
    today = days[-1]
    assert today["critical"] >= 1 and today["warning"] >= 2


def test_top_devices(client, enrolled_device):
    _seed_events(client, enrolled_device["headers"])
    top = client.get("/api/admin/analytics/top-devices", headers=ADMIN_HEADERS).json()
    assert top and top[0]["device_id"] == enrolled_device["device_id"]
    assert top[0]["risk"] >= 90  # critical detection risk


def test_mitre_coverage(client, enrolled_device):
    _seed_events(client, enrolled_device["headers"])
    cov = client.get("/api/admin/analytics/mitre-coverage", headers=ADMIN_HEADERS).json()
    assert any(c["technique_id"] == "T1059" for c in cov)


def test_timeline_category(client, enrolled_device):
    _seed_events(client, enrolled_device["headers"])
    usb = client.get("/api/admin/analytics/timeline?category=usb", headers=ADMIN_HEADERS).json()
    assert len(usb) == 1 and usb[0]["source"] == "usb_guard"
    net = client.get("/api/admin/analytics/timeline?category=network", headers=ADMIN_HEADERS).json()
    assert {e["source"] for e in net} <= {"arp_guard", "dns_sinkhole", "port_watchdog"}


def test_timeline_unknown_category_400(client):
    assert client.get("/api/admin/analytics/timeline?category=bogus",
                      headers=ADMIN_HEADERS).status_code == 400


def test_process_tree(client, enrolled_device):
    _seed_events(client, enrolled_device["headers"])
    tree = client.get(
        f"/api/admin/analytics/process-tree?device_id={enrolled_device['device_id']}",
        headers=ADMIN_HEADERS).json()
    # pid 200 present; its ppid 100 is not a known node, so 200 is a root.
    assert any(n["pid"] == 200 for n in tree)


def test_analytics_requires_auth(client):
    assert client.get("/api/admin/analytics/summary").status_code == 401
