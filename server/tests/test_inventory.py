"""Tests for M13: device inventory + posture."""
from tests.conftest import ADMIN_HEADERS


def _report(**over):
    base = {
        "os_version": "Ubuntu 22.04", "kernel": "6.8.0", "cpu_model": "x86_64",
        "cpu_count": 8, "ram_total_mb": 16000, "disk_total_gb": 500, "disk_free_gb": 250,
        "installed_software": [{"name": "openssl", "version": "3.0"}],
        "running_services": [{"pid": 1, "name": "systemd", "user": "root"}],
        "logged_in_users": ["alice"],
    }
    base.update(over)
    return base


def test_inventory_report_and_read(client, enrolled_device):
    r = client.post("/api/agent/inventory", json=_report(), headers=enrolled_device["headers"])
    assert r.status_code == 200
    assert r.json()["health"] == "healthy"

    inv = client.get(f"/api/admin/devices/{enrolled_device['device_id']}/inventory",
                     headers=ADMIN_HEADERS).json()
    assert inv["os_version"] == "Ubuntu 22.04"
    assert inv["cpu_count"] == 8
    assert inv["logged_in_users"] == ["alice"]
    assert inv["hostname"] == "test-vm"
    assert inv["posture"]["disk_free_pct"] == 50


def test_low_disk_marks_degraded(client, enrolled_device):
    client.post("/api/agent/inventory",
                json=_report(disk_total_gb=500, disk_free_gb=10),  # 2% free
                headers=enrolled_device["headers"])
    inv = client.get(f"/api/admin/devices/{enrolled_device['device_id']}/inventory",
                     headers=ADMIN_HEADERS).json()
    assert inv["health"] == "degraded"
    assert "disk_ok" in inv["posture"]["issues"]


def test_inventory_upsert_keeps_one_row(client, enrolled_device):
    client.post("/api/agent/inventory", json=_report(cpu_count=4),
                headers=enrolled_device["headers"])
    client.post("/api/agent/inventory", json=_report(cpu_count=16),
                headers=enrolled_device["headers"])
    inv = client.get(f"/api/admin/devices/{enrolled_device['device_id']}/inventory",
                     headers=ADMIN_HEADERS).json()
    assert inv["cpu_count"] == 16  # latest wins


def test_inventory_404_before_report(client, enrolled_device):
    r = client.get(f"/api/admin/devices/{enrolled_device['device_id']}/inventory",
                   headers=ADMIN_HEADERS)
    assert r.status_code == 404


def test_inventory_requires_admin(client, enrolled_device):
    assert client.get(f"/api/admin/devices/{enrolled_device['device_id']}/inventory").status_code == 401
