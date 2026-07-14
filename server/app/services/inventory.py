"""Device inventory + security-posture service (M13)."""
from ..core.logging import get_logger
from ..models import Device, DeviceInventory, utcnow

log = get_logger("silentguard.inventory")

CURRENT_AGENT_VERSION = "0.1.0"
LOW_DISK_PCT = 10  # free-disk percentage below which posture flags low_disk


def compute_posture(device: Device, report) -> tuple[str, dict]:
    """Derive a coarse health + posture summary from a report and device state."""
    checks: dict[str, bool] = {}
    disk_free_pct = 0
    if report.disk_total_gb:
        disk_free_pct = round(100 * report.disk_free_gb / report.disk_total_gb)
    checks["disk_ok"] = disk_free_pct >= LOW_DISK_PCT if report.disk_total_gb else True
    checks["agent_up_to_date"] = device.agent_version == CURRENT_AGENT_VERSION
    checks["not_isolated"] = not device.isolated
    posture = {
        "disk_free_pct": disk_free_pct,
        "checks": checks,
        "issues": [k for k, ok in checks.items() if not ok],
    }
    health = "healthy" if all(checks.values()) else "degraded"
    return health, posture


def upsert_inventory(db, device: Device, report) -> DeviceInventory:
    inv = db.get(DeviceInventory, device.id)
    if inv is None:
        inv = DeviceInventory(device_id=device.id)
        db.add(inv)
    inv.org_id = device.org_id
    inv.os_version = report.os_version
    inv.kernel = report.kernel
    inv.cpu_model = report.cpu_model
    inv.cpu_count = report.cpu_count
    inv.ram_total_mb = report.ram_total_mb
    inv.disk_total_gb = report.disk_total_gb
    inv.disk_free_gb = report.disk_free_gb
    inv.installed_software = report.installed_software
    inv.running_services = report.running_services
    inv.logged_in_users = report.logged_in_users
    inv.health, inv.posture = compute_posture(device, report)
    inv.updated_at = utcnow()
    return inv
