"""Device inventory collector (M13).

Gathers a hardware/software/services/users snapshot using psutil + platform and
posts it to the management server. Every probe is defensive: a failure in one
section yields an empty value rather than aborting the whole report.
"""
import logging
import platform
import shutil

import psutil

log = logging.getLogger("silentguard.inventory")


def _cpu_model() -> str:
    try:
        return platform.processor() or platform.machine()
    except Exception:  # noqa: BLE001
        return ""


def _ram_total_mb() -> int:
    try:
        return int(psutil.virtual_memory().total / (1024 * 1024))
    except Exception:  # noqa: BLE001
        return 0


def _disk(path: str = "/") -> tuple[int, int]:
    try:
        total, _used, free = shutil.disk_usage(path)
        return int(total / (1024 ** 3)), int(free / (1024 ** 3))
    except Exception:  # noqa: BLE001
        return 0, 0


def _running_services(limit: int = 200) -> list[dict]:
    services = []
    try:
        for proc in psutil.process_iter(["pid", "name", "username"]):
            services.append({"pid": proc.info.get("pid"),
                             "name": proc.info.get("name") or "",
                             "user": proc.info.get("username") or ""})
            if len(services) >= limit:
                break
    except Exception:  # noqa: BLE001
        pass
    return services


def _logged_in_users() -> list[str]:
    try:
        return sorted({u.name for u in psutil.users()})
    except Exception:  # noqa: BLE001
        return []


def collect_inventory() -> dict:
    """Return an inventory report dict matching the server's InventoryReport."""
    disk_total, disk_free = _disk()
    return {
        "os_version": f"{platform.system()} {platform.release()}".strip(),
        "kernel": platform.version(),
        "cpu_model": _cpu_model(),
        "cpu_count": psutil.cpu_count(logical=True) or 0,
        "ram_total_mb": _ram_total_mb(),
        "disk_total_gb": disk_total,
        "disk_free_gb": disk_free,
        # Installed-software enumeration is OS-specific and expensive; left to
        # the OS adapters (M11/M12). Running processes stand in as services here.
        "installed_software": [],
        "running_services": _running_services(),
        "logged_in_users": _logged_in_users(),
    }
