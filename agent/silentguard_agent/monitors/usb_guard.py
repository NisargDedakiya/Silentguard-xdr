"""USB storage guard — detects USB mass-storage insertion/removal.

Backends:
- Linux: pyudev when installed, otherwise a /sys/block sysfs poller (no
  extra dependency).
- Windows: WMI (pywin32/wmi package) enumeration of USB disk drives.
- Tests inject a fake backend.

Events are emitted on insert (warning) and removal (info). With the
`block_usb_storage` policy enabled, newly inserted devices are blocked
best-effort (Linux: de-authorize via sysfs; Windows: disable the USBSTOR
service) and a critical event is emitted.
"""
import logging
import platform
from pathlib import Path

from ..config import AgentConfig
from ..telemetry import TelemetryClient

log = logging.getLogger("silentguard.usb_guard")


class LinuxSysfsBackend:
    """Polls /sys/block for removable USB-attached disks. Dependency-free."""

    def __init__(self, sys_block: Path = Path("/sys/block")):
        self.sys_block = sys_block

    @staticmethod
    def _read(path: Path) -> str:
        try:
            return path.read_text().strip()
        except OSError:
            return ""

    def list_usb_storage(self) -> list[dict]:
        devices = []
        try:
            entries = list(self.sys_block.iterdir())
        except OSError:
            return devices
        for entry in entries:
            if self._read(entry / "removable") != "1":
                continue
            dev_dir = entry / "device"
            vendor = self._read(dev_dir / "vendor")
            model = self._read(dev_dir / "model")
            serial = self._read(dev_dir / "serial")
            devices.append(
                {
                    "id": f"{entry.name}:{serial or vendor}:{model}",
                    "node": entry.name,
                    "vendor": vendor,
                    "model": model,
                    "serial": serial,
                }
            )
        return devices

    def block(self, device: dict) -> bool:
        """De-authorize the underlying USB device via sysfs (best effort)."""
        try:
            # /sys/block/sdX resolves into the USB device hierarchy; walk up
            # until a directory with an `authorized` attribute is found.
            real = (self.sys_block / device["node"]).resolve()
            for parent in real.parents:
                auth = parent / "authorized"
                if auth.exists():
                    auth.write_text("0")
                    return True
        except OSError as exc:
            log.warning("Failed to block USB device %s: %s", device.get("id"), exc)
        return False


class PyudevBackend:
    """Linux enumeration via pyudev (preferred when installed)."""

    def __init__(self):
        import pyudev  # noqa: F401 — raises ImportError if unavailable

        self._pyudev = pyudev
        self._context = pyudev.Context()
        self._sysfs = LinuxSysfsBackend()

    def list_usb_storage(self) -> list[dict]:
        devices = []
        for dev in self._context.list_devices(subsystem="block", DEVTYPE="disk"):
            usb = dev.find_parent("usb", "usb_device")
            if usb is None:
                continue
            devices.append(
                {
                    "id": f"{dev.sys_name}:{usb.get('ID_SERIAL_SHORT', '')}:"
                          f"{usb.get('ID_MODEL', '')}",
                    "node": dev.sys_name,
                    "vendor": usb.get("ID_VENDOR", ""),
                    "model": usb.get("ID_MODEL", ""),
                    "serial": usb.get("ID_SERIAL_SHORT", ""),
                }
            )
        return devices

    def block(self, device: dict) -> bool:
        return self._sysfs.block(device)


class WindowsWmiBackend:
    """Windows enumeration via the wmi package (pywin32)."""

    def __init__(self):
        import wmi  # noqa: F401 — raises ImportError if unavailable

        self._wmi = wmi.WMI()

    def list_usb_storage(self) -> list[dict]:
        devices = []
        try:
            for disk in self._wmi.Win32_DiskDrive(InterfaceType="USB"):
                devices.append(
                    {
                        "id": f"{disk.DeviceID}:{disk.SerialNumber or ''}",
                        "node": disk.DeviceID,
                        "vendor": (disk.Manufacturer or "").strip(),
                        "model": (disk.Model or "").strip(),
                        "serial": (disk.SerialNumber or "").strip(),
                    }
                )
        except Exception as exc:  # noqa: BLE001 — WMI raises COM errors
            log.warning("WMI USB enumeration failed: %s", exc)
        return devices

    def block(self, device: dict) -> bool:
        """Disable the USBSTOR driver (affects new mounts; needs admin)."""
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\USBSTOR",
                0,
                winreg.KEY_SET_VALUE,
            )
            winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 4)
            winreg.CloseKey(key)
            return True
        except OSError as exc:
            log.warning("Failed to disable USBSTOR: %s", exc)
            return False


def pick_backend():
    if platform.system() == "Windows":
        try:
            return WindowsWmiBackend()
        except ImportError:
            log.warning("wmi/pywin32 not installed — USB monitoring disabled")
            return None
    try:
        return PyudevBackend()
    except ImportError:
        return LinuxSysfsBackend()


class UsbGuard:
    def __init__(self, config: AgentConfig, telemetry: TelemetryClient, backend=None):
        self.config = config
        self.telemetry = telemetry
        self.backend = backend if backend is not None else pick_backend()
        self._known: dict[str, dict] = {}
        self._baselined = False

    def _describe(self, dev: dict) -> str:
        label = " ".join(x for x in (dev.get("vendor"), dev.get("model")) if x) or "USB storage"
        serial = dev.get("serial") or "no serial"
        return f"{label} ({serial})"

    def scan(self) -> None:
        if self.backend is None:
            return
        current = {d["id"]: d for d in self.backend.list_usb_storage()}
        if not self._baselined:
            # Devices already present at agent start are recorded silently.
            self._known = current
            self._baselined = True
            return
        for dev_id, dev in current.items():
            if dev_id in self._known:
                continue
            self.telemetry.emit(
                source="usb_guard",
                action="usb_inserted",
                severity="warning",
                summary=f"USB mass-storage device inserted: {self._describe(dev)}",
                details=dev,
            )
            if self.config.block_usb_storage:
                blocked = False
                if self.config.dry_run:
                    log.info("[dry-run] would block USB device %s", dev_id)
                    blocked = True
                else:
                    blocked = self.backend.block(dev)
                self.telemetry.emit(
                    source="usb_guard",
                    action="usb_blocked" if blocked else "usb_block_failed",
                    severity="critical",
                    summary=f"USB storage policy: {self._describe(dev)} "
                            f"{'blocked' if blocked else 'could not be blocked'}",
                    details=dev,
                )
        for dev_id, dev in self._known.items():
            if dev_id not in current:
                self.telemetry.emit(
                    source="usb_guard",
                    action="usb_removed",
                    severity="info",
                    summary=f"USB mass-storage device removed: {self._describe(dev)}",
                    details=dev,
                )
        self._known = current
