"""USB guard tests with a fake backend + a sysfs backend against a fake tree."""
from silentguard_agent.monitors.usb_guard import LinuxSysfsBackend, UsbGuard


class FakeBackend:
    def __init__(self, devices=None):
        self.devices = devices or []
        self.blocked = []
        self.block_result = True

    def list_usb_storage(self):
        return list(self.devices)

    def block(self, device):
        self.blocked.append(device["id"])
        return self.block_result


def stick(dev_id="sdb:SER123:Cruzer", vendor="SanDisk", model="Cruzer", serial="SER123"):
    return {"id": dev_id, "node": "sdb", "vendor": vendor, "model": model, "serial": serial}


def test_baseline_devices_are_silent(config, telemetry):
    backend = FakeBackend([stick()])
    guard = UsbGuard(config, telemetry, backend)
    guard.scan()
    assert telemetry.events == []


def test_insertion_emits_warning(config, telemetry):
    backend = FakeBackend()
    guard = UsbGuard(config, telemetry, backend)
    guard.scan()  # baseline (empty)
    backend.devices = [stick()]
    guard.scan()
    inserted = telemetry.by_action("usb_inserted")
    assert len(inserted) == 1
    assert inserted[0]["severity"] == "warning"
    assert "SanDisk Cruzer" in inserted[0]["summary"]
    # No duplicate on subsequent scans
    guard.scan()
    assert len(telemetry.by_action("usb_inserted")) == 1


def test_removal_emits_info(config, telemetry):
    backend = FakeBackend([stick()])
    guard = UsbGuard(config, telemetry, backend)
    guard.scan()  # baseline with device present
    backend.devices = []
    guard.scan()
    removed = telemetry.by_action("usb_removed")
    assert len(removed) == 1
    assert removed[0]["severity"] == "info"


def test_block_policy(config, telemetry):
    config.block_usb_storage = True
    config.dry_run = False
    backend = FakeBackend()
    guard = UsbGuard(config, telemetry, backend)
    guard.scan()
    backend.devices = [stick()]
    guard.scan()
    assert backend.blocked == ["sdb:SER123:Cruzer"]
    blocked = telemetry.by_action("usb_blocked")
    assert len(blocked) == 1
    assert blocked[0]["severity"] == "critical"


def test_block_failure_reported(config, telemetry):
    config.block_usb_storage = True
    config.dry_run = False
    backend = FakeBackend()
    backend.block_result = False
    guard = UsbGuard(config, telemetry, backend)
    guard.scan()
    backend.devices = [stick()]
    guard.scan()
    assert len(telemetry.by_action("usb_block_failed")) == 1


def test_no_backend_is_noop(config, telemetry):
    guard = UsbGuard(config, telemetry, backend=False)  # falsy but not None
    guard.backend = None
    guard.scan()
    assert telemetry.events == []


def test_sysfs_backend_lists_removable_devices(tmp_path):
    # Fake /sys/block: sda fixed disk, sdb removable USB stick
    for name, removable in (("sda", "0"), ("sdb", "1")):
        d = tmp_path / name
        (d / "device").mkdir(parents=True)
        (d / "removable").write_text(f"{removable}\n")
        (d / "device" / "vendor").write_text("SanDisk\n")
        (d / "device" / "model").write_text("Cruzer Blade\n")
        (d / "device" / "serial").write_text("4C5300\n")
    backend = LinuxSysfsBackend(sys_block=tmp_path)
    devices = backend.list_usb_storage()
    assert len(devices) == 1
    assert devices[0]["node"] == "sdb"
    assert devices[0]["vendor"] == "SanDisk"
    assert devices[0]["serial"] == "4C5300"
