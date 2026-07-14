"""Agent inventory collector tests (psutil mocked — no real system probing)."""
from unittest.mock import MagicMock, patch

from silentguard_agent import inventory


def test_collect_inventory_shape():
    with patch("silentguard_agent.inventory.psutil") as ps, \
         patch("silentguard_agent.inventory.shutil.disk_usage", return_value=(500 * 1024**3, 0, 250 * 1024**3)), \
         patch("silentguard_agent.inventory.platform") as plat:
        plat.system.return_value = "Linux"
        plat.release.return_value = "6.8.0"
        plat.version.return_value = "#1 SMP"
        plat.processor.return_value = "x86_64"
        ps.virtual_memory.return_value = MagicMock(total=16 * 1024**3)
        ps.cpu_count.return_value = 8
        ps.process_iter.return_value = [
            MagicMock(info={"pid": 1, "name": "systemd", "username": "root"})
        ]
        ps.users.return_value = [MagicMock(name="ignored")]
        # MagicMock(name=...) sets the mock's name, not .name attr; set explicitly
        u = MagicMock()
        u.name = "alice"
        ps.users.return_value = [u]

        report = inventory.collect_inventory()

    assert report["os_version"] == "Linux 6.8.0"
    assert report["cpu_count"] == 8
    assert report["ram_total_mb"] == 16 * 1024
    assert report["disk_total_gb"] == 500 and report["disk_free_gb"] == 250
    assert report["running_services"][0]["name"] == "systemd"
    assert report["logged_in_users"] == ["alice"]


def test_collect_inventory_is_defensive_on_probe_failure():
    with patch("silentguard_agent.inventory.psutil") as ps, \
         patch("silentguard_agent.inventory.shutil.disk_usage", side_effect=OSError), \
         patch("silentguard_agent.inventory.platform") as plat:
        plat.system.return_value = "Linux"
        plat.release.return_value = "6"
        plat.version.return_value = ""
        plat.processor.side_effect = Exception("boom")
        ps.virtual_memory.side_effect = Exception("boom")
        ps.cpu_count.return_value = None
        ps.process_iter.side_effect = Exception("boom")
        ps.users.side_effect = Exception("boom")

        report = inventory.collect_inventory()

    # Failures degrade to empty/zero values instead of raising.
    assert report["cpu_model"] == ""
    assert report["ram_total_mb"] == 0
    assert report["disk_total_gb"] == 0
    assert report["running_services"] == []
    assert report["logged_in_users"] == []
