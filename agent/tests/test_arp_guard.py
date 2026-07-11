"""ARP guard tests with mocked gateway/ARP-table reads — no subprocess calls
reach the real OS (dry-run blocks the firewall action)."""
from unittest.mock import patch

from silentguard_agent.monitors.arp_guard import ArpGuard

GW = "192.168.1.1"
ROUTER_MAC = "aa:bb:cc:dd:ee:ff"
ATTACKER_MAC = "11:22:33:44:55:66"


def scan(guard, gateway, table):
    with patch("silentguard_agent.monitors.arp_guard.default_gateway", return_value=gateway), \
         patch("silentguard_agent.monitors.arp_guard.arp_table", return_value=table):
        guard.scan()


def test_first_sighting_pins_gateway_mac(config, telemetry):
    guard = ArpGuard(config, telemetry)
    scan(guard, GW, {GW: ROUTER_MAC})
    assert guard.gateway_ip == GW
    assert guard.trusted_mac == ROUTER_MAC
    assert telemetry.events == []  # trust-on-first-use, no alert


def test_stable_gateway_stays_silent(config, telemetry):
    guard = ArpGuard(config, telemetry)
    scan(guard, GW, {GW: ROUTER_MAC})
    scan(guard, GW, {GW: ROUTER_MAC})
    assert telemetry.events == []


def test_mac_change_triggers_critical_drop(config, telemetry):
    guard = ArpGuard(config, telemetry)
    scan(guard, GW, {GW: ROUTER_MAC})
    scan(guard, GW, {GW: ATTACKER_MAC})
    dropped = telemetry.by_action("dropped")
    assert len(dropped) == 1
    assert dropped[0]["severity"] == "critical"
    assert dropped[0]["details"] == {
        "gateway": GW,
        "trusted_mac": ROUTER_MAC,
        "spoofed_mac": ATTACKER_MAC,
    }


def test_new_network_re_pins_without_alert(config, telemetry):
    guard = ArpGuard(config, telemetry)
    scan(guard, GW, {GW: ROUTER_MAC})
    # Device moved to a different network: new gateway IP → re-pin, no alert
    scan(guard, "10.0.0.1", {"10.0.0.1": ATTACKER_MAC})
    assert guard.trusted_mac == ATTACKER_MAC
    assert telemetry.events == []


def test_no_gateway_or_no_arp_entry_is_noop(config, telemetry):
    guard = ArpGuard(config, telemetry)
    scan(guard, None, {})
    scan(guard, GW, {})  # gateway known but not yet in ARP cache
    assert telemetry.events == []
    assert guard.gateway_ip is None
