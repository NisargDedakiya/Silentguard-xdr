"""Tests for the SilentGuard Home enforcement core (no GUI, no real OS calls)."""
import json

import pytest

from silentguard_home.blocklist import Blocklist, normalize
from silentguard_home.enforcement import FirewallBlocker, ProcessGuard, resolve_ips
from silentguard_home.engine import ProtectionEngine, apply_hosts


# -- blocklist ------------------------------------------------------------
def test_normalize():
    assert normalize("domain", "https://YouTube.com/watch?v=1") == "youtube.com"
    assert normalize("process", "Mimikatz.EXE") == "mimikatz.exe"
    assert normalize("port", "4444") == "4444"
    with pytest.raises(ValueError):
        normalize("port", "notaport")


def test_blocklist_add_remove_persist(tmp_path):
    p = tmp_path / "bl.json"
    bl = Blocklist(p)
    bl.add("domain", "https://evil.example/x")
    bl.add("domain", "evil.example")     # dedup after normalization
    bl.add("process", "mimikatz.exe")
    assert bl.values("domain") == ["evil.example"]
    assert "mimikatz.exe" in bl.values("process")
    # persisted + reloadable
    assert json.loads(p.read_text())
    assert Blocklist(p).values("domain") == ["evil.example"]
    bl.remove("domain", "evil.example")
    assert bl.values("domain") == []


# -- resolver -------------------------------------------------------------
def test_resolve_ips_includes_www(monkeypatch):
    calls = []

    def fake_getaddrinfo(host, _port):
        calls.append(host)
        return [(2, 1, 6, "", ("93.184.216.34", 0))] if host.endswith("example.com") else []

    ips = resolve_ips("example.com", resolver=fake_getaddrinfo)
    assert "93.184.216.34" in ips
    assert "www.example.com" in calls   # apex expands to common subdomains


# -- firewall command construction ---------------------------------------
def test_firewall_windows_block_and_unblock():
    cmds = []
    fw = FirewallBlocker(system="Windows", runner=lambda c: cmds.append(c) or True)
    fw.block("evil.example", {"1.2.3.4", "5.6.7.8"})
    add = [c for c in cmds if "add" in c][0]
    assert "netsh" in add and "action=block" in add
    assert "remoteip=1.2.3.4,5.6.7.8" in add
    cmds.clear()
    fw.unblock("evil.example")
    assert any("delete" in c and "name=SilentGuard-Block-evil.example" in c for c in cmds)


def test_firewall_linux_block_per_ip():
    cmds = []
    fw = FirewallBlocker(system="Linux", runner=lambda c: cmds.append(c) or True)
    fw.block("evil.example", {"1.2.3.4"})
    drop = [c for c in cmds if "DROP" in c][0]
    assert drop[:4] == ["iptables", "-A", "OUTPUT", "-d"] and "1.2.3.4" in drop


def test_firewall_no_ips_is_noop_add():
    cmds = []
    fw = FirewallBlocker(system="Windows", runner=lambda c: cmds.append(c) or True)
    fw.block("x.example", set())
    assert not any("add" in c for c in cmds)   # nothing to add with no IPs


# -- process guard --------------------------------------------------------
def test_process_guard_kills_matching():
    killed = []
    pg = ProcessGuard(killer=lambda pid: killed.append(pid) or True)
    result = pg.enforce({"mimikatz.exe"}, [(10, "mimikatz.exe"), (11, "chrome.exe")])
    assert result == [10] and killed == [10]


# -- hosts writer ---------------------------------------------------------
def test_apply_hosts_writes_apex_and_www(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n")
    assert apply_hosts(["youtube.com"], path=hosts) is True
    txt = hosts.read_text()
    assert "0.0.0.0 youtube.com" in txt and "0.0.0.0 www.youtube.com" in txt


# -- full engine sync -----------------------------------------------------
class _FakeFW:
    def __init__(self):
        self.blocked = {}
        self.unblocked = []

    def block(self, host, ips):
        self.blocked[host] = ips
        return []

    def unblock(self, host):
        self.unblocked.append(host)
        return []


def _engine(tmp_path):
    bl = Blocklist(tmp_path / "bl.json")
    fw = _FakeFW()
    eng = ProtectionEngine(
        bl, firewall=fw,
        process_guard=ProcessGuard(killer=lambda pid: True),
        resolver=lambda host: {"1.2.3.4"},
        hosts_writer=lambda domains: True,
        process_source=lambda: [(10, "mimikatz.exe"), (11, "chrome.exe")],
    )
    return bl, fw, eng


def test_engine_sync_blocks_everything(tmp_path):
    bl, fw, eng = _engine(tmp_path)
    bl.add("domain", "evil.example")
    bl.add("process", "mimikatz.exe")
    bl.add("port", "4444")
    summary = eng.sync()
    assert summary["domains"] == 1 and summary["firewall_ips"] == 1
    assert summary["processes_killed"] == 1 and summary["ports_blocked"] == 1
    assert "evil.example" in fw.blocked


def test_engine_unblocks_removed_domain(tmp_path):
    bl, fw, eng = _engine(tmp_path)
    bl.add("domain", "evil.example")
    eng.sync()
    bl.remove("domain", "evil.example")
    eng.sync()
    assert "evil.example" in fw.unblocked
