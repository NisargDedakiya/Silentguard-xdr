"""Port watchdog tests with mocked psutil — no real processes are touched."""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import psutil

from silentguard_agent.monitors.port_watchdog import PortWatchdog


def fake_proc(pid, name):
    proc = MagicMock()
    proc.pid = pid
    proc.info = {"pid": pid, "name": name}
    proc.name.return_value = name
    return proc


def fake_conn(pid, port, status=psutil.CONN_LISTEN):
    return SimpleNamespace(pid=pid, status=status, laddr=SimpleNamespace(ip="0.0.0.0", port=port))


def run_scan(watchdog, procs, conns, proc_lookup=None):
    lookup = proc_lookup or {}
    with patch("psutil.process_iter", return_value=procs), \
         patch("psutil.net_connections", return_value=conns), \
         patch("psutil.Process", side_effect=lambda pid: lookup[pid]):
        watchdog.scan()


def test_blocked_process_name_is_killed(config, telemetry):
    wd = PortWatchdog(config, telemetry)
    run_scan(wd, [fake_proc(101, "mimikatz.exe")], [])
    killed = telemetry.by_action("killed")
    assert len(killed) == 1
    assert killed[0]["severity"] == "critical"
    assert killed[0]["details"] == {"pid": 101, "process": "mimikatz.exe"}


def test_suspicious_port_listener_is_killed_even_if_allowlisted(config, telemetry):
    wd = PortWatchdog(config, telemetry)
    proc = fake_proc(202, "python")  # python is on the allowlist
    run_scan(wd, [], [fake_conn(202, 4444)], proc_lookup={202: proc})
    killed = telemetry.by_action("killed")
    assert len(killed) == 1
    assert killed[0]["details"]["port"] == 4444


def test_new_listener_on_normal_port_only_reported(config, telemetry):
    wd = PortWatchdog(config, telemetry)
    proc = fake_proc(303, "myapp")
    run_scan(wd, [], [fake_conn(303, 9090)], proc_lookup={303: proc})
    assert telemetry.by_action("killed") == []
    detected = telemetry.by_action("detected")
    assert len(detected) == 1
    assert detected[0]["severity"] == "warning"


def test_allowlisted_listener_on_normal_port_is_silent(config, telemetry):
    wd = PortWatchdog(config, telemetry)
    proc = fake_proc(404, "sshd")
    run_scan(wd, [], [fake_conn(404, 22)], proc_lookup={404: proc})
    assert telemetry.events == []


def test_known_listener_not_reported_twice(config, telemetry):
    wd = PortWatchdog(config, telemetry)
    proc = fake_proc(505, "myapp")
    conns = [fake_conn(505, 9090)]
    run_scan(wd, [], conns, proc_lookup={505: proc})
    run_scan(wd, [], conns, proc_lookup={505: proc})
    assert len(telemetry.by_action("detected")) == 1


def test_non_listening_connections_ignored(config, telemetry):
    wd = PortWatchdog(config, telemetry)
    proc = fake_proc(606, "evil")
    run_scan(wd, [], [fake_conn(606, 4444, status=psutil.CONN_ESTABLISHED)],
             proc_lookup={606: proc})
    assert telemetry.events == []
