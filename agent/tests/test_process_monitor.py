"""Process monitor tests (psutil mocked)."""
from unittest.mock import MagicMock, patch

from silentguard_agent.monitors.process_monitor import ProcessMonitor


def fake_proc(pid, name, cmdline, ppid=1, user="root", exe=""):
    p = MagicMock()
    p.info = {"pid": pid, "ppid": ppid, "name": name, "username": user,
              "cmdline": cmdline, "exe": exe}
    return p


def run_scan(mon, procs):
    with patch("psutil.process_iter", return_value=procs):
        mon.scan()


def test_baseline_is_silent(config, telemetry):
    mon = ProcessMonitor(config, telemetry)
    run_scan(mon, [fake_proc(1, "systemd", ["/sbin/init"])])
    assert telemetry.events == []


def test_new_process_emitted_with_command_line(config, telemetry):
    mon = ProcessMonitor(config, telemetry)
    run_scan(mon, [fake_proc(1, "systemd", ["/sbin/init"])])  # baseline
    run_scan(mon, [
        fake_proc(1, "systemd", ["/sbin/init"]),
        fake_proc(200, "powershell", ["powershell", "-enc", "SQBFAFgA"], ppid=1),
    ])
    exec_events = telemetry.by_action("exec")
    assert len(exec_events) == 1
    d = exec_events[0]["details"]
    assert d["pid"] == 200 and d["ppid"] == 1
    assert d["command_line"] == "powershell -enc SQBFAFgA"


def test_not_reported_twice(config, telemetry):
    mon = ProcessMonitor(config, telemetry)
    run_scan(mon, [fake_proc(1, "systemd", ["/sbin/init"])])
    procs = [fake_proc(1, "systemd", ["/sbin/init"]), fake_proc(50, "bash", ["bash"])]
    run_scan(mon, procs)
    run_scan(mon, procs)
    assert len(telemetry.by_action("exec")) == 1


def test_burst_is_bounded(config, telemetry):
    mon = ProcessMonitor(config, telemetry, max_events_per_scan=5)
    run_scan(mon, [fake_proc(1, "init", ["init"])])
    run_scan(mon, [fake_proc(1, "init", ["init"])]
             + [fake_proc(100 + i, f"p{i}", [f"p{i}"]) for i in range(20)])
    assert len(telemetry.by_action("exec")) == 5


def test_empty_cmdline_falls_back_to_name(config, telemetry):
    mon = ProcessMonitor(config, telemetry)
    run_scan(mon, [fake_proc(1, "init", ["init"])])
    run_scan(mon, [fake_proc(1, "init", ["init"]), fake_proc(7, "kthreadd", [])])
    d = telemetry.by_action("exec")[0]["details"]
    assert d["command_line"] == "kthreadd"
