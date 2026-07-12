"""Agent response-handler tests (psutil mocked; dry-run for OS-touching ops)."""
from unittest.mock import MagicMock, patch

from silentguard_agent import response_handlers as handlers


class _Tel:
    def __init__(self):
        self.events = []

    def emit(self, source, action, summary, severity="info", details=None):
        self.events.append({"source": source, "action": action, "details": details or {}})


def _reports():
    calls = []
    def report(action_id, status, **extra):
        calls.append({"action_id": action_id, "status": status, **extra})
    return report, calls


def test_kill_process_dry_run(config):
    config.dry_run = True
    tel = _Tel()
    report, calls = _reports()
    proc = MagicMock()
    proc.pid = 4321
    with patch("silentguard_agent.response_handlers.psutil.Process", return_value=proc):
        handlers.kill_process({"pid": 4321, "action_id": 7}, tel, config, report)
    assert calls[0]["status"] == "ok"
    assert calls[0]["killed"] == [4321]
    assert any(e["action"] == "process_killed" for e in tel.events)


def test_kill_process_failure_reports_failed(config):
    config.dry_run = False
    tel = _Tel()
    report, calls = _reports()
    import psutil
    with patch("silentguard_agent.response_handlers.psutil.Process",
               side_effect=psutil.NoSuchProcess(1)):
        handlers.kill_process({"pid": 1, "action_id": 8}, tel, config, report)
    assert calls[0]["status"] == "failed"


def test_delete_file_quarantines(config):
    tel = _Tel()
    report, calls = _reports()
    qm = MagicMock()
    qm.quarantine.return_value = {"id": "q9", "original_path": "/tmp/x"}
    handlers.delete_file({"path": "/tmp/x", "action_id": 9}, tel, config, qm, report)
    assert calls[0]["status"] == "ok" and calls[0]["quarantined"] == "q9"
    qm.quarantine.assert_called_once()


def test_delete_file_no_path_fails(config):
    tel = _Tel()
    report, calls = _reports()
    handlers.delete_file({"action_id": 10}, tel, config, MagicMock(), report)
    assert calls[0]["status"] == "failed"


def test_remote_scan_reports_ok(config):
    tel = _Tel()
    report, calls = _reports()
    with patch("silentguard_agent.response_handlers.psutil.pids", return_value=[1, 2, 3]):
        handlers.remote_scan({"action_id": 11}, tel, config, report)
    assert calls[0]["status"] == "ok" and calls[0]["process_count"] == 3


def test_remote_update_acknowledges(config):
    tel = _Tel()
    report, calls = _reports()
    handlers.remote_update({"action_id": 12, "version": "0.2.0"}, tel, report)
    assert calls[0]["status"] == "ok" and calls[0]["acknowledged"] == "0.2.0"
