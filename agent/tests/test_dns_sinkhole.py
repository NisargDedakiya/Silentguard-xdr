"""DNS sinkhole tests against a temp hosts file — never touches /etc/hosts."""
from unittest.mock import patch

from silentguard_agent.monitors.dns_sinkhole import MARK_BEGIN, MARK_END, DnsSinkhole


def make_sinkhole(config, telemetry, tmp_path, initial="127.0.0.1 localhost\n"):
    hosts = tmp_path / "hosts"
    hosts.write_text(initial)
    sink = DnsSinkhole(config, telemetry)
    return sink, hosts


def test_dry_run_never_touches_hosts_file(config, telemetry, tmp_path):
    sink, hosts = make_sinkhole(config, telemetry, tmp_path)
    with patch("silentguard_agent.monitors.dns_sinkhole.hosts_path", return_value=hosts):
        sink.sync()
    assert hosts.read_text() == "127.0.0.1 localhost\n"  # dry run: unchanged


def test_sync_writes_sinkhole_block_and_emits(config, telemetry, tmp_path):
    config.dry_run = False
    config.blocked_domains = {"evil.example", "bad.example"}
    sink, hosts = make_sinkhole(config, telemetry, tmp_path)
    with patch("silentguard_agent.monitors.dns_sinkhole.hosts_path", return_value=hosts):
        sink.sync()
    content = hosts.read_text()
    assert "127.0.0.1 localhost" in content  # original preserved
    assert "0.0.0.0 evil.example" in content
    assert "0.0.0.0 bad.example" in content
    assert content.count(MARK_BEGIN) == 1
    blocked = telemetry.by_action("blocked")
    assert {e["details"]["domain"] for e in blocked} == {"evil.example", "bad.example"}


def test_sync_replaces_previous_block_instead_of_appending(config, telemetry, tmp_path):
    config.dry_run = False
    config.blocked_domains = {"a.example"}
    sink, hosts = make_sinkhole(config, telemetry, tmp_path)
    with patch("silentguard_agent.monitors.dns_sinkhole.hosts_path", return_value=hosts):
        sink.sync()
        config.blocked_domains.add("b.example")
        sink.sync()
    content = hosts.read_text()
    assert content.count(MARK_BEGIN) == 1
    assert content.count(MARK_END) == 1
    assert "0.0.0.0 a.example" in content and "0.0.0.0 b.example" in content
    # only the newly added domain is re-announced
    assert [e["details"]["domain"] for e in telemetry.by_action("blocked")].count("a.example") == 1


def test_sync_noop_when_domains_unchanged(config, telemetry, tmp_path):
    config.dry_run = False
    config.blocked_domains = {"a.example"}
    sink, hosts = make_sinkhole(config, telemetry, tmp_path)
    with patch("silentguard_agent.monitors.dns_sinkhole.hosts_path", return_value=hosts) as mocked:
        sink.sync()
        calls_after_first = mocked.call_count
        sink.sync()
        assert mocked.call_count == calls_after_first  # second sync short-circuits
