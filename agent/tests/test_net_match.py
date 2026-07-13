"""Agent-side subdomain matching + sinkhole host normalization."""
from unittest.mock import patch

from silentguard_agent.monitors.dns_sinkhole import DnsSinkhole
from silentguard_agent.net_match import (extract_host, host_matches_any,
                                         host_matches_domain)


def test_extract_and_match():
    assert extract_host("https://evil.example.com:8443/x") == "evil.example.com"
    assert host_matches_domain("evil.example.com", "example.com")
    assert host_matches_domain("a.b.example.com", "example.com")
    assert not host_matches_domain("notexample.com", "example.com")
    assert not host_matches_domain("example.com.evil.com", "example.com")
    assert host_matches_any("c2.bad.example", ["bad.example"]) == "bad.example"


def test_sinkhole_normalizes_url_entries_to_hosts(config, telemetry, tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n")
    config.dry_run = False
    config.blocked_domains = {"https://evil.example.com/malware", "bad.test", "example.com"}
    sink = DnsSinkhole(config, telemetry)
    with patch("silentguard_agent.monitors.dns_sinkhole.hosts_path", return_value=hosts):
        sink.sync()
    written = hosts.read_text()
    # URL reduced to its bare host; all entries are valid hostnames.
    assert "0.0.0.0 evil.example.com" in written
    assert "0.0.0.0 bad.test" in written
    assert "0.0.0.0 example.com" in written
    assert "https://" not in written
    # An apex domain also sinkholes its common subdomains (www/m), so blocking
    # example.com covers www.example.com — the browser's real target.
    assert "0.0.0.0 www.example.com" in written
    assert "0.0.0.0 m.example.com" in written


def test_expand_hosts_covers_www_of_apex():
    from silentguard_agent.monitors.dns_sinkhole import expand_hosts
    out = expand_hosts({"youtube.com"})
    assert {"youtube.com", "www.youtube.com", "m.youtube.com"} <= out
    # A subdomain entry is not further expanded.
    assert expand_hosts({"api.example.com"}) == {"api.example.com"}
