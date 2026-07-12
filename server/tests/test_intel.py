"""Tests for M10: threat-intel IOC store, matching, and rule distribution."""
import datetime

import pytest

from app.core.roles import Role
from app.services import auth_service, threat_intel
from tests.conftest import ADMIN_HEADERS

GOOD_PW = "Sup3rSecret!!"


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    auth_service.reset_rate_limit()
    yield
    auth_service.reset_rate_limit()


# -- service unit ---------------------------------------------------------
def test_upsert_and_lookup(db_session_factory):
    db = db_session_factory()
    threat_intel.upsert_ioc(db, "org1", "domain", "Evil.Example", confidence=90, source="feed")
    db.commit()
    hit = threat_intel.lookup(db, "org1", "domain", "evil.example")
    assert hit is not None and hit.confidence == 90
    # Wrong org does not match
    assert threat_intel.lookup(db, "org2", "domain", "evil.example") is None
    db.close()


def test_expired_ioc_not_matched(db_session_factory):
    db = db_session_factory()
    past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    threat_intel.upsert_ioc(db, "org1", "ip", "1.2.3.4", expires_at=past)
    db.commit()
    assert threat_intel.lookup(db, "org1", "ip", "1.2.3.4") is None
    assert threat_intel.prune_expired(db) == 1
    db.close()


def test_extract_indicators():
    got = set(threat_intel.extract_indicators(
        {"domain": "bad.com", "sha256": "AB", "remote_ip": "9.9.9.9"}))
    assert ("domain", "bad.com") in got
    assert ("sha256", "AB") in got
    assert ("ip", "9.9.9.9") in got


# -- API + RBAC -----------------------------------------------------------
def test_ioc_crud_via_api(client):
    r = client.post("/api/admin/intel/iocs",
                    json={"ioc_type": "domain", "value": "c2.bad.example", "confidence": 95},
                    headers=ADMIN_HEADERS)
    assert r.status_code == 201
    ioc_id = r.json()["id"]
    lst = client.get("/api/admin/intel/iocs", headers=ADMIN_HEADERS).json()
    assert any(i["value"] == "c2.bad.example" for i in lst)
    assert client.delete(f"/api/admin/intel/iocs/{ioc_id}", headers=ADMIN_HEADERS).status_code == 200


def test_ioc_import(client):
    r = client.post("/api/admin/intel/iocs/import", json={"source": "feedX", "iocs": [
        {"type": "domain", "value": "a.example", "confidence": 80},
        {"type": "sha256", "value": "deadbeef", "confidence": 70},
        {"type": "bogus", "value": "x"},  # skipped
    ]}, headers=ADMIN_HEADERS)
    assert r.json()["imported"] == 2


def test_read_only_cannot_manage_intel(client, db_session_factory):
    db = db_session_factory()
    auth_service.create_user(db, "ro@x.com", GOOD_PW, Role.READ_ONLY.value)
    db.close()
    tok = client.post("/api/auth/login", json={"email": "ro@x.com", "password": GOOD_PW}).json()
    h = {"Authorization": f"Bearer {tok['access_token']}"}
    assert client.get("/api/admin/intel/iocs", headers=h).status_code == 200
    assert client.post("/api/admin/intel/iocs",
                       json={"ioc_type": "domain", "value": "x.example"},
                       headers=h).status_code == 403


# -- IOC match produces a detection through ingestion ---------------------
def test_ioc_match_creates_detection(client, enrolled_device):
    client.post("/api/admin/intel/iocs",
                json={"ioc_type": "domain", "value": "c2.badactor.example", "confidence": 90},
                headers=ADMIN_HEADERS)
    client.post("/api/agent/telemetry", json={"events": [{
        "source": "dns_sinkhole", "action": "blocked", "severity": "warning",
        "summary": "blocked", "details": {"domain": "c2.badactor.example"},
    }]}, headers=enrolled_device["headers"])
    dets = client.get("/api/admin/detections", headers=ADMIN_HEADERS).json()
    ioc_hits = [d for d in dets if d["rule_id"] == "ioc_match"]
    assert len(ioc_hits) == 1
    assert ioc_hits[0]["severity"] == "critical"  # confidence 90
    assert ioc_hits[0]["technique_id"] == "T1071.004"


# -- YARA / Sigma distribution -------------------------------------------
def test_intel_rule_distribution(client):
    r = client.post("/api/admin/intel/rules", json={
        "kind": "yara", "name": "evil_strings",
        "content": "rule evil { strings: $a = \"evil\" condition: $a }"},
        headers=ADMIN_HEADERS)
    assert r.status_code == 201
    rules = client.get("/api/admin/intel/rules?kind=yara", headers=ADMIN_HEADERS).json()
    assert len(rules) == 1 and rules[0]["name"] == "evil_strings"


def test_intel_rule_kind_validated(client):
    assert client.post("/api/admin/intel/rules",
                       json={"kind": "snort", "name": "x", "content": "y"},
                       headers=ADMIN_HEADERS).status_code == 400
