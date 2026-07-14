# SilentGuard XDR — Test Plan (all features)

Two layers of testing:

1. **Automated** — the full suites (server **273**, agent **119**). Run them:
   ```bash
   cd server && pip install -r requirements.txt && pytest -q --cov=app   # ~91% coverage
   cd agent  && pip install -r requirements.txt && pytest -q
   ```
   **Feature acceptance suites** — one runnable walk-through of *every* feature,
   the executable counterpart of this plan (run these to demo all features):
   ```bash
   cd server && pytest tests/test_acceptance.py -v   # 19 checks across the API surface
   cd agent  && pytest tests/test_acceptance.py -v   # 10 checks across every monitor
   ```
2. **Manual / end‑to‑end** — the cases below, to validate live behavior an operator
   cares about. Each case: **precondition → steps → expected result**, plus the
   automated test that also covers it.

Format for HTTP steps: admin calls send header `X-Admin-Token: <SG_ADMIN_TOKEN>`;
agent calls send `X-Agent-Key: <key from enroll>`.

---

## 1. Platform / smoke

| ID | Feature | Steps | Expected | Automated |
|---|---|---|---|---|
| SMK‑1 | Health | `GET /api/health` | `{"status":"ok"}` | — |
| SMK‑2 | Migrations | `alembic upgrade head` on empty DB; then `alembic revision --autogenerate` | upgrades clean; autogenerate shows **no drift** | `test_migrations` |
| SMK‑3 | Enroll | `POST /api/agent/enroll` with the enroll token | returns `device_id` + `api_key`; device shows online | `test_agents` |
| SMK‑4 | Bad enroll token | enroll with wrong token | `401` | `test_agents` |

## 2. Authentication & access

| ID | Feature | Steps | Expected | Automated |
|---|---|---|---|---|
| AUT‑1 | Login | `POST /api/auth/login` valid creds | access + refresh tokens | `test_auth` |
| AUT‑2 | Bad admin token | `GET /api/admin/detections` no/`wrong` token | `401` | `test_auth` |
| AUT‑3 | Account lockout | N failed logins (`SG_LOGIN_MAX_ATTEMPTS`) | account locked `423` | `test_auth` |
| AUT‑4 | Rate limit | rapid logins beyond `SG_LOGIN_RATE_LIMIT` | `429` | `test_auth` |
| RBAC‑1 | read_only can read | read_only token → `GET /detections` | `200` | `test_detection` |
| RBAC‑2 | read_only denied triage | read_only → `POST /detections/{id}/ack` | `403` | `test_detection` |
| RBAC‑3 | analyst can triage | analyst → ack/resolve | `200` | `test_detection` |
| PWR‑1 | Password reset | request reset → confirm with token | password changed | `test_password_reset` |

## 3. MFA (TOTP)

| ID | Steps | Expected | Automated |
|---|---|---|---|
| MFA‑1 | setup → activate with a valid code | `{"enabled":true}` | `test_mfa` |
| MFA‑2 | activate with wrong code | `401` | `test_mfa` |
| MFA‑3 | login without code (MFA on) | `401 "MFA code required"` | `test_mfa` |
| MFA‑4 | login with current code | tokens issued | `test_mfa` |
| MFA‑5 | disable requires a valid code | wrong code `401`; correct → disabled | `test_mfa` |
| MFA‑6 | empty‑secret cannot be satisfied (fail‑closed) | `verify("",code)` = false | `test_mfa` |

## 4. SSO (OIDC)

| ID | Steps | Expected | Automated |
|---|---|---|---|
| SSO‑1 | unconfigured → `GET /api/auth/sso/login` | `503` | `test_sso` |
| SSO‑2 | configured → `/sso/login` | returns `authorization_url` | `test_sso` |
| SSO‑3 | callback with valid IdP claims | new user provisioned + tokens | `test_sso` |
| SSO‑4 | callback error / bad state | `401` | `test_sso` |
| SSO‑5 | domain allowlist | email outside domain rejected | `test_sso` |

## 5. Detection engine

| ID | Steps | Expected | Automated |
|---|---|---|---|
| DET‑1 | telemetry `powershell -nop -enc …` | `powershell_abuse` + `encoded_command` | `test_detection` |
| DET‑2 | telemetry `certutil -urlcache …` | `lolbin_execution` (T1218) | `test_detection` |
| DET‑3 | port_watchdog killed port 4444 | `reverse_shell` (T1059) | `test_detection` |
| DET‑4 | `comsvcs.dll, MiniDump … lsass` | `credential_dumping` | `test_attack_simulation` |
| DET‑5 | `vssadmin delete shadows` | `ransomware_behavior` (T1490) | `test_attack_simulation` |
| DET‑6 | benign telemetry | no detection | `test_detection` |
| DET‑7 | triage ack→resolve | status transitions | `test_detection` |
| DET‑8 | auto‑isolate on (`SG_DETECTION_AUTO_ISOLATE=1`) | device isolated on critical | `test_detection` |

## 6. Threat intel / Sigma / YARA / Suricata / Registry

| ID | Steps | Expected | Automated |
|---|---|---|---|
| IOC‑1 | add domain IOC, telemetry to it | `ioc_match` | `test_intel` |
| IOC‑2 | domain IOC matches subdomain | `c2.bad.example` matches `bad.example` | `test_netmatch` |
| SIG‑1 | add valid Sigma, matching telemetry | `sigma:<id>` detection | `test_sigma` |
| SIG‑2 | invalid Sigma rule | rejected `400` at ingest | `test_sigma` |
| SIG‑3 | disabled Sigma rule | never fires | `test_sigma` |
| YAR‑1 | YARA match on dropped file | `yara_match` (T1105) | `test_yara_scanner` + `test_detection` |
| SUR‑1 | Suricata eve.json alert | `suricata_alert` (T1071) | `test_suricata_monitor` + `test_detection` |
| SUR‑2 | log rotation / non‑alert lines | offset resets; non‑alerts ignored | `test_suricata_monitor` |
| REG‑1 | new Run‑key autorun (Windows) | `registry_persistence` (T1547.001) | `test_registry_monitor` + `test_detection` |

## 7. Blocking (domain / URL / port / process)

| ID | Steps | Expected | Automated |
|---|---|---|---|
| BLK‑1 | block `example.com`, telemetry to `evil.example.com` | `blocklist_domain` detection | `test_netmatch` |
| BLK‑2 | block `example.com`, cmdline `curl https://cdn.example.com/x` | detection (URL mined) | `test_netmatch` |
| BLK‑3 | block `example.com`, telemetry to `notexample.com` | **no** detection (boundary‑safe) | `test_netmatch` |
| BLK‑4 | block a full URL | stored as bare host | `test_netmatch` |
| BLK‑5 | agent sinkhole (elevated, non‑dry‑run) | apex + `www.`/`m.` written to hosts file | `test_net_match` (expansion) + `test_dns_sinkhole` |
| BLK‑6 | **manual** block a site, elevated agent, DoH off, flush DNS | site fails to load | manual (Part 6 of SETUP‑GUIDE) |
| BLK‑7 | block a process/port | pushed to agent, watchdog acts | `test_port_watchdog` |

## 8. Agent security hardening

| ID | Steps | Expected | Automated |
|---|---|---|---|
| UPD‑1 | signed update manifest (valid sig) | accepted `update_verified` | `test_update_verifier` |
| UPD‑2 | unsigned/invalid manifest | rejected, fail‑closed | `test_update_verifier` |
| UPD‑3 | signed downgrade below floor | `rollback_blocked` | `test_update_rollback` |
| UPD‑4 | forged `allow_rollback` on old manifest | signature invalid → rejected | `test_update_rollback` |
| TMP‑1 | edit state file, restart agent | `tamper_detected` + re‑enroll | `test_tamper` + `test_detection` |
| PIN‑1 | `SG_PIN_SHA256` set | pinned session mounted; mismatch fails closed | `test_cert_pinning` |
| QUE‑1 | offline then restart | spooled telemetry recovered | `test_telemetry_queue` |

## 9. Integrations / AI / analytics / compliance

| ID | Steps | Expected | Automated |
|---|---|---|---|
| INT‑1 | webhook to public sink, trigger detection | POST delivered | `test_integrations` |
| INT‑2 | Splunk HEC / CEF formatting | correct payload shape | `test_integrations` |
| INT‑3 | integration to loopback/private | rejected (SSRF) | `test_integrations` + live |
| AI‑1 | `/detections/{id}/explain` (AI on, mocked) | summary+MITRE+remediation | `test_ai_assistant` |
| AI‑2 | AI off | `503` | `test_ai_assistant` |
| ANL‑1 | analytics summary/timeline/process‑tree/mitre | correct aggregates | `test_analytics` |
| CMP‑1 | compliance report structure + score | 8 controls, score 0–100 | `test_compliance` |
| CMP‑2 | open critical → backlog fails; resolve → passes | control flips | `test_compliance` |
| CMP‑3 | auditor can read, read_only cannot | 200 / 403 | `test_compliance` |

## 10. Multi‑tenancy & policy

| ID | Steps | Expected | Automated |
|---|---|---|---|
| TEN‑1 | org‑scoped data isolation | tenant A can't see tenant B | `test_tenancy` |
| POL‑1 | policy inheritance defaults→org→group | effective policy resolves | `test_policies` |
| LIC‑1 | device cap reached | enroll `402` | `test_agents` |

## 11. Full kill‑chain (regression anchor)

| ID | Steps | Expected | Automated |
|---|---|---|---|
| E2E‑1 | 9‑stage attack telemetry in one batch | all stages detected; MITRE breadth; triage→compliance loop closes | `test_attack_simulation` |

---

## How to run just one area

```bash
cd server && pytest tests/test_mfa.py -q          # MFA
cd server && pytest tests/test_netmatch.py -q      # domain/subdomain blocking
cd agent  && pytest tests/test_update_rollback.py -q
```

## Manual live smoke (10 minutes)

1. Bring up server + dashboard (Part 1).
2. Enroll an elevated agent (Part 4) → device online.
3. On the endpoint run `powershell -nop -enc SQBFAFgA` → detection appears.
4. Block a domain, disable browser DoH, flush DNS → site blocked (Part 6).
5. Create a read_only user → confirm it cannot triage (RBAC‑2).
6. Enable MFA on your admin user → confirm login needs a code.
7. Open the compliance report → confirm score and controls.
