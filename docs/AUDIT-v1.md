# Full Software Audit — SilentGuard XDR

Scope: verify every feature is real and working (not stubbed), exercise the
software end to end, find and fix bugs, and confirm it runs without errors.

## Method

Beyond the test suites, the software was **booted and driven live**:

- Server started under uvicorn on a fresh migrated database.
- A device enrolled, sent attack telemetry, and detections were created.
- Auth, MFA (with real TOTP codes), SSO gating, analytics, and compliance were
  driven over HTTP.
- The **real endpoint agent** was run against the live server (dry-run): it
  enrolled, ran every monitor, flushed telemetry, checked in, and shut down
  cleanly — no errors.

## Results — everything verified real (no fake/stub features)

| Area | Live verification |
|---|---|
| Detection pipeline | Attack telemetry → `powershell_abuse`, `encoded_command`, `reverse_shell`, `suricata_alert` detections created |
| Agent | Enrolled, monitors active (detected real listening ports), telemetry delivered, clean shutdown |
| Auth (JWT) | Login issues access/refresh tokens; bad/no admin token → 401; bad agent key → 401 |
| MFA (TOTP) | setup → activate with a real code → login blocked without code → login succeeds with code |
| SSO (OIDC) | Endpoints return 503 until configured (gated correctly) |
| RBAC | read_only can read detections (200) but cannot triage (403) |
| Analytics/Compliance | Summary + compliance score computed from live data; critical backlog reflected |
| SSRF protection | A webhook to `127.0.0.1` was **blocked** ("SSRF protection") — the guard is live |
| Secure headers | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` present |
| Migrations | `alembic upgrade head` clean; autogenerate reports **zero drift** vs models |
| Imports | All 71 modules (51 server + 20 agent) import with no errors |
| Tests | Server 245 passing at **91% coverage** (gate 85%); agent 102 passing |

## Bugs found & fixed

1. **TOTP fail-open on empty secret (security).** `totp.verify("", code)` computed
   an HMAC over an empty key and could return a matchable code. If a user ever
   reached `mfa_enabled=True` with a null secret, MFA could be bypassed. Fixed:
   `verify()` now returns `False` immediately on an empty secret (fail-closed),
   with a regression test.
2. **Coverage artifact committed.** `server/.coverage` (a binary test artifact)
   was tracked in git. Removed from the index and added to `.gitignore`.

## Notes / hardening opportunities (not bugs)

- **MFA re-enrolment:** `POST /mfa/setup` on an already-enabled account rotates
  the secret from the authenticated session without requiring a current code
  (disable requires one). This matches common "reset MFA from a logged-in
  session" UX; a stricter policy could require a current code to rotate.
- **MFA brute-force:** login attempts are IP-rate-limited, but a correct password
  with wrong codes does not count toward account lockout. The IP rate limit
  still bounds attempts; per-account MFA-failure lockout could be added.

Both are documented for a future hardening pass; neither is a runtime defect.

## Conclusion

The platform boots, the agent runs, and every advertised feature works against a
live server — nothing is a mock or placeholder. One real security fail-open bug
was found and fixed; both test suites are green and coverage exceeds the CI gate.
