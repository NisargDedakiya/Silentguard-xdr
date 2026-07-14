# Testing & CI (Module M22)

## Running the suites

```bash
make test            # server + agent
make test-server     # server only
make test-agent      # agent only
make coverage        # server suite with coverage (fails under 85%)
```

Or directly: `cd server && pytest -q`, `cd agent && pytest -q`.

Current status: **185 server + 44 agent = 229 tests**, server line coverage
~92%.

## Test tiers

Registered pytest markers (`server/pytest.ini`) categorize tests:

| Marker | Scope |
|---|---|
| `unit` | fast isolated logic (rules, formatters, hashing, time utils) |
| `api` | endpoint behavior via the FastAPI `TestClient` |
| `integration` | multi-component flows (agent↔server, ingestion→detection→response) |
| `security` | auth, RBAC, tenancy isolation, SSRF |

Run a tier with `pytest -m <marker>`. The bulk of existing coverage already
spans these tiers by construction (e.g. `test_detection` exercises ingestion →
rule engine → persistence → API as an integration path; `test_rbac`,
`test_tenancy`, `test_security` are security tests).

## Continuous integration

`.github/workflows/ci.yml` runs on every push/PR:

1. **server** — install `requirements.txt`, run `pytest` with a
   `--cov-fail-under=85` gate, and verify migrations match the models.
2. **agent** — install `requirements.txt`, run `pytest`.
3. **supply-chain** — generate `sbom.json` (CycloneDX) and upload it as an
   artifact.

## Migration parity

`tests/test_migrations.py` asserts that `alembic upgrade head` produces the same
schema as the ORM models, so the migration history can never silently drift from
`models.py`.

## Not yet automated

Load testing (a Locust/k6 harness for the ingestion path) and dependency
vulnerability scanning (`pip-audit` in CI) are tracked for a later pass; both
need environments/services not available in the current setup.
