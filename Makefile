# SilentGuard XDR — developer tasks.
.PHONY: help install test test-server test-agent coverage migrate sbom docs

help:
	@echo "Targets:"
	@echo "  install       install server + agent dependencies"
	@echo "  test          run server and agent test suites"
	@echo "  test-server   run the server suite"
	@echo "  test-agent    run the agent suite"
	@echo "  coverage      run server suite with coverage (fails under 85%)"
	@echo "  migrate       apply database migrations (alembic upgrade head)"
	@echo "  sbom          generate a CycloneDX SBOM (sbom.json)"

install:
	pip install -r server/requirements.txt pytest-cov
	pip install -r agent/requirements.txt

test: test-server test-agent

test-server:
	cd server && pytest -q

test-agent:
	cd agent && pytest -q

coverage:
	cd server && pytest -q --cov=app --cov-report=term-missing --cov-fail-under=85

migrate:
	cd server && alembic upgrade head

sbom:
	python scripts/generate_sbom.py > sbom.json
	@echo "wrote sbom.json"

docs:
	python scripts/generate_schema_docs.py > docs/schema.md
	cd server && python ../scripts/export_openapi.py > openapi.json
	python scripts/generate_sbom.py > sbom.json
	@echo "regenerated docs/schema.md, server/openapi.json, sbom.json"
