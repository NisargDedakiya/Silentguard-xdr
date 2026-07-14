"""Tests for M23 documentation automation: OpenAPI + schema generator."""
import importlib.util
from pathlib import Path

from app.database import Base
from app.main import app

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"


def _load(script_name):
    spec = importlib.util.spec_from_file_location(script_name.replace(".py", ""),
                                                  SCRIPTS / script_name)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_openapi_has_expected_paths():
    spec = app.openapi()
    paths = spec["paths"]
    for p in ("/api/health", "/api/auth/login", "/api/admin/detections",
              "/api/admin/intel/iocs", "/api/admin/analytics/summary",
              "/api/admin/integrations", "/api/admin/policies"):
        assert p in paths, f"missing {p} in OpenAPI"
    assert spec["info"]["title"] == "SilentGuard XDR"


def test_schema_doc_generator_covers_all_tables():
    mod = _load("generate_schema_docs.py")
    doc = mod.render()
    for table in Base.metadata.tables:
        assert f"## `{table}`" in doc, f"schema doc missing table {table}"
    # Spot-check a couple of important tables/columns.
    assert "detections" in doc and "response_actions" in doc
    assert "org_id" in doc


def test_sbom_generator_runs():
    mod = _load("generate_sbom.py")
    sbom = mod.build_sbom()
    assert sbom["bomFormat"] == "CycloneDX"
    assert any(c["name"].lower() == "fastapi" for c in sbom["components"])
