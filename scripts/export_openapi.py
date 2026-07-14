#!/usr/bin/env python3
"""Export the FastAPI OpenAPI schema to JSON.

Usage (from the server/ directory so `app` is importable):
    python ../scripts/export_openapi.py > openapi.json
"""
import json
import sys
from pathlib import Path

# Allow running from repo root or server/.
_server = Path(__file__).resolve().parents[1] / "server"
if _server.exists():
    sys.path.insert(0, str(_server))

from app.main import app  # noqa: E402


if __name__ == "__main__":
    json.dump(app.openapi(), sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
