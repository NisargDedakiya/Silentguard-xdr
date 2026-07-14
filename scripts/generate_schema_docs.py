#!/usr/bin/env python3
"""Generate Markdown database-schema docs from the SQLAlchemy models.

Usage (from the server/ directory so `app` is importable):
    python ../scripts/generate_schema_docs.py > ../docs/schema.md
"""
import sys
from pathlib import Path

_server = Path(__file__).resolve().parents[1] / "server"
if _server.exists():
    sys.path.insert(0, str(_server))

from app.database import Base  # noqa: E402
from app import models  # noqa: F401,E402  (register models on Base.metadata)


def render() -> str:
    lines = ["# Database Schema", "",
             "_Generated from `server/app/models.py` by "
             "`scripts/generate_schema_docs.py`._", ""]
    for table in sorted(Base.metadata.tables.values(), key=lambda t: t.name):
        lines.append(f"## `{table.name}`")
        lines.append("")
        lines.append("| Column | Type | Attributes |")
        lines.append("|---|---|---|")
        for col in table.columns:
            attrs = []
            if col.primary_key:
                attrs.append("PK")
            for fk in col.foreign_keys:
                attrs.append(f"FK→{fk.column.table.name}.{fk.column.name}")
            if col.unique:
                attrs.append("unique")
            if col.index:
                attrs.append("indexed")
            if not col.nullable:
                attrs.append("not null")
            lines.append(f"| {col.name} | {col.type} | {', '.join(attrs)} |")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.stdout.write(render())
