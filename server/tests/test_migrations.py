"""Verify Alembic migrations build a schema equivalent to the ORM models.

This guards against the migration history drifting from models.py — a fresh
`alembic upgrade head` must produce the same tables and columns that
`Base.metadata.create_all` would, so production (Alembic) and the SQLite demo
(create_all) never diverge.
"""
import pathlib

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from app.database import Base

SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]


def _alembic_config(db_url: str) -> Config:
    cfg = Config(str(SERVER_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(SERVER_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def _schema_snapshot(engine) -> dict[str, set[str]]:
    insp = inspect(engine)
    return {
        t: {c["name"] for c in insp.get_columns(t)}
        for t in insp.get_table_names()
        if t != "alembic_version"
    }


def test_migrations_match_models(tmp_path, monkeypatch):
    # Alembic env.py reads DATABASE_URL from settings; point both at temp files.
    mig_url = f"sqlite:///{tmp_path/'mig.db'}"
    monkeypatch.setenv("DATABASE_URL", mig_url)
    # settings is import-cached; env.py also honors the config's sqlalchemy.url
    # which we set explicitly below, so the cache does not matter here.

    command.upgrade(_alembic_config(mig_url), "head")
    mig_engine = create_engine(mig_url)
    migrated = _schema_snapshot(mig_engine)
    mig_engine.dispose()

    orm_engine = create_engine(f"sqlite:///{tmp_path/'orm.db'}")
    Base.metadata.create_all(bind=orm_engine)
    orm = _schema_snapshot(orm_engine)
    orm_engine.dispose()

    assert set(migrated) == set(orm), "table set differs between migrations and models"
    for table in orm:
        assert migrated[table] == orm[table], f"columns differ for {table}"


def test_downgrade_to_base(tmp_path):
    mig_url = f"sqlite:///{tmp_path/'dg.db'}"
    cfg = _alembic_config(mig_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    engine = create_engine(mig_url)
    remaining = {t for t in inspect(engine).get_table_names() if t != "alembic_version"}
    engine.dispose()
    assert remaining == set(), f"downgrade left tables behind: {remaining}"
