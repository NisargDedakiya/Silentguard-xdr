"""Alembic migration environment.

Reads the database URL from the application's centralized settings and targets
the app's declarative ``Base.metadata`` so ``--autogenerate`` sees every model.
"""
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.core.config import settings
from app.database import Base

# Import models so they register on Base.metadata before autogenerate runs.
from app import models  # noqa: F401,E402

config = context.config
# Prefer an explicitly-provided URL (e.g. a test harness or CI setting
# sqlalchemy.url on the Config); otherwise fall back to the app's settings,
# which read DATABASE_URL from the environment. This keeps one source of truth
# for normal runs while remaining overridable for isolated test databases.
if not config.get_main_option("sqlalchemy.url"):
    config.set_main_option("sqlalchemy.url", settings.database_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=settings.database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,  # SQLite-safe ALTERs
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,  # SQLite-safe ALTERs
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
