"""Runtime database migration plan.

This module defines the lightweight migrations that run outside of Alembic
so that every database – the primary instance and each organisation-scoped
one – can self-heal the first time it is accessed after a deploy. Update the
``_RUNTIME_MIGRATIONS`` sequence when a new runtime fix is required.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

from lfx.log.logger import logger
from sqlalchemy import inspect
from sqlalchemy.engine import Connection
from sqlmodel import text

RuntimeMigration = Callable[[Connection], None]


def _drop_legacy_message_context_id(connection: Connection) -> None:
    inspector = inspect(connection)

    if "message" not in inspector.get_table_names():
        return

    column_names = {column["name"] for column in inspector.get_columns("message")}
    if "context_id" not in column_names:
        return

    logger.info("Removing legacy context_id column from message table")
    try:
        connection.execute(text('ALTER TABLE "message" DROP COLUMN context_id'))
    except Exception:  # noqa: BLE001
        logger.exception("Failed to drop legacy context_id column from message table")
        raise


_RUNTIME_MIGRATIONS: Final[tuple[RuntimeMigration, ...]] = (
    _drop_legacy_message_context_id,
)


def apply_runtime_migrations(connection: Connection) -> None:
    """Execute the runtime migrations in order on ``connection``.

    Each migration runs inside the caller's transaction/connection scope.
    """

    for migration in _RUNTIME_MIGRATIONS:
        migration(connection)
