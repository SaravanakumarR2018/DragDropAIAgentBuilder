"""Runtime database migration plan.

This module defines the lightweight migrations that run outside of Alembic
so that every database – the primary instance and each organisation-scoped
one – can self-heal the first time it is accessed after a deploy. Update the
``_RUNTIME_MIGRATIONS`` sequence when a new runtime fix is required.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final
from weakref import WeakKeyDictionary

from lfx.log.logger import logger
from sqlalchemy import inspect
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlmodel import text

RuntimeMigration = Callable[[Connection], None]


@dataclass
class _RuntimeMigrationState:
    lock: asyncio.Lock
    done: bool = False


_ENGINE_STATES: "WeakKeyDictionary[AsyncEngine, _RuntimeMigrationState]" = WeakKeyDictionary()


def _state_for_engine(engine: AsyncEngine) -> _RuntimeMigrationState:
    state = _ENGINE_STATES.get(engine)
    if state is None:
        state = _RuntimeMigrationState(lock=asyncio.Lock())
        _ENGINE_STATES[engine] = state
    return state


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


async def ensure_runtime_migrations(
    engine: AsyncEngine, *, use_noop_database: bool = False
) -> None:
    """Run the runtime migrations exactly once for ``engine``.

    ``use_noop_database`` short-circuits the plan for in-memory/disabled
    database configurations.
    """

    state = _state_for_engine(engine)

    if use_noop_database:
        state.done = True
        return

    async with state.lock:
        if state.done:
            return

        async with engine.begin() as conn:
            await conn.run_sync(apply_runtime_migrations)

        state.done = True
