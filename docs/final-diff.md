# Final Diff

## Summary
- Introduced a reusable runtime migration plan so one function governs self-healing schema fixes for the primary database and every organisation database.【F:src/backend/base/langflow/services/database/runtime_migrations.py†L1-L86】
- Updated `DatabaseService` to invoke the shared plan once per engine, ensuring migrations run on first access without per-query overhead.【F:src/backend/base/langflow/services/database/service.py†L186-L254】
- Hooked the runtime plan into bootstrap (`initialize_database`) so the base database aligns before Alembic checks execute.【F:src/backend/base/langflow/services/database/utils.py†L16-L57】
- Refreshed the schema guide to point to the new runtime-migration framework and its tenant coverage.【F:docs/schema-diff.md†L41-L49】

## Key Changes

### `src/backend/base/langflow/services/database/runtime_migrations.py`
- Added a dedicated module that lists runtime migrations and exposes helpers to apply them and ensure they run exactly once per engine. New migrations now land in one place and run everywhere automatically.【F:src/backend/base/langflow/services/database/runtime_migrations.py†L1-L86】

### `src/backend/base/langflow/services/database/service.py`
- Replaced inline guards with a thin `run_runtime_migrations` wrapper that delegates to the shared runtime-migration framework.【F:src/backend/base/langflow/services/database/service.py†L250-L254】
- Ensured `with_session` blocks on the runtime plan only once per database, covering organisation-specific engines without affecting later queries.【F:src/backend/base/langflow/services/database/service.py†L186-L199】

### `src/backend/base/langflow/services/database/utils.py`
- Adjusted bootstrap to call the new `run_runtime_migrations` entrypoint and improved error messaging around runtime fixes.【F:src/backend/base/langflow/services/database/utils.py†L16-L57】

### `docs/schema-diff.md`
- Documented the runtime migration plan so future schema tweaks only require edits to the central function to reach every tenant database.【F:docs/schema-diff.md†L41-L49】
