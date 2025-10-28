# Final Diff

## Summary
- Introduced a reusable runtime migration plan so one function governs self-healing schema fixes for the primary database and every organisation database.【F:src/backend/base/langflow/services/database/service.py†L50-L122】【F:src/backend/base/langflow/services/database/runtime_migrations.py†L1-L44】
- Updated `DatabaseService` to execute the shared plan once per engine, ensuring migrations run on first access without per-query overhead.【F:src/backend/base/langflow/services/database/service.py†L50-L154】
- Hooked the runtime plan into bootstrap (`initialize_database`) so the base database aligns before Alembic checks execute.【F:src/backend/base/langflow/services/database/utils.py†L16-L57】
- Refreshed the schema guide to point to the new runtime-migration framework and its tenant coverage.【F:docs/schema-diff.md†L68-L111】

## Key Changes

### `src/backend/base/langflow/services/database/runtime_migrations.py`
- Added a dedicated module that lists runtime migrations and exposes `apply_runtime_migrations` for the service layer to call. New migrations now land in one place and run everywhere automatically.【F:src/backend/base/langflow/services/database/runtime_migrations.py†L1-L44】

### `src/backend/base/langflow/services/database/service.py`
- Replaced the ad-hoc `drop_legacy_message_context_id` helper with a general `run_runtime_migrations` gate that wraps execution in an async lock and caches completion per service instance.【F:src/backend/base/langflow/services/database/service.py†L50-L154】
- Ensured `with_session` blocks on the runtime plan only once per database, covering organisation-specific engines without affecting later queries.【F:src/backend/base/langflow/services/database/service.py†L92-L122】

### `src/backend/base/langflow/services/database/utils.py`
- Adjusted bootstrap to call the new `run_runtime_migrations` entrypoint and improved error messaging around runtime fixes.【F:src/backend/base/langflow/services/database/utils.py†L16-L57】

### `docs/schema-diff.md`
- Documented the runtime migration plan so future schema tweaks only require edits to the central function to reach every tenant database.【F:docs/schema-diff.md†L68-L111】
