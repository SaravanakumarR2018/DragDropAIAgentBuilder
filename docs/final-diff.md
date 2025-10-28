# Final Diff

```diff
commit de6d869db51dd9118315e1ab53c706ff71a6d49f
Author: Codex <codex@openai.com>
Date:   Tue Oct 28 03:46:18 2025 +0000

    Ensure context_id cleanup runs for organisation databases
    
    ## Summary
    - ensure each database service runs the legacy message.context_id drop before opening sessions by guarding it with an async lock
    - reuse the same cleanup path for organisation-scoped DatabaseService instances so tenant databases self-heal on first access
    - document the per-organisation self-healing behaviour in the schema comparison guide
    
    ## Testing
    - not run (not requested)

diff --git a/docs/schema-diff.md b/docs/schema-diff.md
new file mode 100644
index 0000000..bd11fe3
--- /dev/null
+++ b/docs/schema-diff.md
@@ -0,0 +1,49 @@
+# Database Schema Comparison: `update-dragdrop-aiagent-builder-fix` vs. `main`
+
+This reference outlines the PostgreSQL tables managed by SQLModel in the current `update-dragdrop-aiagent-builder-fix` branch and the upstream `main` branch. It highlights the per-table schemas followed by a summary of the differences between the two branches.
+
+## Branch `update-dragdrop-aiagent-builder-fix`
+
+| Table | Column summary |
+| --- | --- |
+| `api_key` | `id` UUID primary key; `name` nullable/indexed label; `last_used_at` nullable timestamp; `total_uses` counter (default `0`); `is_active` flag (default `True`); `created_at` timezone-aware timestamp (default `now()`); `api_key` unique/indexed secret; `user_id` FK to `user.id` with relationship back-population.【F:src/backend/base/langflow/services/database/models/api_key/model.py†L18-L36】 |
+| `file` | `id` UUID primary key; `user_id` FK to `user.id`; `name`, `path`, `size` mandatory file metadata; optional `provider`; `created_at` and `updated_at` timestamps defaulting to `now()`; unique constraint on (`name`, `user_id`).【F:src/backend/base/langflow/services/database/models/file/model.py†L9-L19】 |
+| `flow` | `id` UUID primary key; indexed `name`; optional `description` (`TEXT`), `icon`, `icon_bg_color`, `gradient`; JSON `data`; flags (`is_component`, `webhook`, `locked`, `mcp_enabled`); optional `endpoint_name` (indexed), `tags` JSON list, `action_name`, `action_description`; `updated_at` auto timestamp; access control enum `access_type` with default `PRIVATE`; optional relationships to `user` (`user_id` FK) and `folder` (`folder_id` FK, plus filesystem path `fs_path`).【F:src/backend/base/langflow/services/database/models/flow/model.py†L32-L196】 |
+| `folder` | `id` UUID primary key; indexed `name`; optional `description` (`TEXT`); optional JSON `auth_settings`; optional `parent_id` self-FK establishing hierarchy; `user_id` FK to owner; relationship collections for children folders and flows; uniqueness constraint on (`user_id`, `name`).【F:src/backend/base/langflow/services/database/models/folder/model.py†L11-L36】 |
+| `message` | `id` UUID primary key; timestamp with UTC default; sender metadata (`sender`, `sender_name`, `session_id`); chat body `text` (`TEXT`); JSON arrays `files`, `content_blocks`; booleans `error`, `edit`; JSON `properties`; `category` (`TEXT`); optional `flow_id` FK-like UUID (stored as nullable UUID).【F:src/backend/base/langflow/services/database/models/message/model.py†L18-L126】 |
+| `transaction` | Table name `transaction`; `id` UUID primary key; timestamp defaulting to UTC `now`; `vertex_id`; optional `target_id`; JSON `inputs` and `outputs`; `status`; optional `error`; required `flow_id` UUID with validator ensuring UUID coercion.【F:src/backend/base/langflow/services/database/models/transactions/model.py†L10-L60】 |
+| `user` | `id` UUID primary key; unique/indexed `username`; `password`; optional `profile_image`; flags `is_active`, `is_superuser`; timestamps `create_at`, `updated_at`; optional `last_login_at`; optional `store_api_key`; JSON `optins` defaulting to opt-in settings; relationships to API keys, flows, variables, and folders with cascade deletes.【F:src/backend/base/langflow/services/database/models/user/model.py†L25-L51】 |
+| `variable` | `id` UUID primary key; `name`; encrypted `value`; JSON `default_fields`; optional `type`; audit timestamps `created_at`, `updated_at` with timezone defaults; required `user_id` FK with relationship back to owner.【F:src/backend/base/langflow/services/database/models/variable/model.py†L18-L45】 |
+| `vertex_build` | Table name `vertex_build`; `build_id` UUID primary key; timestamp defaulting to UTC `now`; string `id` of the vertex; JSON `data` and `artifacts`; optional `params` stored as `TEXT`; boolean `valid`; required `flow_id` UUID with validation helpers for UUID and serialization constraints.【F:src/backend/base/langflow/services/database/models/vertex_builds/model.py†L11-L70】 |
+
+## Branch `main`
+
+The upstream `main` branch keeps the same tables and column layout as `update-dragdrop-aiagent-builder-fix`, with one notable addition on the `message` table: it retains the optional `context_id` column on `MessageBase`, allowing records to track a conversational context identifier.【5446c9†L1-L98】 The table below repeats the schema for completeness.
+
+| Table | Column summary |
+| --- | --- |
+| `api_key` | Identical to `update-dragdrop-aiagent-builder-fix` (`id`, `name`, `last_used_at`, `total_uses`, `is_active`, `created_at`, `api_key`, `user_id`). |
+| `file` | Identical to `update-dragdrop-aiagent-builder-fix` (`id`, `user_id`, `name`, `path`, `size`, `provider`, `created_at`, `updated_at`; unique (`name`, `user_id`)). |
+| `flow` | Identical to `update-dragdrop-aiagent-builder-fix` (`id`, `name`, `description`, `icon`, `icon_bg_color`, `gradient`, `data`, flags, `endpoint_name`, `tags`, `action_name`, `action_description`, `access_type`, `updated_at`, `user_id`, `folder_id`, `fs_path`). |
+| `folder` | Identical to `update-dragdrop-aiagent-builder-fix` (`id`, `name`, `description`, `auth_settings`, `parent_id`, `user_id`, hierarchical relationships, unique (`user_id`, `name`)). |
+| `message` | Same as `update-dragdrop-aiagent-builder-fix` with an additional nullable `context_id` column persisted alongside `session_id` for compatibility with context-aware interactions.【5446c9†L18-L98】 |
+| `transaction` | Identical to `update-dragdrop-aiagent-builder-fix` (`id`, `timestamp`, `vertex_id`, `target_id`, `inputs`, `outputs`, `status`, `error`, `flow_id`). |
+| `user` | Identical to `update-dragdrop-aiagent-builder-fix` (`id`, `username`, `password`, `profile_image`, flags, timestamps, `last_login_at`, `store_api_key`, `optins`, relationship collections). |
+| `variable` | Identical to `update-dragdrop-aiagent-builder-fix` (`id`, `name`, `value`, `default_fields`, `type`, `created_at`, `updated_at`, `user_id`). |
+| `vertex_build` | Identical to `update-dragdrop-aiagent-builder-fix` (`build_id`, `timestamp`, `id`, `data`, `artifacts`, `params`, `valid`, `flow_id`). |
+
+## Table-Level Differences
+
+- `message`: `update-dragdrop-aiagent-builder-fix` omits the legacy nullable `context_id` column, while `main` still stores it next to the session metadata.【F:src/backend/base/langflow/services/database/models/message/model.py†L18-L126】【5446c9†L18-L98】
+
+All other tables share the same schema definitions across both branches.
+
+## Deployment guidance for `context_id`
+
+The runtime initialisation path now removes the obsolete `context_id` column automatically before Alembic compares metadata with the live database. During startup `initialize_database` calls `DatabaseService.drop_legacy_message_context_id`, which inspects the `message` table and issues `ALTER TABLE "message" DROP COLUMN context_id` when the column is still present. In addition, each `DatabaseService` (including organisation-scoped instances) performs the same check the first time it opens a session, so every tenant database self-heals on first use after deployment.【F:src/backend/base/langflow/services/database/utils.py†L16-L68】【F:src/backend/base/langflow/services/database/service.py†L189-L294】
+
+- **When deploying the merged branch**: no manual SQL is required; the service will drop the column the first time it sees an upgraded database—both for the primary database at boot and for each organisation database when it is next accessed. This keeps forward compatibility by aligning the schema with the code that no longer references `context_id`.
+- **If you must roll back to the old `main` image**: reintroduce the column with `ALTER TABLE "message" ADD COLUMN context_id TEXT NULL;` before starting the old image, otherwise SQLModel will fail to hydrate the `Message` records because the expected column is missing.
+- **Fresh installations**: databases created after the merge never create the column, so nothing extra runs.
+
+Because the drop happens ahead of Alembic’s `command.check`, the migration runner no longer sees a schema mismatch, ensuring the new container starts cleanly without needing the destructive `--fix` flag.【F:src/backend/base/langflow/services/database/service.py†L300-L386】【F:src/backend/base/langflow/services/database/utils.py†L18-L60】
diff --git a/src/backend/base/langflow/services/database/service.py b/src/backend/base/langflow/services/database/service.py
index 1672ecd..a4aa2ee 100644
--- a/src/backend/base/langflow/services/database/service.py
+++ b/src/backend/base/langflow/services/database/service.py
@@ -48,6 +48,9 @@ class DatabaseService(Service):
         self.database_url: str = settings_service.settings.database_url
         self._sanitize_database_url()
 
+        self._legacy_cleanup_lock = asyncio.Lock()
+        self._legacy_cleanup_done = False
+
         # This file is in langflow.services.database.manager.py
         # the ini is in langflow
         langflow_dir = Path(__file__).parent.parent.parent
@@ -186,8 +189,10 @@ class DatabaseService(Service):
     @asynccontextmanager
     async def with_session(self):
         if self.settings_service.settings.use_noop_database:
+            self._legacy_cleanup_done = True
             yield NoopSession()
         else:
+            await self._ensure_legacy_context_cleanup()
             async with AsyncSession(self.engine, expire_on_commit=False) as session:
                 # Start of Selection
                 try:
@@ -246,6 +251,48 @@ class DatabaseService(Service):
             await session.commit()
             await logger.adebug("Successfully assigned orphaned flows to the default superuser")
 
+    async def drop_legacy_message_context_id(self) -> None:
+        """Remove the legacy ``context_id`` column from the ``message`` table if it exists."""
+
+        async with self._legacy_cleanup_lock:
+            if self._legacy_cleanup_done:
+                return
+
+            if self.settings_service.settings.use_noop_database:
+                self._legacy_cleanup_done = True
+                return
+
+            async with self.engine.begin() as conn:
+                await conn.run_sync(self._drop_legacy_message_context_id)
+
+            self._legacy_cleanup_done = True
+
+    @staticmethod
+    def _drop_legacy_message_context_id(connection) -> None:
+        inspector = inspect(connection)
+        table_names = inspector.get_table_names()
+
+        if "message" not in table_names:
+            return
+
+        column_names = {column["name"] for column in inspector.get_columns("message")}
+        if "context_id" not in column_names:
+            return
+
+        logger.info("Removing legacy context_id column from message table")
+
+        try:
+            connection.execute(text('ALTER TABLE "message" DROP COLUMN context_id'))
+        except Exception:  # noqa: BLE001
+            logger.exception("Failed to drop legacy context_id column from message table")
+            raise
+
+    async def _ensure_legacy_context_cleanup(self) -> None:
+        if self._legacy_cleanup_done:
+            return
+
+        await self.drop_legacy_message_context_id()
+
     @staticmethod
     def _generate_unique_flow_name(original_name: str, existing_names: set[str]) -> str:
         """Generate a unique flow name by adding or incrementing a suffix."""
diff --git a/src/backend/base/langflow/services/database/utils.py b/src/backend/base/langflow/services/database/utils.py
index ca17488..a6e7005 100644
--- a/src/backend/base/langflow/services/database/utils.py
+++ b/src/backend/base/langflow/services/database/utils.py
@@ -31,6 +31,12 @@ async def initialize_database(*, fix_migration: bool = False) -> None:
             msg = "Error creating DB and tables"
             await logger.aexception(msg)
             raise RuntimeError(msg) from exc
+    try:
+        await database_service.drop_legacy_message_context_id()
+    except Exception as exc:  # noqa: BLE001
+        msg = "Error dropping legacy context_id column"
+        await logger.aexception(msg)
+        raise RuntimeError(msg) from exc
     try:
         await database_service.check_schema_health()
     except Exception as exc:
```
