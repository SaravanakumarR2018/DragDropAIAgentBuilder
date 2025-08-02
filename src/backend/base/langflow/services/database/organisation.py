from __future__ import annotations

import re

from langflow.logging.logger import logger
from langflow.services.auth.clerk_utils import auth_header_ctx
from langflow.services.deps import get_db_service, get_settings_service
from langflow.services.settings.service import SettingsService
from langflow.services.utils import setup_superuser

from .service import DatabaseService


def _build_database_url_for_org(base_url: str, org_id: str) -> str:
    """Return a database URL for the given organisation."""
    if base_url.startswith("sqlite"):
        if "/" in base_url:
            prefix = base_url.rsplit("/", 1)[0]
            new_url = f"{prefix}/{org_id}.db"
        else:
            new_url = f"{org_id}.db"
    else:
        match = re.match(r"^(?P<prefix>.+/)(?P<dbname>[^/?]+)(?P<suffix>.*)$", base_url)
        if match:
            new_url = f"{match.group('prefix')}{org_id}{match.group('suffix')}"
        else:
            logger.warning("Could not construct organisation DB url; using base url")
            new_url = base_url
    logger.debug(f"Derived organisation database URL: {new_url}")
    return new_url


class OrganisationService:
    async def create_database_and_tables_other_initializations_with_org(self) -> None:
        """Create and initialise a database for the organisation from auth context."""
        payload: dict | None = auth_header_ctx.get()
        if not payload:
            msg = "Missing Clerk payload"
            raise RuntimeError(msg)
        org_id = payload.get("org_id")
        if not org_id:
            msg = "Missing organisation id"
            raise RuntimeError(msg)

        db_service = get_db_service()
        base_url = db_service.database_url
        new_url = _build_database_url_for_org(base_url, org_id)

        settings_service = get_settings_service()
        new_settings = settings_service.settings.model_copy()
        new_settings.database_url = new_url
        new_settings_service = SettingsService(new_settings, settings_service.auth_settings)

        new_db_service = DatabaseService(new_settings_service)
        if new_db_service.settings_service.settings.database_connection_retry:
            await new_db_service.create_db_and_tables_with_retry()
        else:
            await new_db_service.create_db_and_tables()

        await new_db_service.check_schema_health()
        await new_db_service.run_migrations()

        async with new_db_service.with_session() as session:
            await setup_superuser(new_settings_service, session)

        await new_db_service.teardown()
