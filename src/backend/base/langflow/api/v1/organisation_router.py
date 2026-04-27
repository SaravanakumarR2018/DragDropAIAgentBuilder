from fastapi import APIRouter, HTTPException
from lfx.log.logger import logger
from langflow.services.auth.clerk_metadata_constants import ORGANISATION_CREATED_BY_KEY
from langflow.services.auth.clerk_utils import (
    get_clerk_user_id_from_payload,
    get_org_id_from_clerk_payload,
    get_organisation_created_by_from_clerk_payload,
    update_clerk_organization,
)
from langflow.services.database.organisation import OrganizationService
from langflow.services.deps import get_settings_service

router = APIRouter(tags=["Organisation"])


@router.post("/create_organisation")
async def create_organisation():
    """Create a new organisation database."""
    settings_service = get_settings_service()
    if not settings_service.auth_settings.CLERK_AUTH_ENABLED:
        raise HTTPException(status_code=404, detail="Not found")
    
    existing_org_created_by= await get_organisation_created_by_from_clerk_payload()
    if not existing_org_created_by:
        org_id = get_org_id_from_clerk_payload()
        clerk_user_id = get_clerk_user_id_from_payload()
        logger.info(f"Creating organisation for user {clerk_user_id} with org id {org_id}")
        await update_clerk_organization(
            org_id=org_id,
            public_metadata={ORGANISATION_CREATED_BY_KEY: clerk_user_id},
        )
    else:
        logger.info(
            "Organisation already has %s=%s; skipping overwrite",
            ORGANISATION_CREATED_BY_KEY,
            existing_org_created_by,
        )

    service = OrganizationService()
    try:
        await service.create_database_and_tables_other_initializations_with_org()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"detail": "Organisation database created"}
