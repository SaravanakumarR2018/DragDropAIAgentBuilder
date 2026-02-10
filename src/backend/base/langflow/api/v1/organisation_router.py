from fastapi import APIRouter, HTTPException

from langflow.services.auth.clerk_utils import (
    get_clerk_organization,
    get_clerk_user_id_from_payload,
    get_org_id_from_clerk_payload,
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

    service = OrganizationService()
    try:
        await service.create_database_and_tables_other_initializations_with_org()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    org_id = get_org_id_from_clerk_payload()
    clerk_user_id = get_clerk_user_id_from_payload()
    organization = await get_clerk_organization(org_id)
    public_metadata = organization.get("public_metadata", {}) if isinstance(organization, dict) else {}
    existing_created_by = public_metadata.get("organisation_created_by")
    existing_subscription_id = public_metadata.get("paddle_subscription_id")
    merged_metadata = {**public_metadata}

    if not existing_created_by:
        merged_metadata["organisation_created_by"] = clerk_user_id

    if "paddle_subscription_id" not in public_metadata and existing_subscription_id is None:
        merged_metadata["paddle_subscription_id"] = None

    if merged_metadata != public_metadata:
        await update_clerk_organization(org_id=org_id, public_metadata=merged_metadata)

    return {"detail": "Organisation database created"}
