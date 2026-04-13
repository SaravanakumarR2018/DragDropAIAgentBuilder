"""Constants for Clerk JWT and Paddle metadata keys.

This module centralizes all metadata key definitions to ensure consistency
across Clerk JWT payload extraction and Paddle customer data storage.
"""

# ============================================================================
# Clerk JWT Payload Keys
# ============================================================================

# Standard Clerk claims
CLERK_JWT_SUB_KEY = "sub"  # Clerk user ID (unique identifier)
CLERK_JWT_EMAIL_KEY = "email"  # User email address
CLERK_JWT_ORG_KEY = "o"  # Organization object

# Custom claims added by verify_clerk_token
CLERK_JWT_UUID_KEY = "uuid"  # Deterministic UUID derived from Clerk ID

# ============================================================================
# Public Metadata Keys (stored in Clerk public_metadata and JWT)
# ============================================================================

PADDLE_CUSTOMER_ID_KEY = "paddle_customer_id"  # Paddle customer ID
PADDLE_SUBSCRIPTION_ID_KEY = "paddle_subscription_id"  # Paddle subscription ID
PADDLE_LOCK_KEY = "paddle_provisioning_lock"  # Key to indicate a lock for provisioning
ORGANISATION_CREATED_BY_KEY = "organisation_created_by"  # Clerk user id of org creator/admin

# ============================================================================
# Custom Data Keys (stored in Paddle customer custom_data)
# ============================================================================

PADDLE_CUSTOM_DATA_ORG_ID_KEY = "org_id"  # Organization ID
PADDLE_CUSTOM_DATA_USER_ID_KEY = "user_id"  # Clerk user ID

# ============================================================================
# Organization Metadata
# ============================================================================

ORG_ID_KEY = "org_id"  # Organization ID key (used in multiple contexts)

# ============================================================================
# Additional Constants
# ============================================================================

HAS_ACCESS_KEY = "has_access"
SUBSCRIPTION_STATUS_KEY = "subscription_status"
SUBSCRIPTION_PLAN_KEY = "subscription_plan_key"
PADDLE_SUBSCRIPTION_ID = "paddle_subscription_id"
ORGANISATION_CREATED_BY = "organisation_created_by"
NEXT_BILLED_AT_KEY = "next_billed_at"
CURRENT_PERIOD_END_KEY = "current_period_end"
CANCEL_SCHEDULED_KEY = "cancel_scheduled"
