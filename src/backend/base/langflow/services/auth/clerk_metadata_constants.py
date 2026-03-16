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
ORGANISATION_CREATED_BY_KEY = "organisation_created_by"  # Clerk user id of org creator/admin
PADDLE_PLAN_KEY = "paddle_plan_key"  # Active plan key
PADDLE_SUBSCRIPTION_STATUS_KEY = "paddle_subscription_status"  # Active subscription status
PADDLE_TRIAL_END_KEY = "paddle_trial_end"  # Trial end timestamp
PADDLE_SEATS_KEY = "paddle_seats"  # Active seat count

# ============================================================================
# Custom Data Keys (stored in Paddle customer custom_data)
# ============================================================================

PADDLE_CUSTOM_DATA_ORG_ID_KEY = "org_id"  # Organization ID
PADDLE_CUSTOM_DATA_USER_ID_KEY = "user_id"  # Clerk user ID

# ============================================================================
# Organization Metadata
# ============================================================================

ORG_ID_KEY = "org_id"  # Organization ID key (used in multiple contexts)
